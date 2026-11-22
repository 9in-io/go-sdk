package nine

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DeviceAuthConfig configures a [DeviceAuth].
type DeviceAuthConfig struct {
	// Issuer is your tenant's issuer.
	Issuer string
	// ClientID is a "TV & Device" application (a public client with the device code grant).
	ClientID string
	// ClientSecret is only for confidential applications that enable the device grant.
	ClientSecret string
	// Scopes default to openid, profile and offline_access.
	Scopes []string
	// Audience is an API identifier, to get access tokens for that API.
	Audience string
	// Leeway is the clock skew allowed when checking ID tokens. Default 30 seconds.
	Leeway time.Duration
	// HTTPClient is used for every call to 9in. Default: a client with a 10-second timeout.
	HTTPClient *http.Client
	// AllowInsecureIssuer accepts a plain-http issuer other than localhost (development only).
	AllowInsecureIssuer bool
}

// DeviceAuth signs users in on devices without a browser or keyboard (CLIs, TVs) with
// the device authorization grant (RFC 8628): the device shows a short code, the user
// enters it on their phone or computer, and the device receives tokens once they
// approve. Safe for concurrent use.
//
//	code, _ := device.Start(ctx)
//	fmt.Printf("Open %s and enter %s\n", code.VerificationURI, code.UserCode)
//	tokens, err := device.Wait(ctx, code)
type DeviceAuth struct {
	cfg    DeviceAuthConfig
	scopes []string
	o      *oauthClient
	sleep  func(context.Context, time.Duration) error
}

// NewDeviceAuth returns a DeviceAuth.
func NewDeviceAuth(cfg DeviceAuthConfig) (*DeviceAuth, error) {
	if cfg.Issuer == "" {
		return nil, invalidOptions("Issuer is required (NINE_ISSUER)")
	}
	if cfg.ClientID == "" {
		return nil, invalidOptions("ClientID is required (NINE_CLIENT_ID)")
	}
	issuer, err := NormalizeIssuer(cfg.Issuer, cfg.AllowInsecureIssuer)
	if err != nil {
		return nil, err
	}
	o, err := newOAuthClient(issuer, cfg.ClientID, cfg.ClientSecret, cfg.HTTPClient, cfg.Leeway)
	if err != nil {
		return nil, err
	}
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "offline_access"}
	}
	cfg.Issuer = issuer
	return &DeviceAuth{cfg: cfg, scopes: splitScopes(scopes), o: o, sleep: sleepContext}, nil
}

// DeviceCode is what [DeviceAuth.Start] returns: show the user VerificationURI and
// UserCode (or a QR code of VerificationURIComplete, which fills the code in).
type DeviceCode struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	// ExpiresIn and Interval are seconds, as 9in sent them.
	ExpiresIn int `json:"expires_in"`
	Interval  int `json:"interval"`
	// ExpiresAt is when the code stops working.
	ExpiresAt time.Time `json:"expires_at"`
}

// Start asks 9in for a device code and a user code.
func (d *DeviceAuth) Start(ctx context.Context) (*DeviceCode, error) {
	doc, err := d.o.provider.discovery(ctx)
	if err != nil {
		return nil, err
	}
	endpoint := doc.DeviceAuthorizationEndpoint
	if endpoint == "" {
		endpoint = d.cfg.Issuer + "/oauth/device/authorize"
	}
	// client_id always goes in the form: 9in's device endpoint reads it from there even
	// when the client also authenticates with HTTP Basic.
	form := url.Values{"scope": {strings.Join(d.scopes, " ")}, "client_id": {d.cfg.ClientID}}
	if d.cfg.Audience != "" {
		form.Set("audience", d.cfg.Audience)
	}
	var code DeviceCode
	if err := postForm(ctx, d.o.http, endpoint, form, d.o.auth, "request_failed", &code); err != nil {
		return nil, err
	}
	if code.DeviceCode == "" || code.UserCode == "" {
		return nil, newError("request_failed", "the device authorization response has no device_code", 0)
	}
	if code.Interval <= 0 {
		code.Interval = 5
	}
	if code.ExpiresIn <= 0 {
		code.ExpiresIn = 600
	}
	code.ExpiresAt = d.o.now().Add(time.Duration(code.ExpiresIn) * time.Second)
	return &code, nil
}

// Poll asks once whether the user has approved. It fails with authorization_pending
// (keep polling), slow_down (poll less often), access_denied (the user declined) or
// expired_token (start over). On success a returned ID token is verified.
func (d *DeviceAuth) Poll(ctx context.Context, code *DeviceCode) (*TokenSet, error) {
	if code == nil || code.DeviceCode == "" {
		return nil, invalidOptions("no device code")
	}
	tokens, err := d.o.tokenRequest(ctx, url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {code.DeviceCode},
	})
	if err != nil {
		return nil, err
	}
	if tokens.IDToken != "" {
		claims, err := d.o.verifier.VerifyIDToken(ctx, tokens.IDToken, d.cfg.ClientID, "")
		if err != nil {
			return nil, err
		}
		tokens.Claims = claims
	}
	return tokens, nil
}

// Wait polls every code.Interval seconds until the user approves (and returns the
// tokens), declines (access_denied), the code expires (expired_token) or ctx ends. It
// slows down by 5 seconds whenever 9in asks it to.
func (d *DeviceAuth) Wait(ctx context.Context, code *DeviceCode) (*TokenSet, error) {
	if code == nil {
		return nil, invalidOptions("no device code")
	}
	interval := time.Duration(code.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	for {
		if !code.ExpiresAt.IsZero() && !d.o.now().Before(code.ExpiresAt) {
			return nil, newError("expired_token", "the device code expired; start over", http.StatusBadRequest)
		}
		if err := d.sleep(ctx, interval); err != nil {
			return nil, err
		}
		tokens, err := d.Poll(ctx, code)
		switch {
		case err == nil:
			return tokens, nil
		case errors.Is(err, ErrAuthorizationPending):
		case errors.Is(err, ErrSlowDown):
			interval += 5 * time.Second
		default:
			return nil, err
		}
	}
}

// Refresh exchanges a refresh token (9in rotates it: keep the new one).
func (d *DeviceAuth) Refresh(ctx context.Context, refreshToken string) (*TokenSet, error) {
	return d.o.refresh(ctx, refreshToken)
}

// EnsureFresh returns tokens unchanged while valid for at least leeway, else refreshed.
func (d *DeviceAuth) EnsureFresh(ctx context.Context, tokens *TokenSet, leeway time.Duration) (*TokenSet, error) {
	return d.o.ensureFresh(ctx, tokens, leeway)
}

// UserInfo returns the user's current claims from the userinfo endpoint.
func (d *DeviceAuth) UserInfo(ctx context.Context, accessToken string) (Claims, error) {
	return d.o.userInfo(ctx, accessToken)
}

// Revoke revokes a refresh token (hint "refresh_token", the default) or an access token.
func (d *DeviceAuth) Revoke(ctx context.Context, token, hint string) error {
	return d.o.revoke(ctx, token, hint)
}

func sleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
