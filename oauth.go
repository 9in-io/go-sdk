package nine

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TokenSet is what a sign-in, a refresh or a client-credentials request returns. It
// marshals to JSON (snake_case keys), so you can keep it in a server-side session.
type TokenSet struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type,omitempty"`
	// ExpiresAt is when the access token expires.
	ExpiresAt time.Time `json:"expires_at"`
	// RefreshToken comes with the offline_access scope. 9in rotates it: keep the new one
	// after every refresh.
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	// Claims are the verified ID token's claims (sub, email, name, amr, sid…), nil
	// without an ID token.
	Claims Claims `json:"claims,omitempty"`
	// ReturnTo is the path to send the user to after sign-in, from the pending login
	// (only a same-site path is kept).
	ReturnTo string `json:"return_to,omitempty"`
}

// Expired reports whether the access token has expired, or will within leeway.
func (t *TokenSet) Expired(leeway time.Duration) bool {
	return t == nil || t.AccessToken == "" || !time.Now().Add(leeway).Before(t.ExpiresAt)
}

type tokenResponse struct {
	AccessToken  string  `json:"access_token"`
	TokenType    string  `json:"token_type"`
	ExpiresIn    float64 `json:"expires_in"`
	RefreshToken string  `json:"refresh_token"`
	IDToken      string  `json:"id_token"`
	Scope        string  `json:"scope"`
}

// LogoutOptions are the parameters of the end-session URL.
type LogoutOptions struct {
	// IDTokenHint identifies the session's application (an expired ID token is fine).
	IDTokenHint string
	// PostLogoutRedirectURI is where 9in sends the user afterwards: one of the
	// application's allowed logout URLs.
	PostLogoutRedirectURI string
	// State is added to that redirect.
	State string
}

// ClientCredentialsOptions are the parameters of a client-credentials request.
type ClientCredentialsOptions struct {
	// Audience is the API to get a token for; leave empty for the Management API.
	Audience string
	// Scope is space-separated; empty means every scope the application was granted.
	Scope string
}

// oauthClient is what WebAppAuth and DeviceAuth share: the token endpoint and the
// endpoints around it, for one application.
type oauthClient struct {
	issuer   string
	auth     clientAuth
	http     *http.Client
	provider *provider
	verifier *Verifier
	now      func() time.Time
}

// newOAuthClient expects an issuer that NormalizeIssuer has already accepted.
func newOAuthClient(issuer, clientID, clientSecret string, client *http.Client, leeway time.Duration) (*oauthClient, error) {
	// The verifier checks ID tokens; it shares its HTTP client and discovery document.
	v, err := NewVerifier(VerifierConfig{Issuer: issuer, Mode: ModeLocal, Leeway: leeway, HTTPClient: client, CacheSize: 1, AllowInsecureIssuer: true})
	if err != nil {
		return nil, err
	}
	return &oauthClient{
		issuer:   issuer,
		auth:     clientAuth{clientID, clientSecret},
		http:     v.http,
		provider: v.provider,
		verifier: v,
		now:      func() time.Time { return v.now() },
	}, nil
}

func (o *oauthClient) tokenRequest(ctx context.Context, form url.Values) (*TokenSet, error) {
	doc, err := o.provider.discovery(ctx)
	if err != nil {
		return nil, err
	}
	var res tokenResponse
	if err := postForm(ctx, o.http, doc.TokenEndpoint, form, o.auth, "request_failed", &res); err != nil {
		return nil, err
	}
	if res.AccessToken == "" {
		return nil, newError("request_failed", "the token response has no access_token", 0)
	}
	expiresIn := res.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 3600
	}
	tokenType := res.TokenType
	if tokenType == "" {
		tokenType = "Bearer"
	}
	return &TokenSet{
		AccessToken:  res.AccessToken,
		TokenType:    tokenType,
		ExpiresAt:    o.now().Add(time.Duration(expiresIn * float64(time.Second))),
		RefreshToken: res.RefreshToken,
		IDToken:      res.IDToken,
		Scope:        res.Scope,
	}, nil
}

// refresh exchanges a refresh token. A new ID token in the answer is verified; Claims
// is set only when it verifies.
func (o *oauthClient) refresh(ctx context.Context, refreshToken string) (*TokenSet, error) {
	if refreshToken == "" {
		return nil, newError("login_required", "no refresh token (request the offline_access scope)", http.StatusUnauthorized)
	}
	tokens, err := o.tokenRequest(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}})
	if err != nil {
		return nil, err
	}
	if tokens.RefreshToken == "" {
		tokens.RefreshToken = refreshToken
	}
	if tokens.IDToken != "" {
		if claims, err := o.verifier.VerifyIDToken(ctx, tokens.IDToken, o.auth.id, ""); err == nil {
			tokens.Claims = claims
		}
	}
	return tokens, nil
}

// ensureFresh returns tokens unchanged while the access token is valid for at least
// leeway; otherwise it refreshes, keeping the ID token, claims and return path when the
// refresh doesn't replace them.
func (o *oauthClient) ensureFresh(ctx context.Context, tokens *TokenSet, leeway time.Duration) (*TokenSet, error) {
	if tokens == nil {
		return nil, newError("login_required", "no tokens", http.StatusUnauthorized)
	}
	if !tokens.Expired(leeway) {
		return tokens, nil
	}
	next, err := o.refresh(ctx, tokens.RefreshToken)
	if err != nil {
		return nil, err
	}
	if next.Claims != nil && tokens.Claims != nil && next.Claims.Subject() != tokens.Claims.Subject() {
		return nil, invalidIDToken("the refreshed ID token is for another user")
	}
	if next.IDToken == "" || next.Claims == nil {
		next.IDToken, next.Claims = tokens.IDToken, tokens.Claims
	}
	if next.Scope == "" {
		next.Scope = tokens.Scope
	}
	next.ReturnTo = tokens.ReturnTo
	return next, nil
}

func (o *oauthClient) userInfo(ctx context.Context, accessToken string) (Claims, error) {
	doc, err := o.provider.discovery(ctx)
	if err != nil {
		return nil, err
	}
	endpoint := doc.UserinfoEndpoint
	if endpoint == "" {
		endpoint = o.issuer + "/oauth/userinfo"
	}
	var info Claims
	err = getJSON(ctx, o.http, endpoint, http.Header{"Authorization": {"Bearer " + accessToken}}, "userinfo_failed", &info)
	if e, ok := err.(*Error); ok && e.Status == http.StatusUnauthorized {
		e.Code = "invalid_token"
	}
	if err != nil {
		return nil, err
	}
	return info, nil
}

func (o *oauthClient) revoke(ctx context.Context, token, hint string) error {
	doc, err := o.provider.discovery(ctx)
	if err != nil {
		return err
	}
	if doc.RevocationEndpoint == "" {
		return nil
	}
	if hint == "" {
		hint = "refresh_token"
	}
	return postForm(ctx, o.http, doc.RevocationEndpoint, url.Values{"token": {token}, "token_type_hint": {hint}}, o.auth, "revocation_failed", nil)
}

func (o *oauthClient) logoutURL(ctx context.Context, opts LogoutOptions) (string, error) {
	doc, err := o.provider.discovery(ctx)
	if err != nil {
		return "", err
	}
	endpoint := doc.EndSessionEndpoint
	if endpoint == "" {
		endpoint = o.issuer + "/oauth/logout"
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", newError("discovery_failed", "bad end_session_endpoint", 0)
	}
	q := u.Query()
	if o.auth.id != "" {
		q.Set("client_id", o.auth.id)
	}
	if opts.IDTokenHint != "" {
		q.Set("id_token_hint", opts.IDTokenHint)
	}
	if opts.PostLogoutRedirectURI != "" {
		q.Set("post_logout_redirect_uri", opts.PostLogoutRedirectURI)
	}
	if opts.State != "" {
		q.Set("state", opts.State)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (o *oauthClient) clientCredentials(ctx context.Context, opts ClientCredentialsOptions) (*TokenSet, error) {
	if o.auth.secret == "" {
		return nil, invalidOptions("client credentials need a ClientSecret (a confidential application)")
	}
	form := url.Values{"grant_type": {"client_credentials"}}
	if opts.Audience != "" {
		form.Set("audience", opts.Audience)
	}
	if opts.Scope != "" {
		form.Set("scope", opts.Scope)
	}
	return o.tokenRequest(ctx, form)
}

// CodeChallenge is the PKCE S256 challenge for a code verifier (RFC 7636):
// BASE64URL(SHA256(verifier)).
func CodeChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// SafeReturnPath returns path when it is a path on your own site ("/dashboard?tab=1"),
// and "" for anything that could send the user elsewhere: absolute URLs,
// protocol-relative "//host" and "/\host", or control characters.
func SafeReturnPath(path string) string {
	if path == "" || path[0] != '/' || strings.HasPrefix(path, "//") || strings.HasPrefix(path, "/\\") || len(path) > 2048 {
		return ""
	}
	for _, r := range path {
		if r < 0x20 || r == 0x7f {
			return ""
		}
	}
	u, err := url.Parse(path)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil {
		return ""
	}
	return path
}

func hasScope(scopes []string, scope string) bool {
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}
