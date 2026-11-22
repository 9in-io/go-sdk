package nine

import (
	"context"
	"crypto/subtle"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DefaultScopes returns the scopes requested when a configuration names none: an ID
// token with the profile and email claims, and a refresh token.
func DefaultScopes() []string { return []string{"openid", "profile", "email", "offline_access"} }

// How long a sign-in may take between CreateLogin and the callback.
const loginTimeout = 15 * time.Minute

// WebAppAuthConfig configures a [WebAppAuth].
type WebAppAuthConfig struct {
	// Issuer is your tenant's issuer, e.g. https://acme.9in.io or your custom login domain.
	Issuer string
	// ClientID is the application's client ID.
	ClientID string
	// ClientSecret is set for confidential applications (sent with HTTP Basic,
	// client_secret_basic). Leave it empty for public ones, which rely on PKCE alone.
	ClientSecret string
	// RedirectURI is your callback URL, as registered on the application. It can also be
	// given per sign-in ([LoginOptions].RedirectURI).
	RedirectURI string
	// Scopes default to [DefaultScopes].
	Scopes []string
	// Audience is an API identifier, to get access tokens for that API.
	Audience string
	// Leeway is the clock skew allowed when checking ID tokens. Default 30 seconds.
	Leeway time.Duration
	// HTTPClient is used for every call to 9in. Default: a client with a 10-second
	// timeout. Redirects are never followed.
	HTTPClient *http.Client
	// AllowInsecureIssuer accepts a plain-http issuer other than localhost (development only).
	AllowInsecureIssuer bool
}

// WebAppAuthConfigFromEnv returns a WebAppAuthConfig from NINE_ISSUER, NINE_CLIENT_ID,
// NINE_CLIENT_SECRET, NINE_REDIRECT_URI, NINE_AUDIENCE and NINE_ALLOW_INSECURE_ISSUER.
func WebAppAuthConfigFromEnv() WebAppAuthConfig {
	return WebAppAuthConfig{
		Issuer:              Env("ISSUER"),
		ClientID:            Env("CLIENT_ID"),
		ClientSecret:        Env("CLIENT_SECRET"),
		RedirectURI:         Env("REDIRECT_URI"),
		Audience:            Env("AUDIENCE"),
		AllowInsecureIssuer: envBool("ALLOW_INSECURE_ISSUER"),
	}
}

// WebAppAuth signs users in to a server-side web app: the authorization code flow with
// PKCE (S256), state and nonce, the RFC 9207 iss check, and the ID token verified
// against your tenant's keys. It also refreshes tokens (9in rotates refresh tokens),
// revokes them, builds the logout URL, reads userinfo and gets client-credentials tokens.
//
// You keep the [PendingLogin] between [WebAppAuth.CreateLogin] and
// [WebAppAuth.HandleCallback] (in the user's session, or an encrypted cookie) and the
// [TokenSet] afterwards. [WebApp] does all of that for you. Safe for concurrent use.
type WebAppAuth struct {
	cfg    WebAppAuthConfig
	scopes []string
	o      *oauthClient

	mu       sync.Mutex
	consumed map[string]time.Time // states already used, so a callback can't be replayed
}

// NewWebAppAuth returns a WebAppAuth. It fails when the issuer or client ID is missing,
// or the issuer is malformed or not https.
func NewWebAppAuth(cfg WebAppAuthConfig) (*WebAppAuth, error) {
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
		scopes = DefaultScopes()
	}
	cfg.Issuer = issuer
	return &WebAppAuth{cfg: cfg, scopes: splitScopes(scopes), o: o, consumed: make(map[string]time.Time)}, nil
}

// Issuer is the normalised issuer.
func (a *WebAppAuth) Issuer() string { return a.cfg.Issuer }

// ClientID is the application's client ID.
func (a *WebAppAuth) ClientID() string { return a.cfg.ClientID }

// Discovery returns your tenant's discovery document (cached).
func (a *WebAppAuth) Discovery(ctx context.Context) (*Discovery, error) {
	return a.o.provider.discovery(ctx)
}

// LoginOptions are the choices for one sign-in.
type LoginOptions struct {
	// ReturnTo is a path on your site to come back to afterwards ("/dashboard"). Only a
	// same-site path is kept ([SafeReturnPath]); it comes back in [TokenSet].ReturnTo.
	ReturnTo string
	// Screen "signup" opens the sign-up form (prompt=create).
	Screen string
	// Prompt is "login" (sign in again), "consent", "select_account", "none" (no UI:
	// fails with login_required) or "create".
	Prompt string
	// LoginHint prefills the identifier.
	LoginHint string
	// Locale picks the language of the hosted pages (ui_locales), e.g. "de".
	Locale string
	// RedirectURI overrides the configured callback URL for this sign-in.
	RedirectURI string
	// Params are extra authorization parameters (max_age, …). They never replace
	// response_type, client_id, redirect_uri, scope, state, nonce or PKCE.
	Params map[string]string
}

// Login is a sign-in that has started: send the browser to URL and keep Pending until
// the callback.
type Login struct {
	URL     string
	Pending *PendingLogin
}

// PendingLogin is what to keep between the redirect to 9in and the callback, for about
// 15 minutes. It holds the PKCE verifier: store it server-side or encrypted, and delete
// it when the callback arrives. It marshals to JSON.
type PendingLogin struct {
	State       string `json:"state"`
	Nonce       string `json:"nonce"`
	Verifier    string `json:"verifier"`
	RedirectURI string `json:"redirect_uri"`
	ReturnTo    string `json:"return_to,omitempty"`
	// CreatedAt is unix seconds.
	CreatedAt int64 `json:"created_at"`
}

var reservedAuthorizeParams = map[string]bool{
	"response_type": true, "client_id": true, "redirect_uri": true, "scope": true, "state": true,
	"nonce": true, "code_challenge": true, "code_challenge_method": true,
}

// CreateLogin starts a sign-in: it returns the URL of your tenant's hosted sign-in page
// and the PendingLogin to keep until the callback.
func (a *WebAppAuth) CreateLogin(ctx context.Context, opts LoginOptions) (*Login, error) {
	redirectURI := opts.RedirectURI
	if redirectURI == "" {
		redirectURI = a.cfg.RedirectURI
	}
	if redirectURI == "" {
		return nil, invalidOptions("RedirectURI is required (NINE_REDIRECT_URI)")
	}
	doc, err := a.o.provider.discovery(ctx)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(doc.AuthorizationEndpoint)
	if err != nil || doc.AuthorizationEndpoint == "" {
		return nil, newError("discovery_failed", "bad authorization_endpoint", 0)
	}
	pending := &PendingLogin{
		State:       randomString(24),
		Nonce:       randomString(24),
		Verifier:    randomString(48),
		RedirectURI: redirectURI,
		ReturnTo:    SafeReturnPath(opts.ReturnTo),
		CreatedAt:   a.o.now().Unix(),
	}
	q := u.Query()
	for k, v := range opts.Params {
		if !reservedAuthorizeParams[k] {
			q.Set(k, v)
		}
	}
	q.Set("response_type", "code")
	q.Set("client_id", a.cfg.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", strings.Join(a.scopes, " "))
	q.Set("state", pending.State)
	q.Set("nonce", pending.Nonce)
	q.Set("code_challenge", CodeChallenge(pending.Verifier))
	q.Set("code_challenge_method", "S256")
	if a.cfg.Audience != "" {
		q.Set("audience", a.cfg.Audience)
	}
	prompt := opts.Prompt
	if opts.Screen == "signup" {
		prompt = "create"
	}
	if prompt != "" {
		q.Set("prompt", prompt)
	}
	if opts.LoginHint != "" {
		q.Set("login_hint", opts.LoginHint)
	}
	if opts.Locale != "" {
		q.Set("ui_locales", opts.Locale)
	}
	u.RawQuery = q.Encode()
	return &Login{URL: u.String(), Pending: pending}, nil
}

// HandleCallback finishes a sign-in on your callback URL. query is the callback's query
// (r.URL.Query()), pending what CreateLogin returned. It checks the error parameter, the
// pending login's age (15 minutes), the state (in constant time, and only once), the
// iss parameter (RFC 9207), exchanges the code with the PKCE verifier and verifies the
// ID token (signature, issuer, audience, expiry, nonce).
//
// Errors: the OAuth error from 9in (access_denied when the user cancelled,
// login_required for prompt=none…), invalid_state, invalid_issuer, missing_code,
// invalid_grant and invalid_id_token.
func (a *WebAppAuth) HandleCallback(ctx context.Context, query url.Values, pending *PendingLogin) (*TokenSet, error) {
	if code := query.Get("error"); code != "" {
		description := query.Get("error_description")
		if description == "" {
			description = code
		}
		return nil, newError(code, description, http.StatusBadRequest)
	}
	if pending == nil || pending.State == "" || pending.Verifier == "" || pending.Nonce == "" {
		return nil, newError("invalid_state", "no sign-in in progress (it expired, or started in another browser)", http.StatusBadRequest)
	}
	now := a.o.now()
	if now.Sub(time.Unix(pending.CreatedAt, 0)) > loginTimeout {
		return nil, newError("invalid_state", "the sign-in took too long; start again", http.StatusBadRequest)
	}
	state := query.Get("state")
	if state == "" || subtle.ConstantTimeCompare([]byte(state), []byte(pending.State)) != 1 {
		return nil, newError("invalid_state", "state mismatch", http.StatusBadRequest)
	}
	doc, err := a.o.provider.discovery(ctx)
	if err != nil {
		return nil, err
	}
	// RFC 9207: when the authorization server identifies itself, it must be ours.
	if iss := query.Get("iss"); iss != "" {
		if !sameIssuer(iss, a.cfg.Issuer) {
			return nil, newError("invalid_issuer", "unexpected issuer "+iss, http.StatusBadRequest)
		}
	} else if doc.AuthorizationResponseIssParameterSupported {
		return nil, newError("invalid_issuer", "the callback has no iss parameter", http.StatusBadRequest)
	}
	code := query.Get("code")
	if code == "" {
		return nil, newError("missing_code", "no authorization code in the callback", http.StatusBadRequest)
	}
	if !a.consume(pending.State, now) {
		return nil, newError("invalid_state", "this sign-in was already completed", http.StatusBadRequest)
	}
	redirectURI := pending.RedirectURI
	if redirectURI == "" {
		redirectURI = a.cfg.RedirectURI
	}
	tokens, err := a.o.tokenRequest(ctx, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {pending.Verifier},
	})
	if err != nil {
		return nil, err
	}
	if tokens.IDToken != "" {
		claims, err := a.o.verifier.VerifyIDToken(ctx, tokens.IDToken, a.cfg.ClientID, pending.Nonce)
		if err != nil {
			return nil, err
		}
		tokens.Claims = claims
	} else if hasScope(a.scopes, "openid") {
		return nil, invalidIDToken("no ID token in the token response")
	}
	tokens.ReturnTo = SafeReturnPath(pending.ReturnTo)
	return tokens, nil
}

// consume marks a state as used; false when it already was. States are remembered for
// the length of a sign-in, in this process.
func (a *WebAppAuth) consume(state string, now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.consumed) > 1000 {
		for s, at := range a.consumed {
			if now.Sub(at) > loginTimeout {
				delete(a.consumed, s)
			}
		}
	}
	key := tokenKey(state)
	if at, ok := a.consumed[key]; ok && now.Sub(at) <= loginTimeout {
		return false
	}
	a.consumed[key] = now
	return true
}

// Refresh exchanges a refresh token for new tokens. 9in rotates refresh tokens: keep
// the RefreshToken of the result (the old one is kept when 9in sends none). When 9in
// sends a new ID token it is verified and its claims are in Claims.
func (a *WebAppAuth) Refresh(ctx context.Context, refreshToken string) (*TokenSet, error) {
	return a.o.refresh(ctx, refreshToken)
}

// EnsureFresh returns tokens unchanged (the same pointer) while the access token is
// valid for at least leeway, and refreshed tokens otherwise (keeping the ID token,
// claims and ReturnTo when the refresh doesn't replace them). Save the result.
func (a *WebAppAuth) EnsureFresh(ctx context.Context, tokens *TokenSet, leeway time.Duration) (*TokenSet, error) {
	return a.o.ensureFresh(ctx, tokens, leeway)
}

// UserInfo returns the user's current claims from the userinfo endpoint. A revoked or
// expired token gets invalid_token.
func (a *WebAppAuth) UserInfo(ctx context.Context, accessToken string) (Claims, error) {
	return a.o.userInfo(ctx, accessToken)
}

// Revoke revokes a refresh token (and its whole rotation family; hint "refresh_token",
// the default) or an access token (hint "access_token"). 9in answers success for
// unknown tokens, so an error is a real failure such as invalid_client.
func (a *WebAppAuth) Revoke(ctx context.Context, token, hint string) error {
	return a.o.revoke(ctx, token, hint)
}

// LogoutURL is the URL that ends the session at 9in (RP-initiated logout) and returns
// to opts.PostLogoutRedirectURI, which must be an allowed logout URL of the application.
func (a *WebAppAuth) LogoutURL(ctx context.Context, opts LogoutOptions) (string, error) {
	return a.o.logoutURL(ctx, opts)
}

// ClientCredentials gets a token for the application itself (no user), for your own API
// (opts.Audience) or the Management API. Confidential applications only. For a cached,
// self-refreshing token use [ClientCredentials] instead.
func (a *WebAppAuth) ClientCredentials(ctx context.Context, opts ClientCredentialsOptions) (*TokenSet, error) {
	return a.o.clientCredentials(ctx, opts)
}

// VerifyIDToken verifies an ID token issued to this application (nonce: the one sent
// with the sign-in, or "" to skip that check).
func (a *WebAppAuth) VerifyIDToken(ctx context.Context, idToken, nonce string) (Claims, error) {
	return a.o.verifier.VerifyIDToken(ctx, idToken, a.cfg.ClientID, nonce)
}
