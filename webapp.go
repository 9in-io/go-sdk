package nine

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// WebAppConfig configures a [WebApp].
type WebAppConfig struct {
	// Issuer is your tenant's issuer, e.g. https://acme.9in.io (NINE_ISSUER).
	Issuer string
	// ClientID is the application's client ID (NINE_CLIENT_ID).
	ClientID string
	// ClientSecret is set for a confidential application (NINE_CLIENT_SECRET). Leave it
	// empty for a public one.
	ClientSecret string
	// Secret encrypts the session and sign-in cookies (NINE_SECRET): 32 characters or
	// more, e.g. from `openssl rand -base64 32`.
	Secret string
	// Secrets are older secrets that still decrypt cookies while you rotate.
	Secrets []string
	// BaseURL is your app's URL, e.g. https://app.acme.com (NINE_BASE_URL). The callback
	// URL is BaseURL + BasePath + "/callback". Default: the scheme and host of each
	// request; set it in production, especially behind a proxy.
	BaseURL string
	// BasePath is where the routes are mounted. Default "/nine": /nine/login,
	// /nine/signup, /nine/callback and /nine/logout. "/" mounts them at the root.
	BasePath string
	// Scopes default to [DefaultScopes] (offline_access gives a refresh token).
	Scopes []string
	// Audience is an API identifier, to get access tokens for that API (NINE_AUDIENCE).
	Audience string
	// CookieName is the session cookie's name. Default "nine_session".
	CookieName string
	// SessionMaxAge is how long a session lasts without being used. Default 30 days;
	// each token refresh starts it again.
	SessionMaxAge time.Duration
	// RefreshLeeway is how long before expiry the access token is refreshed. Default 60 seconds.
	RefreshLeeway time.Duration
	// AfterSignInPath is where users land after sign-in when no return_to was given.
	// Default "/".
	AfterSignInPath string
	// AfterSignOutPath is where users land after sign-out. BaseURL + this path must be
	// an allowed logout URL of the application. Default "/".
	AfterSignOutPath string
	// OnError writes the answer for a failed sign-in (access_denied when the user
	// cancels, say) or 9in being unreachable. Default: a plain-text error page.
	OnError func(w http.ResponseWriter, r *http.Request, err error)
	// HTTPClient is used for every call to 9in. Default: a client with a 10-second timeout.
	HTTPClient *http.Client
	// AllowInsecureIssuer accepts a plain-http issuer other than localhost (development only).
	AllowInsecureIssuer bool
}

// WebAppConfigFromEnv returns a WebAppConfig from NINE_ISSUER, NINE_CLIENT_ID,
// NINE_CLIENT_SECRET, NINE_SECRET (comma-separated to rotate: the first encrypts),
// NINE_BASE_URL, NINE_AUDIENCE and NINE_ALLOW_INSECURE_ISSUER.
func WebAppConfigFromEnv() WebAppConfig {
	secrets := envList("SECRET")
	cfg := WebAppConfig{
		Issuer:              Env("ISSUER"),
		ClientID:            Env("CLIENT_ID"),
		ClientSecret:        Env("CLIENT_SECRET"),
		BaseURL:             Env("BASE_URL"),
		Audience:            Env("AUDIENCE"),
		AllowInsecureIssuer: envBool("ALLOW_INSECURE_ISSUER"),
	}
	if len(secrets) > 0 {
		cfg.Secret, cfg.Secrets = secrets[0], secrets[1:]
	}
	return cfg
}

// WebApp is sign-in for a server-rendered Go web app, ready to mount: the /nine/login,
// /nine/signup, /nine/callback and /nine/logout routes, an encrypted cookie session
// (AES-256-GCM; no server-side storage), token refresh with rotation, and [RequireUser]
// middleware. It works with any router that speaks http.Handler.
//
//	app, err := nine.NewWebApp(nine.WebAppConfigFromEnv())
//	mux.Handle("/nine/", app)
//	mux.Handle("/dashboard", app.RequireUser(dashboard))
//
// In a handler, [UserFrom] returns the signed-in user and [WebApp.AccessToken] a valid
// access token for your API. Safe for concurrent use.
type WebApp struct {
	cfg      WebAppConfig
	auth     *WebAppAuth
	sealer   *sealer
	basePath string // "" when mounted at the root
	now      func() time.Time

	refreshes flight[*TokenSet]
	mu        sync.Mutex
	recent    map[string]recentRefresh
}

type recentRefresh struct {
	tokens *TokenSet
	until  time.Time
}

// User is the signed-in user of a [WebApp], from the ID token.
type User struct {
	// Subject is the user's 9in id (the sub claim).
	Subject       string `json:"sub"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Name          string `json:"name,omitempty"`
	GivenName     string `json:"given_name,omitempty"`
	FamilyName    string `json:"family_name,omitempty"`
	Picture       string `json:"picture,omitempty"`
	PhoneNumber   string `json:"phone_number,omitempty"`
	Locale        string `json:"locale,omitempty"`
	// Claims are all of the user's claims (profile, custom fields, amr, auth_time…).
	Claims Claims `json:"claims"`
}

func newUser(claims Claims) *User {
	return &User{
		Subject:       claims.Subject(),
		Email:         claims.String("email"),
		EmailVerified: claims.Bool("email_verified"),
		Name:          claims.String("name"),
		GivenName:     claims.String("given_name"),
		FamilyName:    claims.String("family_name"),
		Picture:       claims.String("picture"),
		PhoneNumber:   claims.String("phone_number"),
		Locale:        claims.String("locale"),
		Claims:        claims,
	}
}

// Claims about the token rather than the user, left out of the session.
var tokenOnlyClaims = map[string]bool{
	"iss": true, "aud": true, "exp": true, "iat": true, "nbf": true, "nonce": true,
	"at_hash": true, "c_hash": true, "azp": true, "jti": true, "sid": true,
}

func userClaims(claims Claims) Claims {
	out := Claims{}
	for k, v := range claims {
		if !tokenOnlyClaims[k] {
			out[k] = v
		}
	}
	return out
}

// storedSession is what the session cookie holds (encrypted).
type storedSession struct {
	V            int    `json:"v"`
	User         Claims `json:"user"`
	AccessToken  string `json:"at"`
	RefreshToken string `json:"rt,omitempty"`
	ExpiresAt    int64  `json:"at_exp"` // access token expiry, unix seconds
	Scope        string `json:"scope,omitempty"`
	Exp          int64  `json:"exp"` // session expiry, unix seconds
}

const (
	refreshReuse   = 30 * time.Second
	maxPendingTx   = 5
	webLoginMaxAge = loginTimeout
)

var (
	webActions   = []string{"login", "signup", "callback", "logout"}
	validPrompts = map[string]bool{"login": true, "consent": true, "none": true, "select_account": true, "create": true}
	stateFormat  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
)

// NewWebApp returns a WebApp. It fails when the issuer, client ID or secret is missing
// or invalid.
func NewWebApp(cfg WebAppConfig) (*WebApp, error) {
	if cfg.Issuer == "" {
		return nil, invalidOptions("Issuer is required (NINE_ISSUER)")
	}
	if cfg.ClientID == "" {
		return nil, invalidOptions("ClientID is required (NINE_CLIENT_ID)")
	}
	s, err := newSealer(secretList(cfg.Secret, cfg.Secrets))
	if err != nil {
		return nil, err
	}
	auth, err := NewWebAppAuth(WebAppAuthConfig{
		Issuer: cfg.Issuer, ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, Scopes: cfg.Scopes,
		Audience: cfg.Audience, HTTPClient: cfg.HTTPClient, AllowInsecureIssuer: cfg.AllowInsecureIssuer,
	})
	if err != nil {
		return nil, err
	}
	if cfg.BaseURL != "" {
		u, err := url.Parse(cfg.BaseURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
			return nil, invalidOptions("BaseURL must be an absolute URL, e.g. https://app.acme.com")
		}
		cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	}
	basePath := "/nine"
	if cfg.BasePath != "" {
		basePath = "/" + strings.Trim(cfg.BasePath, "/")
	}
	if basePath == "/" {
		basePath = ""
	}
	if cfg.CookieName == "" {
		cfg.CookieName = "nine_session"
	}
	if cfg.SessionMaxAge <= 0 {
		cfg.SessionMaxAge = 30 * 24 * time.Hour
	}
	if cfg.RefreshLeeway <= 0 {
		cfg.RefreshLeeway = time.Minute
	}
	for _, p := range []*string{&cfg.AfterSignInPath, &cfg.AfterSignOutPath} {
		if *p == "" {
			*p = "/"
		}
		if SafeReturnPath(*p) == "" {
			return nil, invalidOptions("AfterSignInPath and AfterSignOutPath must be paths on your site, like /dashboard")
		}
	}
	return &WebApp{cfg: cfg, auth: auth, sealer: s, basePath: basePath, now: time.Now, recent: make(map[string]recentRefresh)}, nil
}

// Auth is the underlying [WebAppAuth] (refresh, revoke, userinfo, client credentials).
func (a *WebApp) Auth() *WebAppAuth { return a.auth }

// ServeHTTP serves the sign-in routes under BasePath: GET login, GET signup, GET
// callback, and GET or POST logout. Anything else is 404.
func (a *WebApp) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch a.route(r) {
	case "login":
		a.Login(w, r)
	case "signup":
		a.Signup(w, r)
	case "callback":
		a.Callback(w, r)
	case "logout":
		a.Logout(w, r)
	default:
		http.NotFound(w, r)
	}
}

// route is which of our routes r is for, or "".
func (a *WebApp) route(r *http.Request) string {
	for _, path := range []string{r.URL.Path, requestPath(r)} {
		path = strings.TrimRight(path, "/")
		for _, action := range webActions {
			if path == a.basePath+"/"+action {
				return action
			}
		}
	}
	return ""
}

// base is our app's URL: the configured one, or the request's scheme and host.
func (a *WebApp) base(r *http.Request) string {
	if a.cfg.BaseURL != "" {
		return a.cfg.BaseURL
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func (a *WebApp) secure(r *http.Request) bool {
	return strings.HasPrefix(a.base(r), "https:")
}

func (a *WebApp) cookiePath() string {
	if a.basePath == "" {
		return "/"
	}
	return a.basePath
}

func (a *WebApp) txPrefix() string { return a.cfg.CookieName + "_tx_" }

func noStore(w http.ResponseWriter) { w.Header().Set("Cache-Control", "no-store") }

// Link prefetches must not sign anyone in or out.
func isPrefetch(r *http.Request) bool {
	return strings.Contains(strings.ToLower(r.Header.Get("Sec-Purpose")), "prefetch") ||
		strings.Contains(strings.ToLower(r.Header.Get("Purpose")), "prefetch")
}

// wantsPage tells a page navigation (redirect to sign-in) from an API call (401).
func wantsPage(r *http.Request) bool {
	return r.Header.Get("Sec-Fetch-Mode") == "navigate" || strings.Contains(r.Header.Get("Accept"), "text/html")
}

// Login starts a sign-in (the /nine/login route). Query parameters: return_to (a path
// on your site), screen=signup, prompt, login_hint, locale.
func (a *WebApp) Login(w http.ResponseWriter, r *http.Request) {
	a.startLogin(w, r, r.URL.Query().Get("screen") == "signup")
}

// Signup opens the sign-up form (the /nine/signup route). It takes the same query
// parameters as Login.
func (a *WebApp) Signup(w http.ResponseWriter, r *http.Request) {
	a.startLogin(w, r, true)
}

func (a *WebApp) startLogin(w http.ResponseWriter, r *http.Request, signup bool) {
	noStore(w)
	if isPrefetch(r) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	q := r.URL.Query()
	opts := LoginOptions{
		ReturnTo:    SafeReturnPath(q.Get("return_to")),
		LoginHint:   q.Get("login_hint"),
		Locale:      q.Get("locale"),
		RedirectURI: a.base(r) + a.basePath + "/callback",
	}
	if opts.ReturnTo == "" {
		opts.ReturnTo = a.cfg.AfterSignInPath
	}
	if opts.Locale == "" {
		opts.Locale = q.Get("ui_locales")
	}
	if prompt := q.Get("prompt"); validPrompts[prompt] {
		opts.Prompt = prompt
	}
	if signup {
		opts.Screen = "signup"
	}
	login, err := a.auth.CreateLogin(r.Context(), opts)
	if err != nil {
		a.fail(w, r, err, http.StatusBadGateway)
		return
	}
	sealed, err := a.sealer.seal(login.Pending, "transaction")
	if err != nil {
		a.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	// Abandoned sign-ins leave cookies behind until they expire; don't let them pile up.
	var pending []string
	for _, c := range r.Cookies() {
		if strings.HasPrefix(c.Name, a.txPrefix()) {
			pending = append(pending, c.Name)
		}
	}
	if len(pending) >= maxPendingTx {
		for _, name := range pending {
			http.SetCookie(w, a.cookie(r, name, "", a.cookiePath(), -1))
		}
	}
	http.SetCookie(w, a.cookie(r, a.txPrefix()+login.Pending.State, sealed, a.cookiePath(), int(webLoginMaxAge/time.Second)))
	http.Redirect(w, r, login.URL, http.StatusFound)
}

func (a *WebApp) cookie(r *http.Request, name, value, path string, maxAge int) *http.Cookie {
	return &http.Cookie{Name: name, Value: value, Path: path, MaxAge: maxAge, HttpOnly: true, Secure: a.secure(r), SameSite: http.SameSiteLaxMode}
}

// Callback finishes a sign-in (the /nine/callback route): it checks the callback against
// the sign-in cookie, starts the session and redirects to return_to.
func (a *WebApp) Callback(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	q := r.URL.Query()
	state := q.Get("state")
	var pending *PendingLogin
	if stateFormat.MatchString(state) {
		name := a.txPrefix() + state
		if c, err := r.Cookie(name); err == nil {
			http.SetCookie(w, a.cookie(r, name, "", a.cookiePath(), -1))
			var p PendingLogin
			if a.sealer.open(c.Value, "transaction", &p) {
				pending = &p
			}
		}
	}
	tokens, err := a.auth.HandleCallback(r.Context(), q, pending)
	if err != nil {
		a.fail(w, r, err, http.StatusBadRequest)
		return
	}
	s := &storedSession{
		V:            1,
		User:         userClaims(tokens.Claims),
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresAt:    tokens.ExpiresAt.Unix(),
		Scope:        tokens.Scope,
	}
	if s.User.Subject() == "" {
		a.fail(w, r, invalidIDToken("no ID token: request the openid scope"), http.StatusBadRequest)
		return
	}
	if err := a.writeSession(w, r, s); err != nil {
		a.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	target := tokens.ReturnTo
	if target == "" {
		target = a.cfg.AfterSignInPath
	}
	http.Redirect(w, r, a.absolute(r, target), http.StatusFound)
}

func (a *WebApp) absolute(r *http.Request, path string) string {
	if a.cfg.BaseURL != "" {
		return a.cfg.BaseURL + path
	}
	return path
}

// Logout signs the user out (the /nine/logout route, GET or POST): it clears the session,
// revokes the refresh token and sends the browser to 9in's end-session URL, which comes
// back to return_to (a path) or AfterSignOutPath. local=1 skips ending the 9in session.
func (a *WebApp) Logout(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if r.Method == http.MethodGet && isPrefetch(r) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	}
	_ = r.ParseForm()
	s := a.read(r)
	a.clearSession(w, r)
	if s != nil && s.RefreshToken != "" {
		// Best effort: the session is gone either way.
		_ = a.auth.Revoke(r.Context(), s.RefreshToken, "refresh_token")
	}
	target := SafeReturnPath(r.Form.Get("return_to"))
	if target == "" {
		target = a.cfg.AfterSignOutPath
	}
	status := http.StatusFound
	if r.Method == http.MethodPost {
		status = http.StatusSeeOther
	}
	if local := r.Form.Get("local"); local == "1" || local == "true" {
		http.Redirect(w, r, a.absolute(r, target), status)
		return
	}
	logout, err := a.auth.LogoutURL(r.Context(), LogoutOptions{PostLogoutRedirectURI: a.base(r) + target})
	if err != nil {
		// 9in unreachable: the local session has ended; go to the target.
		http.Redirect(w, r, a.absolute(r, target), status)
		return
	}
	http.Redirect(w, r, logout, status)
}

func (a *WebApp) fail(w http.ResponseWriter, r *http.Request, err error, status int) {
	if a.cfg.OnError != nil {
		a.cfg.OnError(w, r, err)
		return
	}
	message := err.Error()
	var e *Error
	if errors.As(err, &e) {
		message = e.Code
		if e.Description != "" && e.Description != e.Code {
			message += ": " + e.Description
		}
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "Sign-in failed: %s\n\nStart again: %s%s/login\n", message, a.base(r), a.basePath)
}

// ---------------------------------------------------------------------------
// Session

func (a *WebApp) read(r *http.Request) *storedSession {
	raw := readChunked(r, a.cfg.CookieName)
	if raw == "" {
		return nil
	}
	var s storedSession
	if !a.sealer.open(raw, "session", &s) || s.V != 1 || s.Exp <= a.now().Unix() || s.User.Subject() == "" {
		return nil
	}
	return &s
}

// writeSession seals the session (starting its lifetime again) into the cookie, and
// removes chunks the new value doesn't use.
func (a *WebApp) writeSession(w http.ResponseWriter, r *http.Request, s *storedSession) error {
	s.Exp = a.now().Add(a.cfg.SessionMaxAge).Unix()
	sealed, err := a.sealer.seal(s, "session")
	if err != nil {
		return err
	}
	chunks := chunkCookie(a.cfg.CookieName, sealed)
	maxAge := int(a.cfg.SessionMaxAge / time.Second)
	for _, name := range chunkNames(r, a.cfg.CookieName) {
		if _, kept := chunks[name]; !kept {
			http.SetCookie(w, a.cookie(r, name, "", "/", -1))
		}
	}
	for name, value := range chunks {
		http.SetCookie(w, a.cookie(r, name, value, "/", maxAge))
	}
	return nil
}

func (a *WebApp) clearSession(w http.ResponseWriter, r *http.Request) {
	for _, name := range chunkNames(r, a.cfg.CookieName) {
		http.SetCookie(w, a.cookie(r, name, "", "/", -1))
	}
}

func (a *WebApp) needsRefresh(s *storedSession) bool {
	return !a.now().Add(a.cfg.RefreshLeeway).Before(time.Unix(s.ExpiresAt, 0))
}

// refreshOnce refreshes once per refresh token: concurrent requests share one call, and
// requests that still carry the old refresh token shortly afterwards get the same
// result, because 9in rotates refresh tokens and treats a late second use as theft.
func (a *WebApp) refreshOnce(ctx context.Context, refreshToken string) (*TokenSet, error) {
	key := tokenKey(refreshToken)
	now := a.now()
	a.mu.Lock()
	for k, entry := range a.recent {
		if now.After(entry.until) {
			delete(a.recent, k)
		}
	}
	if hit, ok := a.recent[key]; ok {
		a.mu.Unlock()
		return hit.tokens, nil
	}
	a.mu.Unlock()
	return a.refreshes.do(ctx, key, func(ctx context.Context) (*TokenSet, error) {
		tokens, err := a.auth.Refresh(ctx, refreshToken)
		if err != nil {
			return nil, err
		}
		a.mu.Lock()
		a.recent[key] = recentRefresh{tokens: tokens, until: a.now().Add(refreshReuse)}
		a.mu.Unlock()
		return tokens, nil
	})
}

func (a *WebApp) refreshed(ctx context.Context, s *storedSession) (*storedSession, error) {
	tokens, err := a.refreshOnce(ctx, s.RefreshToken)
	if err != nil {
		return nil, err
	}
	next := *s
	next.AccessToken = tokens.AccessToken
	next.ExpiresAt = tokens.ExpiresAt.Unix()
	if tokens.RefreshToken != "" {
		next.RefreshToken = tokens.RefreshToken
	}
	if tokens.Scope != "" {
		next.Scope = tokens.Scope
	}
	// Keep the profile current when 9in sends a new ID token for the same user.
	if tokens.Claims != nil && tokens.Claims.Subject() == s.User.Subject() {
		next.User = userClaims(tokens.Claims)
	}
	return &next, nil
}

// sessionState is the request's session, shared by the middleware and AccessToken.
type sessionState struct {
	mu      sync.Mutex
	session *storedSession
	user    *User
}

type sessionKey struct{}

// load reads the session cookie and refreshes the access token when it is about to
// expire, writing the new cookie. A session 9in has ended (invalid_grant) is removed; when
// 9in can't be reached the session is kept, since the token may still work.
func (a *WebApp) load(w http.ResponseWriter, r *http.Request) *sessionState {
	if st, ok := r.Context().Value(sessionKey{}).(*sessionState); ok {
		return st
	}
	s := a.read(r)
	if s != nil && s.RefreshToken != "" && a.needsRefresh(s) {
		next, err := a.refreshed(r.Context(), s)
		switch {
		case err == nil:
			if a.writeSession(w, r, next) == nil {
				s = next
			}
		case errors.Is(err, ErrInvalidGrant):
			s = nil
		}
	}
	if s == nil {
		if len(chunkNames(r, a.cfg.CookieName)) > 0 {
			a.clearSession(w, r)
		}
		return &sessionState{}
	}
	return &sessionState{session: s, user: newUser(s.User)}
}

// Middleware reads the session for every request it wraps: [UserFrom] returns the user
// (nil when signed out), and the access token is refreshed before it expires. Signed-out
// visitors go through; use [WebApp.RequireUser] to keep them out.
func (a *WebApp) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.route(r) != "" {
			next.ServeHTTP(w, r)
			return
		}
		st := a.load(w, r)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionKey{}, st)))
	})
}

// RequireUser is [WebApp.Middleware] for pages that need a signed-in user. Signed-out
// visitors are sent to the sign-in page and brought back afterwards; requests that
// aren't page navigations (fetch, API calls) get 401 JSON instead.
func (a *WebApp) RequireUser(next http.Handler) http.Handler {
	return a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if UserFrom(r.Context()) != nil {
			next.ServeHTTP(w, r)
			return
		}
		noStore(w)
		if !wantsPage(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "error_description": "sign in first"})
			return
		}
		back := requestPath(r)
		if r.URL.RawQuery != "" {
			back += "?" + r.URL.RawQuery
		}
		login := a.absolute(r, a.basePath+"/login") + "?" + url.Values{"return_to": {back}}.Encode()
		http.Redirect(w, r, login, http.StatusFound)
	}))
}

// UserFrom returns the signed-in user [WebApp.Middleware] or [WebApp.RequireUser] put in
// the request context, or nil.
func UserFrom(ctx context.Context) *User {
	st, ok := ctx.Value(sessionKey{}).(*sessionState)
	if !ok {
		return nil
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.user
}

// User returns the signed-in user of the request (from the context when the middleware
// ran, else from the session cookie), or nil.
func (a *WebApp) User(r *http.Request) *User {
	if st, ok := r.Context().Value(sessionKey{}).(*sessionState); ok {
		st.mu.Lock()
		defer st.mu.Unlock()
		return st.user
	}
	if s := a.read(r); s != nil {
		return newUser(s.User)
	}
	return nil
}

// AccessToken returns a valid access token for the signed-in user (for your API, with
// Audience set), refreshing it when it expires within RefreshLeeway and saving the
// rotated refresh token in the cookie. Call it before writing the response body, so the
// cookie can still be set. It fails with login_required (401) when there is no session
// or it ended.
func (a *WebApp) AccessToken(w http.ResponseWriter, r *http.Request) (string, error) {
	st := a.load(w, r)
	st.mu.Lock()
	defer st.mu.Unlock()
	s := st.session
	if s == nil {
		return "", newError("login_required", "not signed in", http.StatusUnauthorized)
	}
	if !a.needsRefresh(s) {
		return s.AccessToken, nil
	}
	expired := !a.now().Before(time.Unix(s.ExpiresAt, 0))
	if s.RefreshToken == "" {
		if !expired {
			return s.AccessToken, nil
		}
		return "", newError("login_required", "the access token expired and the session has no refresh token (request the offline_access scope)", http.StatusUnauthorized)
	}
	next, err := a.refreshed(r.Context(), s)
	if errors.Is(err, ErrInvalidGrant) {
		a.clearSession(w, r)
		st.session, st.user = nil, nil
		return "", newError("login_required", "the session ended; sign in again", http.StatusUnauthorized)
	}
	if err != nil {
		if !expired {
			return s.AccessToken, nil
		}
		return "", err
	}
	if err := a.writeSession(w, r, next); err != nil {
		return "", err
	}
	st.session, st.user = next, newUser(next.User)
	return next.AccessToken, nil
}
