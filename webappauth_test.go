package nine

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// signInServer is a fake tenant whose token endpoint completes sign-ins: it remembers
// the PKCE challenge and nonce of each code it hands out (see authorize) and issues an
// ID token with that nonce.
type signInServer struct {
	*fakeIssuer
	mu        sync.Mutex
	codes     map[string]codeGrant
	refreshes map[string]bool // live refresh tokens
	idExtra   map[string]any  // extra ID token claims
	noIDToken bool
	rotate    bool
}

type codeGrant struct {
	challenge, nonce, redirect string
}

func newSignInServer(t *testing.T, client string) *signInServer {
	s := &signInServer{fakeIssuer: newFakeIssuer(t), codes: map[string]codeGrant{}, refreshes: map[string]bool{}, rotate: true}
	s.setKeys(asymmetricKeys(t)...)
	s.token = func(r *http.Request, form url.Values) (int, any) {
		s.mu.Lock()
		defer s.mu.Unlock()
		switch form.Get("grant_type") {
		case "authorization_code":
			grant, ok := s.codes[form.Get("code")]
			delete(s.codes, form.Get("code"))
			if !ok || CodeChallenge(form.Get("code_verifier")) != grant.challenge || form.Get("redirect_uri") != grant.redirect {
				return 400, map[string]any{"error": "invalid_grant", "error_description": "bad code"}
			}
			s.refreshes["rt-1"] = true
			body := map[string]any{"access_token": "at-1", "token_type": "Bearer", "expires_in": 3600, "refresh_token": "rt-1", "scope": "openid profile email offline_access"}
			if !s.noIDToken {
				body["id_token"] = s.idToken(t, client, grant.nonce, s.idExtra)
			}
			return 200, body
		case "refresh_token":
			rt := form.Get("refresh_token")
			if !s.refreshes[rt] {
				return 400, map[string]any{"error": "invalid_grant", "error_description": "refresh token revoked"}
			}
			body := map[string]any{"access_token": "at-" + rt, "expires_in": 600, "id_token": s.idToken(t, client, "", nil)}
			if s.rotate {
				delete(s.refreshes, rt)
				next := rt + "+"
				s.refreshes[next] = true
				body["refresh_token"] = next
			}
			return 200, body
		case "client_credentials":
			return 200, map[string]any{"access_token": "cc-token", "expires_in": 3600, "token_type": "Bearer", "scope": form.Get("scope")}
		}
		return 400, map[string]any{"error": "unsupported_grant_type"}
	}
	return s
}

// authorize plays the hosted sign-in: it reads the authorization URL and returns the
// callback query 9in would redirect to.
func (s *signInServer) authorize(t *testing.T, authURL string) url.Values {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("response_type") != "code" {
		t.Fatalf("bad authorization request %s", authURL)
	}
	code := randomString(12)
	s.mu.Lock()
	s.codes[code] = codeGrant{challenge: q.Get("code_challenge"), nonce: q.Get("nonce"), redirect: q.Get("redirect_uri")}
	s.mu.Unlock()
	return url.Values{"code": {code}, "state": {q.Get("state")}, "iss": {s.issuer}}
}

func newTestAuth(t *testing.T, s *signInServer, cfg WebAppAuthConfig) *WebAppAuth {
	t.Helper()
	cfg.Issuer = s.issuer
	if cfg.ClientID == "" {
		cfg.ClientID = "app_web"
	}
	if cfg.RedirectURI == "" {
		cfg.RedirectURI = "https://app.acme.test/nine/callback"
	}
	return must[*WebAppAuth](t)(NewWebAppAuth(cfg))
}

func TestCreateLogin(t *testing.T) {
	s := newSignInServer(t, "app_web")
	a := newTestAuth(t, s, WebAppAuthConfig{Audience: "https://api.acme.test"})
	login, err := a.CreateLogin(ctx, LoginOptions{
		ReturnTo: "/dashboard?tab=1", Screen: "signup", LoginHint: "jane@acme.test", Locale: "de",
		Params: map[string]string{"max_age": "60", "state": "evil", "client_id": "evil", "code_challenge": "evil", "scope": "evil"},
	})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(login.URL)
	q := u.Query()
	if u.Path != "/oauth/authorize" {
		t.Fatal(u.Path)
	}
	want := map[string]string{
		"response_type": "code", "client_id": "app_web", "redirect_uri": "https://app.acme.test/nine/callback",
		"scope": "openid profile email offline_access", "state": login.Pending.State, "nonce": login.Pending.Nonce,
		"code_challenge": CodeChallenge(login.Pending.Verifier), "code_challenge_method": "S256",
		"audience": "https://api.acme.test", "prompt": "create", "login_hint": "jane@acme.test", "ui_locales": "de", "max_age": "60",
	}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
	if login.Pending.ReturnTo != "/dashboard?tab=1" || login.Pending.RedirectURI != "https://app.acme.test/nine/callback" {
		t.Fatalf("pending %+v", login.Pending)
	}
	if len(login.Pending.Verifier) < 43 || len(login.Pending.Verifier) > 128 || len(login.Pending.State) < 22 || len(login.Pending.Nonce) < 22 {
		t.Fatalf("weak randomness %+v", login.Pending)
	}
	// Each login is different.
	other, _ := a.CreateLogin(ctx, LoginOptions{})
	if other.Pending.State == login.Pending.State || other.Pending.Verifier == login.Pending.Verifier {
		t.Fatal("state reused")
	}
	if q2 := mustQuery(t, other.URL); q2.Get("prompt") != "" || q2.Get("ui_locales") != "" {
		t.Fatal("defaults")
	}
	// Prompt passes through; screen=signup wins.
	if mustQuery(t, must[*Login](t)(a.CreateLogin(ctx, LoginOptions{Prompt: "login"})).URL).Get("prompt") != "login" {
		t.Fatal("prompt")
	}
	// A login without a redirect URI can't start.
	b := must[*WebAppAuth](t)(NewWebAppAuth(WebAppAuthConfig{Issuer: s.issuer, ClientID: "x"}))
	_, err = b.CreateLogin(ctx, LoginOptions{})
	wantCode(t, err, "invalid_options", 0)
	if l := must[*Login](t)(b.CreateLogin(ctx, LoginOptions{RedirectURI: "https://x.test/cb"})); mustQuery(t, l.URL).Get("redirect_uri") != "https://x.test/cb" {
		t.Fatal("per-login redirect URI")
	}
}

func mustQuery(t *testing.T, raw string) url.Values {
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query()
}

func TestOnlySameSiteReturnPathsAreKept(t *testing.T) {
	for _, bad := range []string{"https://evil.test/", "//evil.test", "/\\evil.test", "\\\\evil.test", "javascript:alert(1)", "evil.test", "/\t/evil.test", "/\n/evil.test", "/x\x7f", "http:/evil.test", " /x", "/" + strings.Repeat("a", 3000)} {
		if got := SafeReturnPath(bad); got != "" {
			t.Errorf("%q kept as %q", bad, got)
		}
	}
	for _, good := range []string{"/", "/dashboard", "/a/b?c=d&e=%2F%2Fx#frag", "/@user", "/x//y"} {
		if got := SafeReturnPath(good); got != good {
			t.Errorf("%q dropped", good)
		}
	}
	s := newSignInServer(t, "app_web")
	a := newTestAuth(t, s, WebAppAuthConfig{})
	login := must[*Login](t)(a.CreateLogin(ctx, LoginOptions{ReturnTo: "//evil.test"}))
	if login.Pending.ReturnTo != "" {
		t.Fatal("unsafe return path kept")
	}
	// And a tampered pending login can't smuggle one in either.
	login = must[*Login](t)(a.CreateLogin(ctx, LoginOptions{}))
	login.Pending.ReturnTo = "https://evil.test"
	tokens := must[*TokenSet](t)(a.HandleCallback(ctx, s.authorize(t, login.URL), login.Pending))
	if tokens.ReturnTo != "" {
		t.Fatal("unsafe return path from the pending login")
	}
}

func TestHandleCallbackSignsIn(t *testing.T) {
	s := newSignInServer(t, "app_web")
	a := newTestAuth(t, s, WebAppAuthConfig{ClientSecret: "s3cret"})
	login := must[*Login](t)(a.CreateLogin(ctx, LoginOptions{ReturnTo: "/after"}))
	tokens, err := a.HandleCallback(ctx, s.authorize(t, login.URL), login.Pending)
	if err != nil {
		t.Fatal(err)
	}
	if tokens.AccessToken != "at-1" || tokens.RefreshToken != "rt-1" || tokens.TokenType != "Bearer" || tokens.ReturnTo != "/after" || tokens.Scope == "" {
		t.Fatalf("tokens %+v", tokens)
	}
	if tokens.Claims.Subject() != "usr_1" || tokens.Claims.String("email") != "jane@acme.test" {
		t.Fatalf("claims %v", tokens.Claims)
	}
	if d := time.Until(tokens.ExpiresAt); d < 59*time.Minute || d > time.Hour {
		t.Fatalf("expires in %v", d)
	}
	if tokens.Expired(0) || !tokens.Expired(2*time.Hour) {
		t.Fatal("Expired")
	}
	// Confidential client: HTTP Basic, no client_id in the form.
	form := s.form("/oauth/token")
	if s.authorization("/oauth/token") != basicAuth("app_web", "s3cret") || form.Get("client_id") != "" {
		t.Fatalf("client auth: %q %v", s.authorization("/oauth/token"), form)
	}
	if form.Get("grant_type") != "authorization_code" || form.Get("code_verifier") != login.Pending.Verifier || form.Get("redirect_uri") != login.Pending.RedirectURI {
		t.Fatalf("form %v", form)
	}
	// The token set survives a JSON round trip (for sessions).
	data, _ := json.Marshal(tokens)
	var back TokenSet
	if err := json.Unmarshal(data, &back); err != nil || back.AccessToken != tokens.AccessToken || back.Claims.Subject() != "usr_1" || !back.ExpiresAt.Equal(tokens.ExpiresAt) {
		t.Fatalf("round trip %s", data)
	}
	if !strings.Contains(string(data), `"refresh_token":"rt-1"`) || !strings.Contains(string(data), `"return_to":"/after"`) {
		t.Fatalf("snake_case JSON %s", data)
	}

	// A public client sends client_id in the form and no Authorization header.
	p := newTestAuth(t, s, WebAppAuthConfig{})
	login = must[*Login](t)(p.CreateLogin(ctx, LoginOptions{}))
	if _, err := p.HandleCallback(ctx, s.authorize(t, login.URL), login.Pending); err != nil {
		t.Fatal(err)
	}
	if s.authorization("/oauth/token") != "" || s.form("/oauth/token").Get("client_id") != "app_web" {
		t.Fatal("public client auth")
	}
}

func TestHandleCallbackRefusals(t *testing.T) {
	s := newSignInServer(t, "app_web")
	a := newTestAuth(t, s, WebAppAuthConfig{})
	fresh := func() (*Login, url.Values) {
		login := must[*Login](t)(a.CreateLogin(ctx, LoginOptions{}))
		return login, s.authorize(t, login.URL)
	}
	with := func(q url.Values, k, v string) url.Values {
		out := url.Values{}
		for key, vals := range q {
			out[key] = vals
		}
		if v == "" {
			out.Del(k)
		} else {
			out.Set(k, v)
		}
		return out
	}

	login, query := fresh()
	cases := []struct {
		name    string
		query   url.Values
		pending *PendingLogin
		code    string
	}{
		{"error from 9in", url.Values{"error": {"access_denied"}, "error_description": {"the user cancelled"}, "state": {login.Pending.State}}, login.Pending, "access_denied"},
		{"no pending login", query, nil, "invalid_state"},
		{"wrong state", with(query, "state", "forged"), login.Pending, "invalid_state"},
		{"no state", with(query, "state", ""), login.Pending, "invalid_state"},
		{"other issuer", with(query, "iss", "https://evil.9in.io"), login.Pending, "invalid_issuer"},
		{"no iss although advertised", with(query, "iss", ""), login.Pending, "invalid_issuer"},
		{"no code", with(query, "code", ""), login.Pending, "missing_code"},
	}
	for _, c := range cases {
		_, err := a.HandleCallback(ctx, c.query, c.pending)
		wantCode(t, err, c.code, 400)
	}
	if s.count("/oauth/token") != 0 {
		t.Fatal("a refused callback must not spend the code")
	}
	// The real callback still works, once.
	if _, err := a.HandleCallback(ctx, query, login.Pending); err != nil {
		t.Fatal(err)
	}
	_, err := a.HandleCallback(ctx, query, login.Pending)
	wantCode(t, err, "invalid_state", 400)
	wantDescription(t, err, "already completed")

	// A sign-in older than 15 minutes.
	login, query = fresh()
	login.Pending.CreatedAt = time.Now().Add(-16 * time.Minute).Unix()
	_, err = a.HandleCallback(ctx, query, login.Pending)
	wantDescription(t, err, "took too long")

	// The iss check is skipped when 9in doesn't advertise it and sends none.
	s.discovery = func(doc map[string]any) { delete(doc, "authorization_response_iss_parameter_supported") }
	b := newTestAuth(t, s, WebAppAuthConfig{})
	login = must[*Login](t)(b.CreateLogin(ctx, LoginOptions{}))
	if _, err := b.HandleCallback(ctx, with(s.authorize(t, login.URL), "iss", ""), login.Pending); err != nil {
		t.Fatal(err)
	}

	// 9in refusing the code: its error passes through.
	login, query = fresh()
	_, err = a.HandleCallback(ctx, with(query, "code", "unknown"), login.Pending)
	wantCode(t, err, "invalid_grant", 400)
	if !errors.Is(err, ErrInvalidGrant) {
		t.Fatal("errors.Is(ErrInvalidGrant)")
	}
}

func TestHandleCallbackVerifiesTheIDToken(t *testing.T) {
	s := newSignInServer(t, "app_web")
	a := newTestAuth(t, s, WebAppAuthConfig{})
	run := func(extra map[string]any) error {
		s.idExtra = extra
		login := must[*Login](t)(a.CreateLogin(ctx, LoginOptions{}))
		_, err := a.HandleCallback(ctx, s.authorize(t, login.URL), login.Pending)
		return err
	}
	for name, extra := range map[string]map[string]any{
		"bad nonce":     {"nonce": "other"},
		"other app":     {"aud": "app_other"},
		"expired":       {"exp": time.Now().Unix() - 300},
		"other issuer":  {"iss": "https://evil.9in.io"},
		"azp mismatch":  {"aud": []string{"app_web", "app_other"}, "azp": "app_other"},
		"no azp, 2 aud": {"aud": []string{"app_web", "app_other"}},
	} {
		err := run(extra)
		wantCode(t, err, "invalid_id_token", 401)
		if !errors.Is(err, ErrInvalidIDToken) {
			t.Fatalf("%s: errors.Is(ErrInvalidIDToken)", name)
		}
	}
	s.idExtra = nil
	s.noIDToken = true
	err := run(nil)
	wantDescription(t, err, "no ID token")
	// Without the openid scope there is no ID token to check.
	c := newTestAuth(t, s, WebAppAuthConfig{Scopes: []string{"orders:read offline_access"}})
	login := must[*Login](t)(c.CreateLogin(ctx, LoginOptions{}))
	if mustQuery(t, login.URL).Get("scope") != "orders:read offline_access" {
		t.Fatal("scopes")
	}
	tokens, err := c.HandleCallback(ctx, s.authorize(t, login.URL), login.Pending)
	if err != nil || tokens.Claims != nil {
		t.Fatalf("%v %v", err, tokens)
	}
}

func TestRefreshRotatesAndEnsureFresh(t *testing.T) {
	s := newSignInServer(t, "app_web")
	a := newTestAuth(t, s, WebAppAuthConfig{})
	login := must[*Login](t)(a.CreateLogin(ctx, LoginOptions{ReturnTo: "/x"}))
	tokens := must[*TokenSet](t)(a.HandleCallback(ctx, s.authorize(t, login.URL), login.Pending))

	same, err := a.EnsureFresh(ctx, tokens, time.Minute)
	if err != nil || same != tokens {
		t.Fatal("a fresh set comes back as is")
	}
	if s.form("/oauth/token").Get("grant_type") != "authorization_code" {
		t.Fatal("no request for a fresh set")
	}
	tokens.ExpiresAt = time.Now().Add(30 * time.Second)
	next, err := a.EnsureFresh(ctx, tokens, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if next.RefreshToken != "rt-1+" || next.AccessToken != "at-rt-1" || next.Claims.Subject() != "usr_1" || next.ReturnTo != "/x" || next.Scope != tokens.Scope || next.IDToken == "" {
		t.Fatalf("refreshed %+v", next)
	}
	// The old refresh token was rotated away.
	_, err = a.Refresh(ctx, "rt-1")
	wantCode(t, err, "invalid_grant", 400)
	// Without rotation, the old refresh token is kept.
	s.rotate = false
	kept := must[*TokenSet](t)(a.Refresh(ctx, "rt-1+"))
	if kept.RefreshToken != "rt-1+" {
		t.Fatalf("kept %q", kept.RefreshToken)
	}
	_, err = a.Refresh(ctx, "")
	wantCode(t, err, "login_required", 401)
	_, err = a.EnsureFresh(ctx, nil, 0)
	wantCode(t, err, "login_required", 401)
}

func TestEnsureFreshRefusesAnotherUsersIDToken(t *testing.T) {
	s := newSignInServer(t, "app_web")
	a := newTestAuth(t, s, WebAppAuthConfig{})
	s.refreshes["rt"] = true
	old := &TokenSet{AccessToken: "x", RefreshToken: "rt", Claims: Claims{"sub": "usr_other"}}
	_, err := a.EnsureFresh(ctx, old, 0)
	wantCode(t, err, "invalid_id_token", 401)
}

func TestUserInfoRevokeLogoutAndClientCredentials(t *testing.T) {
	s := newSignInServer(t, "app_web")
	s.userinfo = func(r *http.Request) (int, any) {
		if r.Header.Get("Authorization") != "Bearer good" {
			return 401, map[string]any{"error": "invalid_token"}
		}
		return 200, map[string]any{"sub": "usr_1", "email": "jane@acme.test"}
	}
	revoked := map[string]string{}
	s.revoke = func(r *http.Request, form url.Values) (int, any) {
		if r.Header.Get("Authorization") != basicAuth("app_web", "s3cret") {
			return 401, map[string]any{"error": "invalid_client"}
		}
		revoked[form.Get("token")] = form.Get("token_type_hint")
		return 200, nil
	}
	a := newTestAuth(t, s, WebAppAuthConfig{ClientSecret: "s3cret"})
	info, err := a.UserInfo(ctx, "good")
	if err != nil || info.String("email") != "jane@acme.test" {
		t.Fatalf("%v %v", err, info)
	}
	_, err = a.UserInfo(ctx, "bad")
	wantCode(t, err, "invalid_token", 401)

	if err := a.Revoke(ctx, "rt-9", ""); err != nil {
		t.Fatal(err)
	}
	if err := a.Revoke(ctx, "at-9", "access_token"); err != nil {
		t.Fatal(err)
	}
	if revoked["rt-9"] != "refresh_token" || revoked["at-9"] != "access_token" {
		t.Fatalf("revoked %v", revoked)
	}
	wrong := newTestAuth(t, s, WebAppAuthConfig{ClientSecret: "nope"})
	wantCode(t, wrong.Revoke(ctx, "x", ""), "invalid_client", 401)

	logout := must[string](t)(a.LogoutURL(ctx, LogoutOptions{IDTokenHint: "idt", PostLogoutRedirectURI: "https://app.acme.test/", State: "st"}))
	u, _ := url.Parse(logout)
	q := u.Query()
	if u.Path != "/oauth/logout" || q.Get("client_id") != "app_web" || q.Get("id_token_hint") != "idt" || q.Get("post_logout_redirect_uri") != "https://app.acme.test/" || q.Get("state") != "st" {
		t.Fatalf("logout %s", logout)
	}

	cc := must[*TokenSet](t)(a.ClientCredentials(ctx, ClientCredentialsOptions{Audience: "https://api.acme.test", Scope: "reports:read"}))
	form := s.form("/oauth/token")
	if cc.AccessToken != "cc-token" || form.Get("grant_type") != "client_credentials" || form.Get("audience") != "https://api.acme.test" || form.Get("scope") != "reports:read" || cc.RefreshToken != "" {
		t.Fatalf("%+v %v", cc, form)
	}
	public := newTestAuth(t, s, WebAppAuthConfig{})
	_, err = public.ClientCredentials(ctx, ClientCredentialsOptions{})
	wantCode(t, err, "invalid_options", 0)

	// No revocation endpoint: nothing to do.
	s.discovery = func(doc map[string]any) { delete(doc, "revocation_endpoint") }
	if err := newTestAuth(t, s, WebAppAuthConfig{}).Revoke(ctx, "x", ""); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoveryIsCachedAndFailuresAreNot(t *testing.T) {
	s := newSignInServer(t, "app_web")
	a := newTestAuth(t, s, WebAppAuthConfig{})
	for i := 0; i < 3; i++ {
		if _, err := a.CreateLogin(ctx, LoginOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	if n := s.count("/.well-known/openid-configuration"); n != 1 {
		t.Fatalf("discovery fetched %d times", n)
	}
	broken := true
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if broken {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		s.serve(w, r)
	}))
	defer srv.Close()
	b := must[*WebAppAuth](t)(NewWebAppAuth(WebAppAuthConfig{Issuer: s.issuer, ClientID: "x", RedirectURI: "https://x.test/cb", HTTPClient: &http.Client{Transport: rewriteTo(srv.URL)}}))
	_, err := b.CreateLogin(ctx, LoginOptions{})
	wantCode(t, err, "discovery_failed", 503)
	mu.Lock()
	broken = false
	mu.Unlock()
	if _, err := b.CreateLogin(ctx, LoginOptions{}); err != nil {
		t.Fatalf("a failure must not be cached: %v", err)
	}
}

func rewriteTo(target string) http.RoundTripper {
	u, _ := url.Parse(target)
	return roundTripFunc(func(r *http.Request) (*http.Response, error) {
		r = r.Clone(r.Context())
		r.URL.Scheme, r.URL.Host = u.Scheme, u.Host
		return http.DefaultTransport.RoundTrip(r)
	})
}

func TestRedirectsAreNeverFollowed(t *testing.T) {
	var elsewhere sync.Map
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elsewhere.Store(r.URL.Path, r.Header.Get("Authorization"))
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"access_token":"stolen"}`))
	}))
	defer other.Close()
	s := newSignInServer(t, "app_web")
	s.token = func(r *http.Request, form url.Values) (int, any) { return 0, nil }
	s.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			http.Redirect(w, r, other.URL+"/steal", http.StatusTemporaryRedirect)
			return
		}
		s.serve(w, r)
	})
	a := newTestAuth(t, s, WebAppAuthConfig{ClientSecret: "s3cret"})
	_, err := a.ClientCredentials(ctx, ClientCredentialsOptions{})
	wantCode(t, err, "request_failed", 307)
	wantDescription(t, err, "redirects are not followed")
	if _, hit := elsewhere.Load("/steal"); hit {
		t.Fatal("the redirect was followed")
	}
}
