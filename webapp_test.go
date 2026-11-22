package nine

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	appSecret = "0123456789abcdef0123456789abcdef-test"
	appBase   = "https://app.acme.test"
)

// browser keeps cookies across requests to a handler, like a real browser.
type browser struct {
	t   *testing.T
	jar *cookiejar.Jar
	h   http.Handler
}

func newBrowser(t *testing.T, h http.Handler) *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{t: t, jar: jar, h: h}
}

func (b *browser) do(r *http.Request) *httptest.ResponseRecorder {
	b.t.Helper()
	for _, c := range b.jar.Cookies(r.URL) {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	b.h.ServeHTTP(w, r)
	b.jar.SetCookies(r.URL, w.Result().Cookies())
	return w
}

func (b *browser) get(target string, header ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	for i := 0; i+1 < len(header); i += 2 {
		r.Header.Set(header[i], header[i+1])
	}
	return b.do(r)
}

func (b *browser) cookie(name string) *http.Cookie {
	u, _ := url.Parse(appBase + "/")
	for _, c := range b.jar.Cookies(u) {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func setCookie(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

type webAppSetup struct {
	s       *signInServer
	app     *WebApp
	mux     *http.ServeMux
	clock   *clock
	revoked sync.Map
}

func newWebAppSetup(t *testing.T, cfg WebAppConfig) *webAppSetup {
	s := newSignInServer(t, "app_web")
	w := &webAppSetup{s: s}
	s.revoke = func(r *http.Request, form url.Values) (int, any) {
		w.revoked.Store(form.Get("token"), true)
		return 200, nil
	}
	cfg.Issuer = s.issuer
	cfg.ClientID = "app_web"
	if cfg.Secret == "" {
		cfg.Secret = appSecret
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = appBase
	}
	w.app = must[*WebApp](t)(NewWebApp(cfg))
	w.clock = newClock()
	w.app.now = w.clock.Now
	w.app.auth.o.verifier.now = w.clock.Now
	w.mux = http.NewServeMux()
	w.mux.Handle("/nine/", w.app)
	w.mux.Handle("/dashboard", w.app.RequireUser(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		user := UserFrom(r.Context())
		token, err := w.app.AccessToken(rw, r)
		if err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
		_ = json.NewEncoder(rw).Encode(map[string]string{"email": user.Email, "sub": user.Subject, "token": token})
	})))
	w.mux.Handle("/", w.app.Middleware(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if u := UserFrom(r.Context()); u != nil {
			_, _ = io.WriteString(rw, "hello "+u.Name)
			return
		}
		_, _ = io.WriteString(rw, "signed out")
	})))
	return w
}

// signIn runs the whole sign-in in b and returns the callback response.
func (w *webAppSetup) signIn(t *testing.T, b *browser, loginPath string) *httptest.ResponseRecorder {
	t.Helper()
	res := b.get(appBase + loginPath)
	if res.Code != http.StatusFound {
		t.Fatalf("login: %d %s", res.Code, res.Body)
	}
	query := w.s.authorize(t, res.Header().Get("Location"))
	return b.get(appBase + "/nine/callback?" + query.Encode())
}

func TestWebAppSignInFlow(t *testing.T) {
	w := newWebAppSetup(t, WebAppConfig{Audience: "https://api.acme.test"})
	b := newBrowser(t, w.mux)

	login := b.get(appBase + "/nine/login?return_to=%2Fdashboard%3Ftab%3D1&login_hint=jane%40acme.test&locale=de&prompt=login")
	if login.Code != http.StatusFound || login.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("login %d", login.Code)
	}
	authorize, _ := url.Parse(login.Header().Get("Location"))
	q := authorize.Query()
	if q.Get("redirect_uri") != appBase+"/nine/callback" || q.Get("login_hint") != "jane@acme.test" || q.Get("ui_locales") != "de" || q.Get("prompt") != "login" || q.Get("audience") != "https://api.acme.test" {
		t.Fatalf("authorize %s", authorize)
	}
	tx := setCookie(login, "nine_session_tx_"+q.Get("state"))
	if tx == nil || tx.Path != "/nine" || !tx.HttpOnly || !tx.Secure || tx.SameSite != http.SameSiteLaxMode || tx.MaxAge != 900 {
		t.Fatalf("transaction cookie %+v", tx)
	}
	if strings.Contains(tx.Value, q.Get("state")) || strings.Contains(tx.Value, "verifier") {
		t.Fatal("the transaction cookie must be encrypted")
	}

	callback := b.get(appBase + "/nine/callback?" + w.s.authorize(t, login.Header().Get("Location")).Encode())
	if callback.Code != http.StatusFound || callback.Header().Get("Location") != appBase+"/dashboard?tab=1" {
		t.Fatalf("callback %d %s %s", callback.Code, callback.Header().Get("Location"), callback.Body)
	}
	session := setCookie(callback, "nine_session")
	if session == nil || session.Path != "/" || !session.HttpOnly || !session.Secure || session.SameSite != http.SameSiteLaxMode || session.MaxAge != 30*24*3600 {
		t.Fatalf("session cookie %+v", session)
	}
	if cleared := setCookie(callback, tx.Name); cleared == nil || cleared.MaxAge >= 0 {
		t.Fatalf("the transaction cookie must be cleared: %+v", cleared)
	}
	if strings.Contains(session.Value, "at-1") || strings.Contains(session.Value, "jane") {
		t.Fatal("the session cookie must be encrypted")
	}

	dash := b.get(appBase + "/dashboard?tab=1")
	var got map[string]string
	_ = json.Unmarshal(dash.Body.Bytes(), &got)
	if dash.Code != 200 || got["email"] != "jane@acme.test" || got["sub"] != "usr_1" || got["token"] != "at-1" {
		t.Fatalf("dashboard %d %s", dash.Code, dash.Body)
	}
	if home := b.get(appBase + "/"); home.Body.String() != "hello Jane" {
		t.Fatalf("home %s", home.Body)
	}
	user := w.app.User(httptest.NewRequest("GET", appBase+"/", nil))
	if user != nil {
		t.Fatal("no cookie, no user")
	}

	// The access token nears expiry: the middleware refreshes it and saves the new refresh token.
	w.clock.Advance(59*time.Minute + 30*time.Second)
	dash = b.get(appBase + "/dashboard")
	_ = json.Unmarshal(dash.Body.Bytes(), &got)
	if got["token"] != "at-rt-1" || setCookie(dash, "nine_session") == nil {
		t.Fatalf("refresh: %s", dash.Body)
	}
	if n := w.s.count("/oauth/token"); n != 2 {
		t.Fatalf("token requests %d", n)
	}
	// The next refresh uses the rotated token.
	w.clock.Advance(10 * time.Minute)
	dash = b.get(appBase + "/dashboard")
	_ = json.Unmarshal(dash.Body.Bytes(), &got)
	if got["token"] != "at-rt-1+" {
		t.Fatalf("second refresh: %s", dash.Body)
	}

	// Sign out: cookies cleared, refresh token revoked, then 9in's end-session URL.
	out := b.get(appBase + "/nine/logout")
	if out.Code != http.StatusFound {
		t.Fatalf("logout %d", out.Code)
	}
	end, _ := url.Parse(out.Header().Get("Location"))
	if end.Path != "/oauth/logout" || end.Query().Get("client_id") != "app_web" || end.Query().Get("post_logout_redirect_uri") != appBase+"/" {
		t.Fatalf("end session %s", end)
	}
	if _, ok := w.revoked.Load("rt-1++"); !ok {
		t.Fatal("the refresh token must be revoked")
	}
	if b.cookie("nine_session") != nil {
		t.Fatal("the session cookie must be cleared")
	}
	if home := b.get(appBase + "/"); home.Body.String() != "signed out" {
		t.Fatalf("after logout: %s", home.Body)
	}
}

func TestWebAppRequireUser(t *testing.T) {
	w := newWebAppSetup(t, WebAppConfig{})
	b := newBrowser(t, w.mux)
	page := b.get(appBase+"/dashboard?x=1", "Accept", "text/html,application/xhtml+xml")
	if page.Code != http.StatusFound || page.Header().Get("Location") != appBase+"/nine/login?return_to=%2Fdashboard%3Fx%3D1" {
		t.Fatalf("page %d %s", page.Code, page.Header().Get("Location"))
	}
	nav := b.get(appBase+"/dashboard", "Sec-Fetch-Mode", "navigate")
	if nav.Code != http.StatusFound {
		t.Fatalf("navigation %d", nav.Code)
	}
	api := b.get(appBase+"/dashboard", "Accept", "application/json")
	if api.Code != http.StatusUnauthorized || !strings.Contains(api.Body.String(), `"error":"unauthorized"`) {
		t.Fatalf("api %d %s", api.Code, api.Body)
	}
	// Signing in via the redirect comes back to the page.
	res := w.signIn(t, b, "/nine/login?return_to=%2Fdashboard%3Fx%3D1")
	if res.Header().Get("Location") != appBase+"/dashboard?x=1" {
		t.Fatalf("return %s", res.Header().Get("Location"))
	}
}

func TestWebAppLoginRoutes(t *testing.T) {
	w := newWebAppSetup(t, WebAppConfig{AfterSignInPath: "/home"})
	b := newBrowser(t, w.mux)
	for path, want := range map[string]string{
		"/nine/signup":                   "create",
		"/nine/login?screen=signup":      "create",
		"/nine/login?prompt=none":        "none",
		"/nine/login?prompt=evil":        "",
		"/nine/login?ui_locales=fr":      "",
		"/nine/login?return_to=//evil.x": "",
	} {
		res := b.get(appBase + path)
		q := mustQuery(t, res.Header().Get("Location"))
		if q.Get("prompt") != want {
			t.Errorf("%s: prompt %q, want %q", path, q.Get("prompt"), want)
		}
	}
	// An unsafe return_to falls back to AfterSignInPath.
	res := w.signIn(t, newBrowser(t, w.mux), "/nine/login?return_to=https%3A%2F%2Fevil.test%2F")
	if res.Header().Get("Location") != appBase+"/home" {
		t.Fatalf("fallback %s", res.Header().Get("Location"))
	}
	// Link prefetches don't start a sign-in.
	pre := b.get(appBase+"/nine/login", "Sec-Purpose", "prefetch")
	if pre.Code != http.StatusNoContent || len(pre.Result().Cookies()) != 0 {
		t.Fatalf("prefetch %d", pre.Code)
	}
	if res := b.get(appBase + "/nine/nothing"); res.Code != 404 {
		t.Fatalf("unknown route %d", res.Code)
	}
	if res := b.get(appBase + "/nine/login/"); res.Code != http.StatusFound {
		t.Fatalf("trailing slash %d", res.Code)
	}
}

func TestWebAppAbandonedSignInsDontPileUp(t *testing.T) {
	w := newWebAppSetup(t, WebAppConfig{})
	b := newBrowser(t, w.mux)
	for i := 0; i < 5; i++ {
		b.get(appBase + "/nine/login")
	}
	u, _ := url.Parse(appBase + "/nine/callback")
	count := func() int {
		n := 0
		for _, c := range b.jar.Cookies(u) {
			if strings.HasPrefix(c.Name, "nine_session_tx_") {
				n++
			}
		}
		return n
	}
	if count() != 5 {
		t.Fatalf("%d pending", count())
	}
	b.get(appBase + "/nine/login")
	if count() != 1 {
		t.Fatalf("after cleanup: %d pending", count())
	}
}

func TestWebAppCallbackFailures(t *testing.T) {
	w := newWebAppSetup(t, WebAppConfig{})
	b := newBrowser(t, w.mux)
	res := b.get(appBase + "/nine/callback?code=x&state=abc&iss=" + url.QueryEscape(w.s.issuer))
	if res.Code != 400 || !strings.Contains(res.Body.String(), "Sign-in failed: invalid_state") || !strings.Contains(res.Body.String(), "Start again: "+appBase+"/nine/login") {
		t.Fatalf("no transaction: %d %s", res.Code, res.Body)
	}
	if res.Header().Get("Content-Type") != "text/plain; charset=utf-8" || res.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("the error page must be plain text")
	}
	login := b.get(appBase + "/nine/login")
	state := mustQuery(t, login.Header().Get("Location")).Get("state")
	res = b.get(appBase + "/nine/callback?error=access_denied&error_description=%3Cscript%3E&state=" + state)
	if res.Code != 400 || !strings.Contains(res.Body.String(), "access_denied") {
		t.Fatalf("access_denied: %d %s", res.Code, res.Body)
	}
	if setCookie(res, "nine_session_tx_"+state) == nil {
		t.Fatal("the transaction cookie is cleared even when sign-in fails")
	}
	// Junk state values never become cookie names.
	res = b.get(appBase + "/nine/callback?code=x&state=" + url.QueryEscape("a;b=c"))
	if res.Code != 400 {
		t.Fatalf("junk state %d", res.Code)
	}

	var handled error
	custom := newWebAppSetup(t, WebAppConfig{OnError: func(rw http.ResponseWriter, r *http.Request, err error) {
		handled = err
		http.Redirect(rw, r, "/sign-in-failed", http.StatusFound)
	}})
	res = newBrowser(t, custom.mux).get(appBase + "/nine/callback?error=access_denied")
	if res.Code != http.StatusFound || !errors.Is(handled, ErrAccessDenied) {
		t.Fatalf("custom: %d %v", res.Code, handled)
	}
}

func TestWebAppCookiesAreEncryptedAndBound(t *testing.T) {
	w := newWebAppSetup(t, WebAppConfig{})
	b := newBrowser(t, w.mux)
	w.signIn(t, b, "/nine/login")
	session := b.cookie("nine_session")

	// A value sealed as a transaction can't be used as a session, and vice versa.
	tx, _ := w.app.sealer.seal(map[string]any{"v": 1, "user": map[string]any{"sub": "usr_evil"}, "at": "x", "exp": time.Now().Add(time.Hour).Unix()}, "transaction")
	r := httptest.NewRequest("GET", appBase+"/", nil)
	r.AddCookie(&http.Cookie{Name: "nine_session", Value: tx})
	if w.app.User(r) != nil {
		t.Fatal("a transaction value accepted as a session")
	}
	// A tampered session is treated as signed out, and its cookie removed.
	tampered := []byte(session.Value)
	tampered[len(tampered)/2] ^= 0x01
	r = httptest.NewRequest("GET", appBase+"/", nil)
	r.AddCookie(&http.Cookie{Name: "nine_session", Value: string(tampered)})
	res := httptest.NewRecorder()
	w.mux.ServeHTTP(res, r)
	if res.Body.String() != "signed out" || setCookie(res, "nine_session") == nil || setCookie(res, "nine_session").MaxAge >= 0 {
		t.Fatalf("tampered: %s", res.Body)
	}

	// Rotation: an app with a new secret still opens cookies sealed with the old one.
	rotated := must[*WebApp](t)(NewWebApp(WebAppConfig{Issuer: w.s.issuer, ClientID: "app_web", BaseURL: appBase, Secret: "a-brand-new-secret-of-32-characters!!", Secrets: []string{appSecret}}))
	r = httptest.NewRequest("GET", appBase+"/", nil)
	r.AddCookie(session)
	if u := rotated.User(r); u == nil || u.Email != "jane@acme.test" {
		t.Fatal("rotation")
	}
	other := must[*WebApp](t)(NewWebApp(WebAppConfig{Issuer: w.s.issuer, ClientID: "app_web", BaseURL: appBase, Secret: "a-brand-new-secret-of-32-characters!!"}))
	if other.User(r) != nil {
		t.Fatal("another secret must not open the cookie")
	}

	// An expired session is gone.
	w.clock.Advance(31 * 24 * time.Hour)
	if w.app.User(r) != nil {
		t.Fatal("expired session")
	}
}

func TestWebAppLargeSessionsAreChunked(t *testing.T) {
	w := newWebAppSetup(t, WebAppConfig{})
	w.s.idExtra = map[string]any{"bio": strings.Repeat("long profile text ", 400)}
	b := newBrowser(t, w.mux)
	res := w.signIn(t, b, "/nine/login")
	if setCookie(res, "nine_session.0") == nil || setCookie(res, "nine_session.1") == nil {
		t.Fatalf("not chunked: %v", res.Result().Cookies())
	}
	for _, c := range res.Result().Cookies() {
		if len(c.Value) > cookieChunkSize {
			t.Fatalf("%s is %d bytes", c.Name, len(c.Value))
		}
	}
	if home := b.get(appBase + "/"); home.Body.String() != "hello Jane" {
		t.Fatalf("chunked session not read: %s", home.Body)
	}
	// Signing in again with a small profile removes the chunks.
	w.s.idExtra = nil
	res = w.signIn(t, b, "/nine/login")
	if c := setCookie(res, "nine_session.1"); c == nil || c.MaxAge >= 0 {
		t.Fatal("old chunks must be removed")
	}
	if b.cookie("nine_session.0") != nil || b.cookie("nine_session") == nil {
		t.Fatal("cookies after shrinking")
	}
}

func TestWebAppRefreshIsSharedAndEndsRevokedSessions(t *testing.T) {
	w := newWebAppSetup(t, WebAppConfig{})
	b := newBrowser(t, w.mux)
	w.signIn(t, b, "/nine/login")
	session := b.cookie("nine_session")
	w.clock.Advance(59*time.Minute + 30*time.Second)

	// Requests arriving together with the same old cookie share one refresh, and later
	// requests still carrying it get the same new tokens (no reuse detection at 9in).
	var refreshes atomic.Int32
	base := w.s.token
	w.s.token = func(r *http.Request, form url.Values) (int, any) {
		if form.Get("grant_type") == "refresh_token" {
			refreshes.Add(1)
			time.Sleep(20 * time.Millisecond)
		}
		return base(r, form)
	}
	var wg sync.WaitGroup
	tokens := make(chan string, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := httptest.NewRequest("GET", appBase+"/dashboard", nil)
			r.AddCookie(session)
			res := httptest.NewRecorder()
			w.mux.ServeHTTP(res, r)
			var got map[string]string
			_ = json.Unmarshal(res.Body.Bytes(), &got)
			tokens <- got["token"]
		}()
	}
	wg.Wait()
	close(tokens)
	for tok := range tokens {
		if tok != "at-rt-1" {
			t.Fatalf("token %q", tok)
		}
	}
	if refreshes.Load() != 1 {
		t.Fatalf("%d refreshes", refreshes.Load())
	}
	// 9in can't be reached: the session is kept.
	w.clock.Advance(time.Minute)
	w.s.token = func(*http.Request, url.Values) (int, any) {
		return 503, map[string]any{"error": "temporarily_unavailable"}
	}
	r := httptest.NewRequest("GET", appBase+"/", nil)
	r.AddCookie(session)
	res := httptest.NewRecorder()
	w.mux.ServeHTTP(res, r)
	if res.Body.String() != "hello Jane" {
		t.Fatalf("unreachable: %s", res.Body)
	}
	// 9in ended the session (invalid_grant): signed out, cookie removed.
	w.clock.Advance(time.Minute)
	w.s.token = func(*http.Request, url.Values) (int, any) { return 400, map[string]any{"error": "invalid_grant"} }
	res = httptest.NewRecorder()
	w.mux.ServeHTTP(res, r)
	if res.Body.String() != "signed out" || setCookie(res, "nine_session") == nil {
		t.Fatalf("revoked: %s", res.Body)
	}
	// AccessToken outside the middleware says login_required.
	rec := httptest.NewRecorder()
	_, err := w.app.AccessToken(rec, r)
	wantCode(t, err, "login_required", 401)
}

func TestWebAppAccessTokenWithoutRefreshToken(t *testing.T) {
	w := newWebAppSetup(t, WebAppConfig{Scopes: []string{"openid", "email", "profile"}})
	w.s.token = func(r *http.Request, form url.Values) (int, any) {
		grant := w.s.codes[form.Get("code")]
		return 200, map[string]any{"access_token": "short", "expires_in": 3600, "id_token": w.s.idToken(t, "app_web", grant.nonce, nil)}
	}
	b := newBrowser(t, w.mux)
	w.signIn(t, b, "/nine/login")
	session := b.cookie("nine_session")
	r := httptest.NewRequest("GET", appBase+"/x", nil)
	r.AddCookie(session)
	tok, err := w.app.AccessToken(httptest.NewRecorder(), r)
	if err != nil || tok != "short" {
		t.Fatalf("%v %q", err, tok)
	}
	w.clock.Advance(59*time.Minute + 30*time.Second)
	if tok, _ := w.app.AccessToken(httptest.NewRecorder(), r); tok != "short" {
		t.Fatal("still valid, can't refresh: the current token")
	}
	w.clock.Advance(time.Minute)
	_, err = w.app.AccessToken(httptest.NewRecorder(), r)
	wantCode(t, err, "login_required", 401)
	wantDescription(t, err, "offline_access")
	// The user is still signed in (the session outlives the access token).
	if w.app.User(r) == nil {
		t.Fatal("user")
	}
}

func TestWebAppLogoutVariants(t *testing.T) {
	w := newWebAppSetup(t, WebAppConfig{AfterSignOutPath: "/bye"})
	b := newBrowser(t, w.mux)
	w.signIn(t, b, "/nine/login")
	pre := b.get(appBase+"/nine/logout", "Purpose", "prefetch")
	if pre.Code != http.StatusNoContent || b.cookie("nine_session") == nil {
		t.Fatal("a prefetch must not sign out")
	}
	r := httptest.NewRequest(http.MethodPost, appBase+"/nine/logout", strings.NewReader("return_to=%2Fsee-you&local=1"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res := b.do(r)
	if res.Code != http.StatusSeeOther || res.Header().Get("Location") != appBase+"/see-you" {
		t.Fatalf("local POST logout: %d %s", res.Code, res.Header().Get("Location"))
	}
	if b.cookie("nine_session") != nil {
		t.Fatal("cookie kept")
	}
	res = b.get(appBase + "/nine/logout?return_to=https%3A%2F%2Fevil.test")
	if q := mustQuery(t, res.Header().Get("Location")); q.Get("post_logout_redirect_uri") != appBase+"/bye" {
		t.Fatalf("unsafe return_to: %s", res.Header().Get("Location"))
	}
	put := httptest.NewRequest(http.MethodPut, appBase+"/nine/logout", nil)
	if res := b.do(put); res.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT %d", res.Code)
	}
}

func TestWebAppAtTheRootWithoutBaseURL(t *testing.T) {
	s := newSignInServer(t, "app_web")
	app := must[*WebApp](t)(NewWebApp(WebAppConfig{Issuer: s.issuer, ClientID: "app_web", Secret: appSecret, BasePath: "/"}))
	b := newBrowser(t, app)
	b.t = t
	r := httptest.NewRequest("GET", "http://127.0.0.1:8932/login", nil)
	res := b.do(r)
	if res.Code != http.StatusFound {
		t.Fatalf("login %d", res.Code)
	}
	q := mustQuery(t, res.Header().Get("Location"))
	if q.Get("redirect_uri") != "http://127.0.0.1:8932/callback" {
		t.Fatalf("redirect_uri %s", q.Get("redirect_uri"))
	}
	tx := setCookie(res, "nine_session_tx_"+q.Get("state"))
	if tx.Secure || tx.Path != "/" {
		t.Fatalf("plain-http cookie %+v", tx)
	}
	cb := httptest.NewRequest("GET", "http://127.0.0.1:8932/callback?"+s.authorize(t, res.Header().Get("Location")).Encode(), nil)
	res = b.do(cb)
	if res.Code != http.StatusFound || res.Header().Get("Location") != "/" {
		t.Fatalf("callback %d %s %s", res.Code, res.Header().Get("Location"), res.Body)
	}
}

func TestWebAppConfigValidation(t *testing.T) {
	s := newSignInServer(t, "app_web")
	for name, cfg := range map[string]WebAppConfig{
		"no secret":       {},
		"short secret":    {Secret: "short"},
		"short old":       {Secret: appSecret, Secrets: []string{"short"}},
		"bad base URL":    {Secret: appSecret, BaseURL: "app.acme.test"},
		"base URL query":  {Secret: appSecret, BaseURL: "https://app.acme.test/?x"},
		"unsafe redirect": {Secret: appSecret, AfterSignInPath: "https://evil.test"},
		"unsafe logout":   {Secret: appSecret, AfterSignOutPath: "//evil.test"},
	} {
		cfg.Issuer, cfg.ClientID = s.issuer, "app_web"
		_, err := NewWebApp(cfg)
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else {
			wantCode(t, err, "invalid_options", 0)
		}
	}
	_, err := NewWebApp(WebAppConfig{ClientID: "x", Secret: appSecret})
	wantCode(t, err, "invalid_options", 0)
	_, err = NewWebApp(WebAppConfig{Issuer: s.issuer, Secret: appSecret})
	wantCode(t, err, "invalid_options", 0)
	app := must[*WebApp](t)(NewWebApp(WebAppConfig{Issuer: s.issuer, ClientID: "app_web", Secret: appSecret, BaseURL: "https://app.acme.test/", BasePath: "auth/"}))
	if app.cfg.BaseURL != "https://app.acme.test" || app.basePath != "/auth" || app.Auth() == nil {
		t.Fatalf("normalised %+v %s", app.cfg.BaseURL, app.basePath)
	}
}

func TestSealer(t *testing.T) {
	s := must[*sealer](t)(newSealer([]string{appSecret}))
	sealed := must[string](t)(s.seal(map[string]string{"a": "b"}, "p"))
	var out map[string]string
	if !s.open(sealed, "p", &out) || out["a"] != "b" {
		t.Fatal("round trip")
	}
	if s.open(sealed, "q", &out) {
		t.Fatal("purpose")
	}
	for _, junk := range []string{"", "!!", "abc", sealed[:10]} {
		if s.open(junk, "p", &out) {
			t.Fatalf("%q opened", junk)
		}
	}
	again := must[string](t)(s.seal(map[string]string{"a": "b"}, "p"))
	if again == sealed {
		t.Fatal("the nonce must be random")
	}
	// HKDF-SHA256 against RFC 5869 test case 1 (first 32 bytes of OKM).
	ikm := make([]byte, 22)
	for i := range ikm {
		ikm[i] = 0x0b
	}
	salt := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	info := []byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9}
	if got := b16(hkdfSHA256(ikm, salt, info, 32)); got != "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf" {
		t.Fatalf("HKDF %s", got)
	}
}

func b16(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, hexdigits[c>>4], hexdigits[c&15])
	}
	return string(out)
}
