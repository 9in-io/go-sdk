package nine

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestParseJWKRefusesBadKeys(t *testing.T) {
	str := func(s string) *string { return &s }
	good := jwkFor(t, "ES256", "x")
	cases := map[string]jsonWebKey{
		"RSA without n":       {Kty: "RSA", E: "AQAB"},
		"RSA bad base64":      {Kty: "RSA", N: "!!", E: "AQAB"},
		"RSA even exponent":   {Kty: "RSA", N: b64(keys(t).rsa.N.Bytes()), E: b64([]byte{2})},
		"RSA exponent 1":      {Kty: "RSA", N: b64(keys(t).rsa.N.Bytes()), E: b64([]byte{1})},
		"RSA huge exponent":   {Kty: "RSA", N: b64(keys(t).rsa.N.Bytes()), E: b64([]byte{1, 0, 0, 0, 1})},
		"EC unknown curve":    {Kty: "EC", Crv: "P-521", X: good["x"].(string), Y: good["y"].(string)},
		"EC short coordinate": {Kty: "EC", Crv: "P-256", X: "AQAB", Y: good["y"].(string)},
		"EC P-384 with P-256": {Kty: "EC", Crv: "P-384", X: good["x"].(string), Y: good["y"].(string)},
		"OKP X25519":          {Kty: "OKP", Crv: "X25519", X: b64(make([]byte, 32))},
		"OKP short":           {Kty: "OKP", Crv: "Ed25519", X: "AQAB"},
		"unknown key type":    {Kty: "oct"},
		"no key type":         {Kid: str("k")},
	}
	for name, j := range cases {
		if k := parseJWK(j); k.err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if k := parseJWK(jsonWebKey{Kty: "RSA", Kid: str("k"), N: b64(keys(t).rsa.N.Bytes()), E: "AQAB"}); k.err != nil || !k.hasKid || k.kid != "k" {
		t.Fatalf("good RSA key: %v", k.err)
	}
	// A JWKS with junk keys still serves the good ones.
	f := newFakeIssuer(t)
	f.setKeys(map[string]any{"kty": "RSA", "kid": "junk", "n": "!!"}, jwkFor(t, "EdDSA", "k-EdDSA"))
	v := newTestVerifier(t, f, VerifierConfig{})
	if _, err := v.Verify(ctx, makeToken(t, "EdDSA", nil, claimsFor(f.issuer, nil))); err != nil {
		t.Fatal(err)
	}
	// verify refuses a signature for a key of the wrong type.
	k := parseJWK(jsonWebKey{Kty: "OKP", Crv: "Ed25519", X: jwkFor(t, "EdDSA", "e")["x"].(string)})
	for _, alg := range []string{"RS256", "PS256", "ES256"} {
		if k.verify(alg, "x", []byte("sig")) {
			t.Fatalf("%s verified with an Ed25519 key", alg)
		}
	}
	if k.fits("HS256") || k.verify("HS256", "x", nil) {
		t.Fatal("HMAC with a public key")
	}
}

func TestAccessTokenRetriesWhenTheMiddlewareCouldNotRefresh(t *testing.T) {
	w := newWebAppSetup(t, WebAppConfig{})
	b := newBrowser(t, w.mux)
	w.signIn(t, b, "/nine/login")
	session := b.cookie("nine_session")
	request := func() *http.Request {
		r := httptest.NewRequest("GET", appBase+"/api", nil)
		r.AddCookie(session)
		return r
	}
	base := w.s.token
	down := func(*http.Request, url.Values) (int, any) {
		return 503, map[string]any{"error": "temporarily_unavailable"}
	}

	// Within the leeway, 9in down: the current token is still good.
	w.clock.Advance(59*time.Minute + 30*time.Second)
	w.s.token = down
	tok, err := w.app.AccessToken(httptest.NewRecorder(), request())
	if err != nil || tok != "at-1" {
		t.Fatalf("%v %q", err, tok)
	}
	// Expired and 9in down: the error.
	w.clock.Advance(time.Minute)
	_, err = w.app.AccessToken(httptest.NewRecorder(), request())
	wantCode(t, err, "temporarily_unavailable", 503)
	// 9in back: refreshed, and the new cookie written.
	w.s.token = base
	rec := httptest.NewRecorder()
	tok, err = w.app.AccessToken(rec, request())
	if err != nil || tok != "at-rt-1" || setCookie(rec, "nine_session") == nil {
		t.Fatalf("%v %q", err, tok)
	}
	// Through the middleware, a handler's AccessToken sees the refreshed session.
	var inside string
	h := w.app.Middleware(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		inside, _ = w.app.AccessToken(rw, r)
		if w.app.User(r) == nil || UserFrom(r.Context()) == nil {
			t.Error("user in context")
		}
	}))
	r := request()
	r.Header.Set("Cookie", "")
	r.AddCookie(setCookie(rec, "nine_session"))
	h.ServeHTTP(httptest.NewRecorder(), r)
	if inside != "at-rt-1" {
		t.Fatalf("inside %q", inside)
	}
	// The middleware leaves the sign-in routes alone.
	called := false
	w.app.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", appBase+"/nine/login", nil))
	if !called {
		t.Fatal("own route")
	}
	if UserFrom(ctx) != nil {
		t.Fatal("no user in an empty context")
	}
}

func TestDeviceAuthTokenHelpers(t *testing.T) {
	s := newSignInServer(t, "app_tv")
	s.userinfo = func(*http.Request) (int, any) { return 200, map[string]any{"sub": "usr_1"} }
	s.revoke = func(*http.Request, url.Values) (int, any) { return 200, nil }
	d := must[*DeviceAuth](t)(NewDeviceAuth(DeviceAuthConfig{Issuer: s.issuer, ClientID: "app_tv", Scopes: []string{"openid"}}))
	s.refreshes["rt"] = true
	tokens := must[*TokenSet](t)(d.Refresh(ctx, "rt"))
	if tokens.RefreshToken != "rt+" || tokens.Claims.Subject() != "usr_1" {
		t.Fatalf("%+v", tokens)
	}
	if same := must[*TokenSet](t)(d.EnsureFresh(ctx, tokens, 0)); same != tokens {
		t.Fatal("EnsureFresh")
	}
	if info := must[Claims](t)(d.UserInfo(ctx, "at")); info.Subject() != "usr_1" {
		t.Fatal("UserInfo")
	}
	if err := d.Revoke(ctx, "rt+", ""); err != nil {
		t.Fatal(err)
	}
	a := newTestAuth(t, s, WebAppAuthConfig{ClientID: "app_tv"})
	if a.Issuer() != s.issuer || a.ClientID() != "app_tv" {
		t.Fatal("accessors")
	}
	if doc := must[*Discovery](t)(a.Discovery(ctx)); doc.TokenEndpoint != s.issuer+"/oauth/token" || !doc.AuthorizationResponseIssParameterSupported {
		t.Fatalf("discovery %+v", doc)
	}
	idt := s.idToken(t, "app_tv", "n", nil)
	if c, err := a.VerifyIDToken(ctx, idt, "n"); err != nil || c.Subject() != "usr_1" {
		t.Fatal(err)
	}
}

func TestErrorFormatting(t *testing.T) {
	if (&Error{Code: "x"}).Error() != "nine: x" || (&Error{Code: "x", Description: "x"}).Error() != "nine: x" || (&Error{Code: "x", Description: "why"}).Error() != "nine: x: why" {
		t.Fatal("Error()")
	}
	cause := &url.Error{Op: "Get", URL: "https://secret.test/?token=abc", Err: http.ErrHandlerTimeout}
	e := &Error{Code: "request_failed", Description: describeNetworkError(cause), cause: cause}
	if e.Unwrap() != cause || e.Description == "" {
		t.Fatal("cause")
	}
	if got := describeNetworkError(cause); got != http.ErrHandlerTimeout.Error() {
		t.Fatalf("the URL must not leak into the description: %q", got)
	}
	data, _ := json.Marshal(CachedAnswer{Claims: Claims{"sub": "x"}, Until: time.Unix(0, 0).UTC()})
	if string(data) != `{"claims":{"sub":"x"},"until":"1970-01-01T00:00:00Z"}` {
		t.Fatalf("CachedAnswer JSON %s", data)
	}
}

func TestReviewRegressions(t *testing.T) {
	// A pending login without a nonce is refused (the nonce check can't be skipped).
	s := newSignInServer(t, "app_web")
	a := newTestAuth(t, s, WebAppAuthConfig{})
	login := must[*Login](t)(a.CreateLogin(ctx, LoginOptions{}))
	query := s.authorize(t, login.URL)
	noNonce := *login.Pending
	noNonce.Nonce = ""
	_, err := a.HandleCallback(ctx, query, &noNonce)
	wantCode(t, err, "invalid_state", 400)

	// ErrNotFound also matches the Management API's user_not_found.
	if !errors.Is(&Error{Code: "user_not_found", Status: 404}, ErrNotFound) || errors.Is(&Error{Code: "not_found"}, &Error{Code: "user_not_found"}) {
		t.Fatal("ErrNotFound / user_not_found")
	}

	// Numeric adapter ids keep every digit.
	var seen string
	h := AdapterHandler(AdapterConfig{Secret: adapterSecret, Adapter: queryRecorder{&seen}})
	callAdapter(t, h, "POST", "/nine/user", `{"id":12345678901234567891}`, adapterSecret, "r")
	if seen != "12345678901234567891" {
		t.Fatalf("id %q", seen)
	}
	if r := callAdapter(t, h, "POST", "/nine/user", `{"id":"1"} {"id":"2"}`, adapterSecret, "r"); r.status != 400 {
		t.Fatalf("trailing JSON: %d", r.status)
	}

	// Optional auth lets other schemes through; a bearer token must be valid.
	ok := fakeVerifier(func(token string, _ []string) (Claims, error) {
		if token != "good" {
			return nil, invalidToken("bad")
		}
		return Claims{"sub": "u"}, nil
	})
	optional := AuthMiddleware{Verifier: ok, Optional: true}.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	for header, want := range map[string]int{"Basic dXNlcjpwYXNz": 200, "Bearer bad": 401, "Bearer": 401, "bearer good": 200, "Bearergood": 200} {
		if w, _ := serveAuth(t, optional, header); w.Code != want {
			t.Errorf("%q: %d, want %d", header, w.Code, want)
		}
	}
	strict := RequireAuth(ok)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if w, _ := serveAuth(t, strict, "Bearergood"); w.Code != 401 {
		t.Fatal("Bearergood is not a bearer token")
	}

	// DefaultScopes can't be changed from outside.
	DefaultScopes()[0] = "admin"
	if DefaultScopes()[0] != "openid" {
		t.Fatal("DefaultScopes")
	}
}

type queryRecorder struct{ id *string }

func (q queryRecorder) Authenticate(context.Context, Identifier, string) (*AdapterUser, error) {
	return nil, nil
}
func (q queryRecorder) FindUser(_ context.Context, query UserQuery) (*AdapterUser, error) {
	*q.id = query.ID
	return nil, nil
}
func (q queryRecorder) OnEvent(context.Context, *AdapterEvent) error { return nil }

func TestWebAppBehindStripPrefixAndNilBodies(t *testing.T) {
	w := newWebAppSetup(t, WebAppConfig{})
	mux := http.NewServeMux()
	mux.Handle("/app/", http.StripPrefix("/app", w.app.RequireUser(http.NotFoundHandler())))
	r := httptest.NewRequest("GET", appBase+"/app/dashboard?x=1", nil)
	r.Header.Set("Accept", "text/html")
	res := httptest.NewRecorder()
	mux.ServeHTTP(res, r)
	if res.Header().Get("Location") != appBase+"/nine/login?return_to=%2Fapp%2Fdashboard%3Fx%3D1" {
		t.Fatalf("return_to %s", res.Header().Get("Location"))
	}
	u, _ := url.Parse(appBase + "/nine/logout")
	bare := &http.Request{Method: http.MethodPost, URL: u, Header: http.Header{}, Host: "app.acme.test"}
	rec := httptest.NewRecorder()
	w.app.Logout(rec, bare)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("nil body logout %d", rec.Code)
	}
}
