package nine

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeVerifier func(token string, scopes []string) (Claims, error)

func (f fakeVerifier) Verify(_ context.Context, token string, scopes ...string) (Claims, error) {
	return f(token, scopes)
}

func serveAuth(t *testing.T, h http.Handler, header string) (*httptest.ResponseRecorder, map[string]string) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/orders", nil)
	if header != "" {
		r.Header.Set("Authorization", header)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var body map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return w, body
}

func TestRequireAuth(t *testing.T) {
	f := newFakeIssuer(t)
	f.setKeys(asymmetricKeys(t)...)
	v := newTestVerifier(t, f, VerifierConfig{Audience: "https://api.acme.test"})
	var seen Claims
	h := RequireAuth(v, "orders:read")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = ClaimsFrom(r.Context())
		w.WriteHeader(http.StatusTeapot)
	}))

	w, _ := serveAuth(t, h, "Bearer "+makeToken(t, "ES256", nil, claimsFor(f.issuer, nil)))
	if w.Code != http.StatusTeapot || seen.Subject() != "usr_1" {
		t.Fatalf("valid token: %d %v", w.Code, seen)
	}

	for _, header := range []string{"", "Basic abc", "Bearer", "Bearer junk", "Bearer " + makeToken(t, "ES256", nil, claimsFor(f.issuer, map[string]any{"aud": "x"}))} {
		w, body := serveAuth(t, h, header)
		if w.Code != http.StatusUnauthorized || body["error"] != "invalid_token" {
			t.Fatalf("%q: %d %v", header, w.Code, body)
		}
		if !strings.HasPrefix(w.Header().Get("WWW-Authenticate"), `Bearer realm="9in", error="invalid_token"`) {
			t.Fatalf("WWW-Authenticate %q", w.Header().Get("WWW-Authenticate"))
		}
		if w.Header().Get("Content-Type") != "application/json" {
			t.Fatal("content type")
		}
	}

	w, body := serveAuth(t, h, "Bearer "+makeToken(t, "ES256", nil, claimsFor(f.issuer, map[string]any{"scope": "openid"})))
	if w.Code != http.StatusForbidden || body["error"] != "insufficient_scope" || w.Header().Get("WWW-Authenticate") != `Bearer realm="9in", error="insufficient_scope", scope="orders:read"` {
		t.Fatalf("missing scope: %d %v %q", w.Code, body, w.Header().Get("WWW-Authenticate"))
	}
}

func TestRequireAuthAnswers503WhenVerificationItselfFails(t *testing.T) {
	broken := fakeVerifier(func(string, []string) (Claims, error) {
		return nil, newError("jwks_unavailable", "HTTP 500", 500)
	})
	w, body := serveAuth(t, RequireAuth(broken)(http.NotFoundHandler()), "Bearer x")
	if w.Code != http.StatusServiceUnavailable || body["error"] != "temporarily_unavailable" {
		t.Fatalf("%d %v", w.Code, body)
	}
	// Introspection refusing our credentials answers 401 to us, not to the caller.
	misconfigured := fakeVerifier(func(string, []string) (Claims, error) {
		return nil, newError("invalid_client", "", 401)
	})
	w, _ = serveAuth(t, RequireAuth(misconfigured)(http.NotFoundHandler()), "Bearer x")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("invalid_client: %d", w.Code)
	}
	plain := fakeVerifier(func(string, []string) (Claims, error) { return nil, errors.New("boom") })
	w, _ = serveAuth(t, RequireAuth(plain)(http.NotFoundHandler()), "Bearer x")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("plain error: %d", w.Code)
	}
}

func TestAuthMiddlewareOptionalAndCustomErrors(t *testing.T) {
	ok := fakeVerifier(func(token string, scopes []string) (Claims, error) {
		if token != "good" {
			return nil, invalidToken("bad")
		}
		return Claims{"sub": "u", "scope": strings.Join(scopes, " ")}, nil
	})
	var seen Claims
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen = ClaimsFrom(r.Context()) })
	h := AuthMiddleware{Verifier: ok, Optional: true, Scopes: []string{"a b"}}.Wrap(next)
	w, _ := serveAuth(t, h, "")
	if w.Code != 200 || seen != nil {
		t.Fatalf("optional without a token: %d %v", w.Code, seen)
	}
	w, _ = serveAuth(t, h, "Bearer bad")
	if w.Code != 401 {
		t.Fatalf("optional with a bad token: %d", w.Code)
	}
	_, _ = serveAuth(t, h, "Bearer good")
	if seen.String("scope") != "a b" {
		t.Fatalf("scopes passed: %v", seen)
	}
	custom := AuthMiddleware{Verifier: ok, OnError: func(w http.ResponseWriter, r *http.Request, err error) { w.WriteHeader(418) }}.Wrap(next)
	if w, _ := serveAuth(t, custom, "Bearer bad"); w.Code != 418 {
		t.Fatalf("custom: %d", w.Code)
	}
	if ClaimsFrom(context.Background()) != nil {
		t.Fatal("no claims in an empty context")
	}
	if WithClaims(context.Background(), Claims{"sub": "x"}) == nil || ClaimsFrom(WithClaims(context.Background(), Claims{"sub": "x"})).Subject() != "x" {
		t.Fatal("WithClaims")
	}
	if quoteSafe("a\"b\\c\nd") != "abcd" {
		t.Fatal("quoteSafe")
	}
}
