package nine

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// AccessTokenVerifier verifies bearer tokens. [*Verifier] implements it; so can a fake
// in your tests.
type AccessTokenVerifier interface {
	Verify(ctx context.Context, token string, scopes ...string) (Claims, error)
}

type claimsKey struct{}

// ClaimsFrom returns the access token claims [RequireAuth] put in the request context,
// or nil.
func ClaimsFrom(ctx context.Context) Claims {
	c, _ := ctx.Value(claimsKey{}).(Claims)
	return c
}

// WithClaims returns a copy of ctx carrying claims (what [RequireAuth] does; handy in tests).
func WithClaims(ctx context.Context, claims Claims) context.Context {
	return context.WithValue(ctx, claimsKey{}, claims)
}

// RequireAuth is net/http middleware for your API: it verifies the
// "Authorization: Bearer …" access token with v, requires every scope given (each
// argument may hold several, space-separated), and puts the claims in the request
// context ([ClaimsFrom]).
//
// A missing or bad token gets 401 invalid_token, a missing scope 403 insufficient_scope,
// both as JSON with a WWW-Authenticate header (RFC 6750). When verification itself fails
// (9in unreachable, introspection refused) the answer is 503: that is your server's
// problem, not the caller's. Use [AuthMiddleware] to change these answers or to let
// requests without a token through.
func RequireAuth(v AccessTokenVerifier, scopes ...string) func(http.Handler) http.Handler {
	return AuthMiddleware{Verifier: v, Scopes: scopes}.Wrap
}

// AuthMiddleware is [RequireAuth] with more choices.
type AuthMiddleware struct {
	// Verifier checks the tokens (required).
	Verifier AccessTokenVerifier
	// Scopes must all be granted.
	Scopes []string
	// Optional lets requests without a bearer token through, without claims. A bearer
	// token that is present must still be valid.
	Optional bool
	// OnError writes the answer when verification fails. Default: 401, 403 or 503 JSON.
	OnError func(w http.ResponseWriter, r *http.Request, err error)
}

// Wrap returns next behind the middleware.
func (m AuthMiddleware) Wrap(next http.Handler) http.Handler {
	if m.Verifier == nil {
		panic("nine: AuthMiddleware needs a Verifier")
	}
	onError := m.OnError
	if onError == nil {
		onError = func(w http.ResponseWriter, r *http.Request, err error) { WriteAuthError(w, err, m.Scopes...) }
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		scheme, rest, _ := strings.Cut(strings.TrimSpace(header), " ")
		isBearer := strings.EqualFold(scheme, "bearer")
		token := ""
		if isBearer {
			token = strings.TrimSpace(rest)
		}
		if m.Optional && !isBearer {
			// No bearer token (no header, or another scheme): through, without claims.
			next.ServeHTTP(w, r)
			return
		}
		if token == "" {
			onError(w, r, invalidToken("missing bearer token"))
			return
		}
		claims, err := m.Verifier.Verify(r.Context(), token, m.Scopes...)
		if err != nil {
			onError(w, r, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(WithClaims(r.Context(), claims)))
	})
}

// WriteAuthError writes the answer for a failed token check: 401 invalid_token, 403
// insufficient_scope (naming the required scopes), or 503 for anything else, as JSON
// with a WWW-Authenticate header.
func WriteAuthError(w http.ResponseWriter, err error, scopes ...string) {
	status := http.StatusServiceUnavailable
	body := map[string]string{"error": "temporarily_unavailable", "error_description": "the access token could not be checked"}
	var e *Error
	if errors.As(err, &e) {
		switch e.Code {
		case "invalid_token":
			status = http.StatusUnauthorized
			body = map[string]string{"error": e.Code, "error_description": e.Description}
			w.Header().Set("WWW-Authenticate", `Bearer realm="9in", error="invalid_token", error_description="`+quoteSafe(e.Description)+`"`)
		case "insufficient_scope":
			status = http.StatusForbidden
			body = map[string]string{"error": e.Code, "error_description": e.Description}
			w.Header().Set("WWW-Authenticate", `Bearer realm="9in", error="insufficient_scope", scope="`+quoteSafe(strings.Join(splitScopes(scopes), " "))+`"`)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// quoteSafe keeps a value usable inside a quoted header parameter.
func quoteSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '"' || r == '\\' || r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}
