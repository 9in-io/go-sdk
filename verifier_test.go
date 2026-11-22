package nine

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

var ctx = context.Background()

// asymmetricKeys publishes the test key for every asymmetric algorithm.
func asymmetricKeys(t testing.TB) []map[string]any {
	var out []map[string]any
	for _, alg := range allAlgorithms {
		if !strings.HasPrefix(alg, "HS") {
			out = append(out, jwkFor(t, alg, "k-"+alg))
		}
	}
	return out
}

func newTestVerifier(t testing.TB, f *fakeIssuer, cfg VerifierConfig) *Verifier {
	t.Helper()
	cfg.Issuer = f.issuer
	return must[*Verifier](t)(NewVerifier(cfg))
}

func TestVerifiesEveryAlgorithm(t *testing.T) {
	f := newFakeIssuer(t)
	f.setKeys(asymmetricKeys(t)...)
	v := newTestVerifier(t, f, VerifierConfig{Audience: "https://api.acme.test", Secret: testHMACSecret})
	for _, alg := range allAlgorithms {
		t.Run(alg, func(t *testing.T) {
			token := makeToken(t, alg, nil, claimsFor(f.issuer, map[string]any{"sub": "usr_" + alg}))
			claims, err := v.Verify(ctx, token, "orders:read")
			if err != nil {
				t.Fatal(err)
			}
			if claims.Subject() != "usr_"+alg || claims.ClientID() != "app_1" || claims.SessionID() != "sid_1" || claims.TokenID() != "jti_1" {
				t.Fatalf("claims %v", claims)
			}
		})
	}
	if n := f.count("/.well-known/jwks.json"); n != 1 {
		t.Fatalf("JWKS fetched %d times, want 1 (cached)", n)
	}
}

type vectors struct {
	Issuer     string            `json:"issuer"`
	HMACSecret string            `json:"hmacSecret"`
	JWKS       json.RawMessage   `json:"jwks"`
	Tokens     map[string]string `json:"tokens"`
	Invalid    map[string]string `json:"invalid"`
}

func loadVectors(t testing.TB) (*vectors, []map[string]any) {
	data, err := os.ReadFile("testdata/jws-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(v.JWKS, &jwks); err != nil {
		t.Fatal(err)
	}
	return &v, jwks.Keys
}

// vectorVerifier serves the WebCrypto vectors' keys from a fake server standing in for
// their issuer, https://vectors.9in.test.
func vectorVerifier(t *testing.T, keys []map[string]any, cfg VerifierConfig) (*Verifier, *fakeIssuer) {
	vec, _ := loadVectors(t)
	f := newFakeIssuer(t)
	f.setKeys(keys...)
	f.issuer = vec.Issuer
	cfg.Issuer = vec.Issuer
	cfg.HTTPClient = f.client()
	return must[*Verifier](t)(NewVerifier(cfg)), f
}

// Tokens signed by WebCrypto (as @9in-io/sdk and the 9in server do), shared with the PHP SDK.
func TestVerifiesTheWebCryptoVectors(t *testing.T) {
	vec, keys := loadVectors(t)
	v, _ := vectorVerifier(t, keys, VerifierConfig{Audience: "https://api.acme.test", Secret: vec.HMACSecret})
	if len(vec.Tokens) != len(allAlgorithms) {
		t.Fatalf("vectors for %d algorithms", len(vec.Tokens))
	}
	for _, alg := range allAlgorithms {
		claims, err := v.Verify(ctx, vec.Tokens[alg], "orders:read")
		if err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		if claims.Subject() != "usr_1" || claims.TokenID() != "jti_1" {
			t.Fatalf("%s: claims %v", alg, claims)
		}
	}
}

func TestTamperedVectorsFailForEveryAlgorithm(t *testing.T) {
	vec, keys := loadVectors(t)
	v, _ := vectorVerifier(t, keys, VerifierConfig{Secret: vec.HMACSecret})
	for alg, token := range vec.Tokens {
		parts := strings.Split(token, ".")
		payload, _ := decodeSegment(parts[1])
		var claims map[string]any
		_ = json.Unmarshal(payload, &claims)
		claims["sub"] = "usr_admin"
		tampered, _ := json.Marshal(claims)
		parts[1] = b64(tampered)
		_, err := v.Verify(ctx, strings.Join(parts, "."))
		wantCode(t, err, "invalid_token", 401)
		wantDescription(t, err, "bad signature")
		// A flipped signature byte fails too.
		parts = strings.Split(token, ".")
		sig, _ := decodeSegment(parts[2])
		sig[len(sig)/2] ^= 0x01
		parts[2] = b64(sig)
		_, err = v.Verify(ctx, strings.Join(parts, "."))
		if err == nil {
			t.Fatalf("%s: flipped signature accepted", alg)
		}
	}
}

func TestRSAPSSRequiresTheJWSSaltLength(t *testing.T) {
	vec, keys := loadVectors(t)
	v, _ := vectorVerifier(t, keys, VerifierConfig{})
	_, err := v.Verify(ctx, vec.Invalid["PS256 salt length 0"])
	wantDescription(t, err, "bad signature")
}

func TestRejectsIDTokensAsAccessTokens(t *testing.T) {
	vec, keys := loadVectors(t)
	v, _ := vectorVerifier(t, keys, VerifierConfig{})
	_, err := v.Verify(ctx, vec.Invalid["ES256 ID token (typ JWT)"])
	wantCode(t, err, "invalid_token", 401)
	wantDescription(t, err, "not an access token")
}

func TestTokenTypeChecks(t *testing.T) {
	f := newFakeIssuer(t)
	f.setKeys(asymmetricKeys(t)...)
	v := newTestVerifier(t, f, VerifierConfig{})
	for _, typ := range []any{"JWT", "", nil, 42, "at+jwt+x"} {
		_, err := v.Verify(ctx, makeToken(t, "ES256", map[string]any{"typ": typ}, claimsFor(f.issuer, nil)))
		wantDescription(t, err, "not an access token")
	}
	for _, typ := range []string{"Application/AT+JWT", "AT+JWT", "application/at+jwt"} {
		if _, err := v.Verify(ctx, makeToken(t, "ES256", map[string]any{"typ": typ}, claimsFor(f.issuer, nil))); err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
	}
}

func TestTheKeyDecidesTheAlgorithm(t *testing.T) {
	f := newFakeIssuer(t)
	// The JWKS says RS256, the token says PS256 (same RSA key).
	rs := jwkFor(t, "RS256", "k-PS256")
	f.setKeys(rs)
	v := newTestVerifier(t, f, VerifierConfig{})
	_, err := v.Verify(ctx, makeToken(t, "PS256", nil, claimsFor(f.issuer, nil)))
	wantDescription(t, err, "does not match the key")

	// A key without alg must still fit: an ES256 header pointing at an RSA key…
	noAlg := jwkFor(t, "RS256", "k-ES256")
	delete(noAlg, "alg")
	f.setKeys(noAlg)
	v = newTestVerifier(t, f, VerifierConfig{})
	_, err = v.Verify(ctx, makeToken(t, "ES256", nil, claimsFor(f.issuer, nil)))
	wantDescription(t, err, "does not match the key")

	// …or an ES384 header pointing at a P-256 key, or EdDSA at an EC key.
	p256 := jwkFor(t, "ES256", "k-ES384")
	delete(p256, "alg")
	ec := jwkFor(t, "ES256", "k-EdDSA")
	delete(ec, "alg")
	f.setKeys(p256, ec)
	v = newTestVerifier(t, f, VerifierConfig{})
	_, err = v.Verify(ctx, makeToken(t, "ES384", nil, claimsFor(f.issuer, nil)))
	wantDescription(t, err, "does not match the key")
	_, err = v.Verify(ctx, makeToken(t, "EdDSA", nil, claimsFor(f.issuer, nil)))
	wantDescription(t, err, "does not match the key")

	// Without alg, a fitting key works.
	ok := jwkFor(t, "ES256", "k-ES256")
	delete(ok, "alg")
	f.setKeys(ok)
	v = newTestVerifier(t, f, VerifierConfig{})
	if _, err := v.Verify(ctx, makeToken(t, "ES256", nil, claimsFor(f.issuer, nil))); err != nil {
		t.Fatal(err)
	}
}

func TestRejectsAlgNoneAndUnknownAlgorithms(t *testing.T) {
	f := newFakeIssuer(t)
	f.setKeys(asymmetricKeys(t)...)
	v := newTestVerifier(t, f, VerifierConfig{Secret: testHMACSecret})
	for _, alg := range []string{"none", "None", "HS1", "RS1", "ES512", "", "EdDSA25519"} {
		_, err := v.Verify(ctx, makeToken(t, alg, map[string]any{"kid": "k-RS256"}, claimsFor(f.issuer, nil)))
		wantCode(t, err, "invalid_token", 401)
		wantDescription(t, err, "unsupported algorithm")
	}
	// alg missing altogether.
	_, err := v.Verify(ctx, makeToken(t, "none", map[string]any{"alg": nil}, claimsFor(f.issuer, nil)))
	wantDescription(t, err, "unsupported algorithm")
}

func TestHMACTokensNeedTheRightSecret(t *testing.T) {
	f := newFakeIssuer(t)
	token := makeToken(t, "HS256", nil, claimsFor(f.issuer, nil))
	_, err := newTestVerifier(t, f, VerifierConfig{}).Verify(ctx, token)
	wantDescription(t, err, "pass the API's secret")
	_, err = newTestVerifier(t, f, VerifierConfig{Secret: testHMACSecret + "x"}).Verify(ctx, token)
	wantDescription(t, err, "bad signature")
	for _, alg := range []string{"HS256", "HS384", "HS512"} {
		if _, err := newTestVerifier(t, f, VerifierConfig{Secret: testHMACSecret}).Verify(ctx, makeToken(t, alg, nil, claimsFor(f.issuer, nil))); err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
	}
	// HMAC tokens never touch the JWKS.
	if f.count("/.well-known/jwks.json") != 0 {
		t.Fatal("JWKS fetched for an HMAC token")
	}
}

func TestClaimChecks(t *testing.T) {
	f := newFakeIssuer(t)
	f.setKeys(asymmetricKeys(t)...)
	v := newTestVerifier(t, f, VerifierConfig{Audience: "https://api.acme.test"})
	now := time.Now().Unix()
	cases := []struct {
		name   string
		claims map[string]any
		want   string
	}{
		{"expired", map[string]any{"exp": now - 31}, "token expired"},
		{"no exp", map[string]any{"exp": nil}, "token expired"},
		{"exp not a number", map[string]any{"exp": "tomorrow"}, "token expired"},
		{"not yet valid", map[string]any{"nbf": now + 31}, "not yet valid"},
		{"other issuer", map[string]any{"iss": "https://evil.9in.io"}, "issuer mismatch"},
		{"no issuer", map[string]any{"iss": nil}, "issuer mismatch"},
		{"other audience", map[string]any{"aud": "https://other.acme.test"}, "audience mismatch"},
		{"no audience", map[string]any{"aud": nil}, "audience mismatch"},
	}
	for _, c := range cases {
		_, err := v.Verify(ctx, makeToken(t, "ES256", nil, claimsFor(f.issuer, c.claims)))
		wantCode(t, err, "invalid_token", 401)
		wantDescription(t, err, c.want)
		if !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("%s: errors.Is(ErrInvalidToken) false", c.name)
		}
	}
	// Within the leeway (30 s), and an issuer with a trailing slash, pass.
	for _, extra := range []map[string]any{
		{"exp": now - 20},
		{"nbf": now + 20},
		{"iss": f.issuer + "/"},
		{"aud": []any{"https://other.acme.test", "https://api.acme.test"}},
	} {
		if _, err := v.Verify(ctx, makeToken(t, "ES256", nil, claimsFor(f.issuer, extra))); err != nil {
			t.Fatalf("%v: %v", extra, err)
		}
	}
	// Several accepted audiences; none configured accepts any.
	multi := newTestVerifier(t, f, VerifierConfig{Audience: "https://a.test", Audiences: []string{"https://api.acme.test"}})
	if _, err := multi.Verify(ctx, makeToken(t, "ES256", nil, claimsFor(f.issuer, nil))); err != nil {
		t.Fatal(err)
	}
	anyAud := newTestVerifier(t, f, VerifierConfig{})
	if _, err := anyAud.Verify(ctx, makeToken(t, "ES256", nil, claimsFor(f.issuer, map[string]any{"aud": "whatever"}))); err != nil {
		t.Fatal(err)
	}
	// A custom leeway.
	strict := newTestVerifier(t, f, VerifierConfig{Leeway: time.Second})
	_, err := strict.Verify(ctx, makeToken(t, "ES256", nil, claimsFor(f.issuer, map[string]any{"exp": now - 10})))
	wantDescription(t, err, "token expired")
}

func TestScopeChecks(t *testing.T) {
	f := newFakeIssuer(t)
	f.setKeys(asymmetricKeys(t)...)
	v := newTestVerifier(t, f, VerifierConfig{})
	token := makeToken(t, "EdDSA", nil, claimsFor(f.issuer, map[string]any{"scope": "openid orders:read orders:write"}))
	for _, scopes := range [][]string{nil, {"orders:read"}, {"orders:read orders:write"}, {"orders:read", "orders:write"}, {" orders:write "}} {
		if _, err := v.Verify(ctx, token, scopes...); err != nil {
			t.Fatalf("%v: %v", scopes, err)
		}
	}
	_, err := v.Verify(ctx, token, "orders:read", "orders:delete admin")
	e := wantCode(t, err, "insufficient_scope", 403)
	if e.Description != "missing orders:delete, admin" {
		t.Fatalf("description %q", e.Description)
	}
	if !errors.Is(err, ErrInsufficientScope) {
		t.Fatal("errors.Is(ErrInsufficientScope) false")
	}
	// No scope claim at all.
	_, err = v.Verify(ctx, makeToken(t, "EdDSA", nil, claimsFor(f.issuer, map[string]any{"scope": nil})), "orders:read")
	wantCode(t, err, "insufficient_scope", 403)
}

func TestMalformedAndMissingTokens(t *testing.T) {
	f := newFakeIssuer(t)
	f.setKeys(asymmetricKeys(t)...)
	v := newTestVerifier(t, f, VerifierConfig{})
	_, err := v.Verify(ctx, "")
	wantDescription(t, err, "missing token")
	_, err = v.Verify(ctx, "Bearer   ")
	wantDescription(t, err, "missing token")
	good := makeToken(t, "ES256", nil, claimsFor(f.issuer, nil))
	parts := strings.Split(good, ".")
	for _, bad := range []string{
		"abc", "a.b", "a.b.c.d", parts[0] + "." + parts[1], "!!!." + parts[1] + "." + parts[2],
		b64([]byte("not json")) + "." + parts[1] + "." + parts[2],
		b64([]byte(`[1,2]`)) + "." + parts[1] + "." + parts[2],
		parts[0] + "." + b64([]byte("null")) + "." + parts[2],
		parts[0] + "." + b64([]byte(`{"a":1} trailing`)) + "." + parts[2],
		strings.Repeat("a", maxTokenLength+1),
	} {
		_, err := v.Verify(ctx, bad)
		wantCode(t, err, "invalid_token", 401)
	}
	// Bearer prefixes in any case, and surrounding spaces, are fine.
	for _, header := range []string{"Bearer " + good, "bearer " + good, "BEARER  " + good + " ", good} {
		if _, err := v.Verify(ctx, header); err != nil {
			t.Fatalf("%q: %v", header[:8], err)
		}
	}
	// A critical header we don't understand is refused.
	_, err = v.Verify(ctx, makeToken(t, "ES256", map[string]any{"crit": []string{"exp"}}, claimsFor(f.issuer, nil)))
	wantDescription(t, err, "critical")
}

func TestUnknownKidIsRefetchedOnceThenThrottled(t *testing.T) {
	f := newFakeIssuer(t)
	f.setKeys(jwkFor(t, "ES256", "old"))
	v := newTestVerifier(t, f, VerifierConfig{})
	c := newClock()
	v.now = c.Now

	if _, err := v.Verify(ctx, makeToken(t, "ES256", map[string]any{"kid": "old"}, claimsFor(f.issuer, nil))); err != nil {
		t.Fatal(err)
	}
	if f.count("/.well-known/jwks.json") != 1 {
		t.Fatal("first fetch")
	}
	// Key rotation: a token with the new kid triggers one refetch, then verifies.
	f.setKeys(jwkFor(t, "ES256", "old"), jwkFor(t, "ES256", "new"))
	c.Advance(10 * time.Second)
	if _, err := v.Verify(ctx, makeToken(t, "ES256", map[string]any{"kid": "new"}, claimsFor(f.issuer, nil))); err != nil {
		t.Fatal(err)
	}
	if n := f.count("/.well-known/jwks.json"); n != 2 {
		t.Fatalf("refetch: %d", n)
	}
	// A junk kid: one refetch, then ignored for a minute.
	c.Advance(10 * time.Second)
	junk := makeToken(t, "ES256", map[string]any{"kid": "junk"}, claimsFor(f.issuer, nil))
	_, err := v.Verify(ctx, junk)
	wantDescription(t, err, "unknown signing key")
	if n := f.count("/.well-known/jwks.json"); n != 3 {
		t.Fatalf("junk refetch: %d", n)
	}
	for i := 0; i < 5; i++ {
		c.Advance(5 * time.Second)
		_, err = v.Verify(ctx, junk)
		wantDescription(t, err, "unknown signing key")
	}
	if n := f.count("/.well-known/jwks.json"); n != 3 {
		t.Fatalf("throttled junk kid fetched again: %d", n)
	}
	c.Advance(time.Minute)
	_, _ = v.Verify(ctx, junk)
	if n := f.count("/.well-known/jwks.json"); n != 4 {
		t.Fatalf("after the throttle: %d", n)
	}
	// Random kids can't force more than one refetch every few seconds.
	for i := 0; i < 20; i++ {
		_, _ = v.Verify(ctx, makeToken(t, "ES256", map[string]any{"kid": "random-" + string(rune('a'+i))}, claimsFor(f.issuer, nil)))
	}
	if n := f.count("/.well-known/jwks.json"); n != 4 {
		t.Fatalf("random kids forced refetches: %d", n)
	}
	// A token without a kid matches only a key without one.
	_, err = v.Verify(ctx, makeToken(t, "ES256", map[string]any{"kid": nil}, claimsFor(f.issuer, nil)))
	wantDescription(t, err, "unknown signing key")
	_, err = v.Verify(ctx, makeToken(t, "ES256", map[string]any{"kid": 7}, claimsFor(f.issuer, nil)))
	wantDescription(t, err, "unknown signing key")
}

func TestJWKSIsCachedForTenMinutes(t *testing.T) {
	f := newFakeIssuer(t)
	f.setKeys(asymmetricKeys(t)...)
	v := newTestVerifier(t, f, VerifierConfig{})
	c := newClock()
	v.now = c.Now
	token := makeToken(t, "RS256", nil, claimsFor(f.issuer, nil))
	for i := 0; i < 4; i++ {
		if _, err := v.Verify(ctx, token); err != nil {
			t.Fatal(err)
		}
		c.Advance(4 * time.Minute)
	}
	if n := f.count("/.well-known/jwks.json"); n != 2 {
		t.Fatalf("JWKS fetched %d times over 12 minutes, want 2", n)
	}
	if n := f.count("/.well-known/openid-configuration"); n != 1 {
		t.Fatalf("discovery fetched %d times, want 1", n)
	}
}

func TestKeysThatCantBeUsed(t *testing.T) {
	f := newFakeIssuer(t)
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	weak := map[string]any{"kty": "RSA", "kid": "weak", "alg": "RS256", "n": b64(small.N.Bytes()), "e": b64(big.NewInt(int64(small.E)).Bytes())}
	offCurve := jwkFor(t, "ES256", "off")
	x, _ := decodeSegment(offCurve["x"].(string))
	x[0] ^= 0xff
	offCurve["x"] = b64(x)
	encryption := jwkFor(t, "ES256", "enc")
	encryption["use"] = "enc"
	f.setKeys(weak, offCurve, encryption)
	v := newTestVerifier(t, f, VerifierConfig{})
	_, err = v.Verify(ctx, makeToken(t, "RS256", map[string]any{"kid": "weak"}, claimsFor(f.issuer, nil)))
	wantDescription(t, err, "unusable signing key")
	_, err = v.Verify(ctx, makeToken(t, "ES256", map[string]any{"kid": "off"}, claimsFor(f.issuer, nil)))
	wantDescription(t, err, "unusable signing key")
	_, err = v.Verify(ctx, makeToken(t, "ES256", map[string]any{"kid": "enc"}, claimsFor(f.issuer, nil)))
	wantDescription(t, err, "unknown signing key")
}

func TestJWKSAndDiscoveryFailures(t *testing.T) {
	f := newFakeIssuer(t)
	f.discovery = func(doc map[string]any) { doc["jwks_uri"] = f.issuer + "/missing-jwks" }
	v := newTestVerifier(t, f, VerifierConfig{})
	_, err := v.Verify(ctx, makeToken(t, "ES256", nil, claimsFor(f.issuer, nil)))
	wantCode(t, err, "jwks_unavailable", 404)
	if errors.Is(err, ErrInvalidToken) {
		t.Fatal("a JWKS failure is not an invalid token")
	}

	// Discovery for another issuer is refused (OpenID Connect Discovery §4.3).
	g := newFakeIssuer(t)
	g.discovery = func(doc map[string]any) { doc["issuer"] = "https://evil.9in.io" }
	_, err = newTestVerifier(t, g, VerifierConfig{}).Verify(ctx, makeToken(t, "ES256", nil, claimsFor(g.issuer, nil)))
	wantCode(t, err, "discovery_failed", 0)

	// An unreachable issuer, and failures that are not cached.
	h := newFakeIssuer(t)
	h.Close()
	_, err = newTestVerifier(t, h, VerifierConfig{}).Verify(ctx, makeToken(t, "ES256", nil, claimsFor(h.issuer, nil)))
	wantCode(t, err, "discovery_failed", 0)
}

func TestConcurrentVerification(t *testing.T) {
	f := newFakeIssuer(t)
	f.setKeys(asymmetricKeys(t)...)
	v := newTestVerifier(t, f, VerifierConfig{Secret: testHMACSecret})
	tokens := map[string]string{}
	for _, alg := range allAlgorithms {
		tokens[alg] = makeToken(t, alg, nil, claimsFor(f.issuer, nil))
	}
	var wg sync.WaitGroup
	errs := make(chan error, 200)
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := v.Verify(ctx, tokens[allAlgorithms[i%len(allAlgorithms)]], "orders:read"); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if n := f.count("/.well-known/jwks.json"); n != 1 {
		t.Fatalf("concurrent first use fetched the JWKS %d times, want 1", n)
	}
}

func TestVerifyIDToken(t *testing.T) {
	f := newFakeIssuer(t)
	f.setKeys(asymmetricKeys(t)...)
	v := newTestVerifier(t, f, VerifierConfig{})
	for _, alg := range []string{"RS256", "PS384", "ES256", "ES384", "EdDSA"} {
		now := time.Now().Unix()
		token := makeToken(t, alg, map[string]any{"typ": "JWT"}, map[string]any{"iss": f.issuer, "sub": "u", "aud": "app_1", "nonce": "n1", "exp": now + 60, "iat": now})
		claims, err := v.VerifyIDToken(ctx, token, "app_1", "n1")
		if err != nil || claims.Subject() != "u" {
			t.Fatalf("%s: %v", alg, err)
		}
	}
	now := time.Now().Unix()
	base := map[string]any{"iss": f.issuer, "sub": "u", "aud": "app_1", "nonce": "n1", "exp": now + 60}
	with := func(extra map[string]any) map[string]any {
		out := map[string]any{}
		for k, v := range base {
			out[k] = v
		}
		for k, v := range extra {
			if v == nil {
				delete(out, k)
			} else {
				out[k] = v
			}
		}
		return out
	}
	cases := []struct {
		name   string
		token  string
		client string
		nonce  string
		want   string
	}{
		{"wrong nonce", makeToken(t, "ES256", map[string]any{"typ": "JWT"}, base), "app_1", "n2", "nonce mismatch"},
		{"no nonce", makeToken(t, "ES256", map[string]any{"typ": "JWT"}, with(map[string]any{"nonce": nil})), "app_1", "n1", "nonce mismatch"},
		{"wrong audience", makeToken(t, "ES256", map[string]any{"typ": "JWT"}, base), "app_2", "n1", "audience mismatch"},
		{"several audiences, no azp", makeToken(t, "ES256", map[string]any{"typ": "JWT"}, with(map[string]any{"aud": []string{"app_1", "app_2"}})), "app_1", "n1", "authorized party"},
		{"azp of another app", makeToken(t, "ES256", map[string]any{"typ": "JWT"}, with(map[string]any{"azp": "app_2"})), "app_1", "n1", "authorized party"},
		{"expired", makeToken(t, "ES256", map[string]any{"typ": "JWT"}, with(map[string]any{"exp": now - 60})), "app_1", "n1", "expired"},
		{"other issuer", makeToken(t, "ES256", map[string]any{"typ": "JWT"}, with(map[string]any{"iss": "https://evil.test"})), "app_1", "n1", "issuer"},
		{"no subject", makeToken(t, "ES256", map[string]any{"typ": "JWT"}, with(map[string]any{"sub": nil})), "app_1", "n1", "missing subject"},
		{"an access token", makeToken(t, "ES256", nil, base), "app_1", "n1", "not an ID token"},
		{"HMAC-signed", makeToken(t, "HS256", map[string]any{"typ": "JWT"}, base), "app_1", "n1", "unsupported algorithm"},
		{"unknown key", makeToken(t, "ES256", map[string]any{"typ": "JWT", "kid": "nope"}, base), "app_1", "n1", "unknown signing key"},
		{"malformed", "x.y", "app_1", "n1", "malformed"},
		{"empty", "", "app_1", "n1", "missing"},
	}
	for _, c := range cases {
		_, err := v.VerifyIDToken(ctx, c.token, c.client, c.nonce)
		wantCode(t, err, "invalid_id_token", 401)
		wantDescription(t, err, c.want)
	}
	// azp equal to the client with several audiences passes; an empty expected nonce skips the check.
	if _, err := v.VerifyIDToken(ctx, makeToken(t, "ES256", map[string]any{"typ": "JWT"}, with(map[string]any{"aud": []string{"app_1", "app_2"}, "azp": "app_1"})), "app_1", "n1"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.VerifyIDToken(ctx, makeToken(t, "ES256", map[string]any{"typ": "JWT"}, base), "app_1", ""); err != nil {
		t.Fatal(err)
	}
}

func TestClaimsHelpers(t *testing.T) {
	c := Claims{"sub": "app_1", "client_id": "app_1", "aud": []any{"a", "b", 3}, "scope": "x y", "exp": float64(1700000000), "email_verified": true, "n": json.Number("12")}
	if !c.IsMachine() || c.Audience()[1] != "b" || len(c.Audience()) != 2 || !c.HasScope("y") || c.HasScope("z") {
		t.Fatalf("helpers: %v", c)
	}
	if c.ExpiresAt().Unix() != 1700000000 || !c.Bool("email_verified") || c.String("missing") != "" {
		t.Fatal("time/bool/string")
	}
	if n, ok := c.Int("n"); !ok || n != 12 {
		t.Fatal("json.Number")
	}
	if _, ok := c.Int("scope"); ok {
		t.Fatal("a string is not a number")
	}
	if (Claims{"sub": "usr_1", "client_id": "app_1", "sid": "s"}).IsMachine() {
		t.Fatal("a user token is not a machine token")
	}
}
