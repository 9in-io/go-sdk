package nine

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Keys and tokens for every algorithm

const testHMACSecret = "an-api-secret-of-at-least-32-bytes-long!"

type testKeySet struct {
	rsa  *rsa.PrivateKey
	p256 *ecdsa.PrivateKey
	p384 *ecdsa.PrivateKey
	ed   ed25519.PrivateKey
}

var (
	testKeysOnce sync.Once
	testKeys     testKeySet
)

func keys(t testing.TB) *testKeySet {
	t.Helper()
	testKeysOnce.Do(func() {
		var err error
		if testKeys.rsa, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		if testKeys.p256, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			panic(err)
		}
		if testKeys.p384, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader); err != nil {
			panic(err)
		}
		if _, testKeys.ed, err = ed25519.GenerateKey(rand.Reader); err != nil {
			panic(err)
		}
	})
	return &testKeys
}

var allAlgorithms = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA", "HS256", "HS384", "HS512"}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// ecPoint returns the uncompressed coordinates of an EC public key (without the
// deprecated X/Y fields).
func ecPoint(pub *ecdsa.PublicKey) (x, y []byte) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(err)
	}
	// The last 2*size+1 bytes of the DER are the uncompressed point.
	size := (pub.Curve.Params().BitSize + 7) / 8
	point := der[len(der)-(2*size+1):]
	return point[1 : 1+size], point[1+size:]
}

// jwkFor is the public JWK for alg's test key, with that alg and kid.
func jwkFor(t testing.TB, alg, kid string) map[string]any {
	k := keys(t)
	jwk := map[string]any{"kid": kid, "alg": alg, "use": "sig"}
	switch {
	case strings.HasPrefix(alg, "RS"), strings.HasPrefix(alg, "PS"):
		jwk["kty"] = "RSA"
		jwk["n"] = b64(k.rsa.N.Bytes())
		jwk["e"] = b64(big.NewInt(int64(k.rsa.E)).Bytes())
	case alg == "ES256":
		x, y := ecPoint(&k.p256.PublicKey)
		jwk["kty"], jwk["crv"], jwk["x"], jwk["y"] = "EC", "P-256", b64(x), b64(y)
	case alg == "ES384":
		x, y := ecPoint(&k.p384.PublicKey)
		jwk["kty"], jwk["crv"], jwk["x"], jwk["y"] = "EC", "P-384", b64(x), b64(y)
	case alg == "EdDSA":
		jwk["kty"], jwk["crv"], jwk["x"] = "OKP", "Ed25519", b64(k.ed.Public().(ed25519.PublicKey))
	default:
		t.Fatalf("no JWK for %s", alg)
	}
	return jwk
}

func hashFor(alg string) crypto.Hash {
	switch alg[len(alg)-3:] {
	case "384":
		return crypto.SHA384
	case "512":
		return crypto.SHA512
	}
	return crypto.SHA256
}

// signRaw signs input with alg's test key (HMAC with testHMACSecret).
func signRaw(t testing.TB, alg, input string) []byte {
	k := keys(t)
	h := hashFor(alg)
	switch {
	case strings.HasPrefix(alg, "RS"):
		sig, err := rsa.SignPKCS1v15(rand.Reader, k.rsa, h, digest(h, []byte(input)))
		if err != nil {
			t.Fatal(err)
		}
		return sig
	case strings.HasPrefix(alg, "PS"):
		sig, err := rsa.SignPSS(rand.Reader, k.rsa, h, digest(h, []byte(input)), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		if err != nil {
			t.Fatal(err)
		}
		return sig
	case alg == "ES256" || alg == "ES384":
		priv, size := k.p256, 32
		if alg == "ES384" {
			priv, size = k.p384, 48
		}
		der, err := ecdsa.SignASN1(rand.Reader, priv, digest(h, []byte(input)))
		if err != nil {
			t.Fatal(err)
		}
		var rs struct{ R, S *big.Int }
		if _, err := asn1.Unmarshal(der, &rs); err != nil {
			t.Fatal(err)
		}
		out := make([]byte, 2*size)
		rs.R.FillBytes(out[:size])
		rs.S.FillBytes(out[size:])
		return out
	case alg == "EdDSA":
		return ed25519.Sign(k.ed, []byte(input))
	case strings.HasPrefix(alg, "HS"):
		mac := hmac.New(hmacAlgorithms[alg], []byte(testHMACSecret))
		mac.Write([]byte(input))
		return mac.Sum(nil)
	}
	t.Fatalf("can't sign %s", alg)
	return nil
}

// makeToken builds a JWT. header entries override the defaults {alg, typ: at+jwt, kid}
// (a nil value removes one).
func makeToken(t testing.TB, alg string, header map[string]any, claims map[string]any) string {
	t.Helper()
	h := map[string]any{"alg": alg, "typ": "at+jwt", "kid": "k-" + alg}
	if strings.HasPrefix(alg, "HS") {
		delete(h, "kid")
	}
	for k, v := range header {
		if v == nil {
			delete(h, k)
		} else {
			h[k] = v
		}
	}
	hj, _ := json.Marshal(h)
	cj, _ := json.Marshal(claims)
	input := b64(hj) + "." + b64(cj)
	if _, known := asymmetricAlgorithms[alg]; !known {
		if _, known := hmacAlgorithms[alg]; !known {
			return input + "."
		}
	}
	return input + "." + b64(signRaw(t, alg, input))
}

// claimsFor are valid access token claims for issuer.
func claimsFor(issuer string, extra map[string]any) map[string]any {
	now := time.Now().Unix()
	c := map[string]any{
		"iss": issuer, "sub": "usr_1", "aud": "https://api.acme.test", "client_id": "app_1",
		"scope": "openid orders:read", "iat": now, "exp": now + 3600, "jti": "jti_1", "sid": "sid_1",
	}
	for k, v := range extra {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return c
}

// ---------------------------------------------------------------------------
// A fake 9in tenant

type fakeIssuer struct {
	*httptest.Server
	t      testing.TB
	issuer string

	mu       sync.Mutex
	jwks     []map[string]any
	counts   map[string]int
	lastForm map[string]url.Values
	lastAuth map[string]string

	// discovery tweaks the discovery document.
	discovery func(doc map[string]any)
	// Handlers for the endpoints; nil answers 404.
	token      func(r *http.Request, form url.Values) (int, any)
	introspect func(r *http.Request, form url.Values) (int, any)
	userinfo   func(r *http.Request) (int, any)
	revoke     func(r *http.Request, form url.Values) (int, any)
	device     func(r *http.Request, form url.Values) (int, any)
	api        func(w http.ResponseWriter, r *http.Request)
}

func newFakeIssuer(t testing.TB) *fakeIssuer {
	f := &fakeIssuer{t: t, counts: map[string]int{}, lastForm: map[string]url.Values{}, lastAuth: map[string]string{}}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	f.issuer = f.URL
	t.Cleanup(f.Close)
	return f
}

// client sends every request to the fake server, whatever its host (for issuers that
// aren't the server's own URL).
func (f *fakeIssuer) client() *http.Client {
	target, _ := url.Parse(f.URL)
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		r = r.Clone(r.Context())
		r.URL.Scheme, r.URL.Host = target.Scheme, target.Host
		return http.DefaultTransport.RoundTrip(r)
	})}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func (f *fakeIssuer) setKeys(keys ...map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.jwks = keys
}

func (f *fakeIssuer) count(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.counts[path]
}

func (f *fakeIssuer) form(path string) url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastForm[path]
}

func (f *fakeIssuer) authorization(path string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastAuth[path]
}

func (f *fakeIssuer) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.counts[r.URL.Path]++
	f.lastAuth[r.URL.Path] = r.Header.Get("Authorization")
	f.mu.Unlock()
	reply := func(status int, body any) {
		if status == 0 {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}
	form := func() url.Values {
		_ = r.ParseForm()
		f.mu.Lock()
		f.lastForm[r.URL.Path] = r.PostForm
		f.mu.Unlock()
		return r.PostForm
	}
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		doc := map[string]any{
			"issuer":                        f.issuer,
			"authorization_endpoint":        f.issuer + "/oauth/authorize",
			"token_endpoint":                f.issuer + "/oauth/token",
			"userinfo_endpoint":             f.issuer + "/oauth/userinfo",
			"jwks_uri":                      f.issuer + "/.well-known/jwks.json",
			"revocation_endpoint":           f.issuer + "/oauth/revoke",
			"introspection_endpoint":        f.issuer + "/oauth/introspect",
			"end_session_endpoint":          f.issuer + "/oauth/logout",
			"device_authorization_endpoint": f.issuer + "/oauth/device/authorize",
			"authorization_response_iss_parameter_supported": true,
		}
		if f.discovery != nil {
			f.discovery(doc)
		}
		reply(200, doc)
	case "/.well-known/jwks.json":
		f.mu.Lock()
		keys := f.jwks
		f.mu.Unlock()
		if keys == nil {
			keys = []map[string]any{}
		}
		reply(200, map[string]any{"keys": keys})
	case "/oauth/token":
		if f.token == nil {
			reply(0, nil)
			return
		}
		reply(f.token(r, form()))
	case "/oauth/introspect":
		if f.introspect == nil {
			reply(0, nil)
			return
		}
		reply(f.introspect(r, form()))
	case "/oauth/userinfo":
		if f.userinfo == nil {
			reply(0, nil)
			return
		}
		reply(f.userinfo(r))
	case "/oauth/revoke":
		if f.revoke == nil {
			reply(0, nil)
			return
		}
		reply(f.revoke(r, form()))
	case "/oauth/device/authorize":
		if f.device == nil {
			reply(0, nil)
			return
		}
		reply(f.device(r, form()))
	default:
		if f.api != nil && strings.HasPrefix(r.URL.Path, "/api/v1/") {
			f.api(w, r)
			return
		}
		reply(0, nil)
	}
}

// idToken signs an ID token (typ JWT) for client with the ES256 test key.
func (f *fakeIssuer) idToken(t testing.TB, client, nonce string, extra map[string]any) string {
	now := time.Now().Unix()
	claims := map[string]any{"iss": f.issuer, "sub": "usr_1", "aud": client, "iat": now, "exp": now + 3600, "email": "jane@acme.test", "name": "Jane", "sid": "sid_1", "auth_time": now}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	for k, v := range extra {
		if v == nil {
			delete(claims, k)
		} else {
			claims[k] = v
		}
	}
	return makeToken(t, "ES256", map[string]any{"typ": "JWT"}, claims)
}

// ---------------------------------------------------------------------------
// Assertions

func wantCode(t testing.TB, err error, code string, status int) *Error {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("want *nine.Error %s, got %v", code, err)
	}
	if e.Code != code {
		t.Fatalf("want code %s, got %s (%v)", code, e.Code, err)
	}
	if status >= 0 && e.Status != status {
		t.Fatalf("want status %d for %s, got %d", status, code, e.Status)
	}
	return e
}

func wantDescription(t testing.TB, err error, part string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), part) {
		t.Fatalf("want an error containing %q, got %v", part, err)
	}
}

func must[T any](t testing.TB) func(T, error) T {
	return func(v T, err error) T {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
}

// clock is a settable time source for tests.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Now()} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}
