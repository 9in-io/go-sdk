package nine

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// introspectFrom answers introspection from a map of token → active claims; unknown
// tokens are inactive. It checks the client authenticates with HTTP Basic.
func introspectFrom(t testing.TB, active *sync.Map) func(r *http.Request, form url.Values) (int, any) {
	return func(r *http.Request, form url.Values) (int, any) {
		if r.Header.Get("Authorization") != basicAuth("app_server", "s3cret:with/chars") {
			return 401, map[string]any{"error": "invalid_client"}
		}
		if claims, ok := active.Load(form.Get("token")); ok {
			return 200, claims
		}
		return 200, map[string]any{"active": false}
	}
}

func hybridSetup(t *testing.T, mode Mode) (*Verifier, *fakeIssuer, *sync.Map, *clock) {
	f := newFakeIssuer(t)
	f.setKeys(asymmetricKeys(t)...)
	active := &sync.Map{}
	handler := introspectFrom(t, active)
	f.introspect = handler
	v := newTestVerifier(t, f, VerifierConfig{Audience: "https://api.acme.test", Mode: mode, ClientID: "app_server", ClientSecret: "s3cret:with/chars"})
	c := newClock()
	v.now = c.Now
	if m, ok := v.answers.(*MemoryAnswerCache); ok {
		m.now = c.Now
	}
	return v, f, active, c
}

func activeClaims(issuer string, extra map[string]any) map[string]any {
	c := claimsFor(issuer, extra)
	c["active"] = true
	c["token_type"] = "access_token"
	return c
}

func TestModeDefaults(t *testing.T) {
	f := newFakeIssuer(t)
	if m := newTestVerifier(t, f, VerifierConfig{}).Mode(); m != ModeLocal {
		t.Fatalf("no credentials: %s", m)
	}
	if m := newTestVerifier(t, f, VerifierConfig{ClientID: "a", ClientSecret: "b"}).Mode(); m != ModeHybrid {
		t.Fatalf("credentials: %s", m)
	}
	if m := newTestVerifier(t, f, VerifierConfig{ClientID: "a", ClientSecret: "b", Mode: ModeLocal}).Mode(); m != ModeLocal {
		t.Fatalf("explicit local: %s", m)
	}
	for _, mode := range []Mode{ModeHybrid, ModeIntrospect} {
		_, err := NewVerifier(VerifierConfig{Issuer: f.issuer, Mode: mode, ClientID: "a"})
		wantCode(t, err, "invalid_options", 0)
	}
}

func TestHybridIntrospectsOncePerTokenAndCaches(t *testing.T) {
	v, f, active, _ := hybridSetup(t, ModeHybrid)
	token := makeToken(t, "ES256", nil, claimsFor(f.issuer, nil))
	active.Store(token, activeClaims(f.issuer, nil))
	for i := 0; i < 5; i++ {
		claims, err := v.Verify(ctx, token, "orders:read")
		if err != nil {
			t.Fatal(err)
		}
		if claims.Subject() != "usr_1" {
			t.Fatal(claims)
		}
	}
	if n := f.count("/oauth/introspect"); n != 1 {
		t.Fatalf("introspected %d times, want 1", n)
	}
	if got := f.form("/oauth/introspect").Get("token"); got != token {
		t.Fatal("introspected another token")
	}
	// A scope check still happens locally on cached tokens.
	_, err := v.Verify(ctx, token, "orders:delete")
	wantCode(t, err, "insufficient_scope", 403)
}

func TestHybridRevocationWebhooksEvict(t *testing.T) {
	v, f, active, _ := hybridSetup(t, ModeHybrid)
	mk := func(sub, sid, jti string) string {
		token := makeToken(t, "ES256", nil, claimsFor(f.issuer, map[string]any{"sub": sub, "sid": sid, "jti": jti}))
		active.Store(token, activeClaims(f.issuer, map[string]any{"sub": sub, "sid": sid, "jti": jti}))
		if _, err := v.Verify(ctx, token); err != nil {
			t.Fatal(err)
		}
		return token
	}
	a := mk("usr_a", "sid_a", "jti_a")
	b := mk("usr_b", "sid_b", "jti_b")
	c := mk("usr_c", "sid_c", "jti_c")
	d := mk("usr_c", "sid_d", "jti_d")
	if n := f.count("/oauth/introspect"); n != 4 {
		t.Fatalf("%d", n)
	}
	event := func(typ string, data map[string]any) *WebhookEvent {
		return &WebhookEvent{ID: "evt", EventType: typ, Data: data}
	}
	// Events that don't concern cached tokens evict nothing.
	for _, e := range []*WebhookEvent{
		event("token.revoked", map[string]any{"token_type": "refresh_token", "jti": "jti_a"}),
		event("token.revoked", map[string]any{"token_type": "access_token"}),
		event("user.login", map[string]any{"user": map[string]any{"id": "usr_a"}}),
		event("user.created", map[string]any{"user": map[string]any{"id": "usr_a"}}),
		event("session.revoked", map[string]any{"sid": "sid_zzz"}),
		nil,
	} {
		if n := v.HandleEvent(ctx, e); n != 0 {
			t.Fatalf("%v evicted %d", e, n)
		}
	}
	if n := v.HandleEvent(ctx, event("token.revoked", map[string]any{"token_type": "access_token", "jti": "jti_a"})); n != 1 {
		t.Fatalf("token.revoked evicted %d", n)
	}
	if n := v.HandleEvent(ctx, event("session.revoked", map[string]any{"sid": "sid_b"})); n != 1 {
		t.Fatalf("session.revoked evicted %d", n)
	}
	for _, typ := range []string{"user.sessions_revoked", "user.deleted", "user.updated", "user.password_changed"} {
		for _, tok := range []string{c, d} {
			if _, err := v.Verify(ctx, tok); err != nil {
				t.Fatal(err)
			}
		}
		if n := v.HandleEvent(ctx, event(typ, map[string]any{"user": map[string]any{"id": "usr_c"}})); n != 2 {
			t.Fatalf("%s evicted %d", typ, n)
		}
	}
	// Revoked at 9in: the next check asks again and refuses.
	active.Delete(a)
	_, err := v.Verify(ctx, a)
	wantCode(t, err, "invalid_token", 401)
	wantDescription(t, err, "revoked")
	// b is still active at 9in, c and d were evicted and are asked again.
	before := f.count("/oauth/introspect")
	for _, tok := range []string{b, c, d} {
		if _, err := v.Verify(ctx, tok); err != nil {
			t.Fatal(err)
		}
	}
	if f.count("/oauth/introspect") != before+3 {
		t.Fatal("evicted tokens must be introspected again")
	}
}

func TestHybridCachesRefusalsUntilExpiryAndAnswersAtMostCacheTTL(t *testing.T) {
	v, f, active, c := hybridSetup(t, ModeHybrid)
	revoked := makeToken(t, "ES256", nil, claimsFor(f.issuer, map[string]any{"exp": time.Now().Unix() + 600}))
	for i := 0; i < 3; i++ {
		_, err := v.Verify(ctx, revoked)
		wantCode(t, err, "invalid_token", 401)
		c.Advance(2 * time.Minute)
	}
	if n := f.count("/oauth/introspect"); n != 1 {
		t.Fatalf("a refusal must be cached: introspected %d times", n)
	}

	// An active answer is trusted for CacheTTL (5 minutes), then asked again.
	token := makeToken(t, "ES256", nil, claimsFor(f.issuer, map[string]any{"exp": time.Now().Unix() + 3600, "jti": "long"}))
	active.Store(token, activeClaims(f.issuer, nil))
	before := f.count("/oauth/introspect")
	_, _ = v.Verify(ctx, token)
	c.Advance(4 * time.Minute)
	_, _ = v.Verify(ctx, token)
	if f.count("/oauth/introspect") != before+1 {
		t.Fatal("within CacheTTL")
	}
	c.Advance(2 * time.Minute)
	_, _ = v.Verify(ctx, token)
	if f.count("/oauth/introspect") != before+2 {
		t.Fatal("after CacheTTL")
	}
}

func TestHybridNeverCachesPastExpiry(t *testing.T) {
	v, f, active, _ := hybridSetup(t, ModeHybrid)
	exp := v.now().Add(90 * time.Second).Unix()
	token := makeToken(t, "ES256", nil, claimsFor(f.issuer, map[string]any{"exp": exp}))
	active.Store(token, activeClaims(f.issuer, map[string]any{"exp": exp}))
	if _, err := v.Verify(ctx, token); err != nil {
		t.Fatal(err)
	}
	hit, ok := v.answers.Get(ctx, tokenKey(token))
	if !ok || hit.Until.Unix() != exp {
		t.Fatalf("cached until %v, want the token's expiry %d", hit.Until, exp)
	}
}

func TestIntrospectModeAsksEveryTime(t *testing.T) {
	v, f, active, _ := hybridSetup(t, ModeIntrospect)
	token := makeToken(t, "ES256", nil, claimsFor(f.issuer, nil))
	active.Store(token, activeClaims(f.issuer, nil))
	for i := 0; i < 3; i++ {
		if _, err := v.Verify(ctx, token); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.count("/oauth/introspect"); n != 3 {
		t.Fatalf("introspected %d times, want 3", n)
	}
	active.Delete(token)
	_, err := v.Verify(ctx, token)
	wantCode(t, err, "invalid_token", 401)
}

func TestOpaqueTokens(t *testing.T) {
	v, f, active, c := hybridSetup(t, ModeHybrid)
	opaque := OpaquePrefix + "abc123"
	active.Store(opaque, activeClaims(f.issuer, map[string]any{"scope": "orders:read"}))
	claims, err := v.Verify(ctx, "Bearer "+opaque, "orders:read")
	if err != nil || claims.Subject() != "usr_1" {
		t.Fatalf("%v %v", err, claims)
	}
	_, _ = v.Verify(ctx, opaque)
	if n := f.count("/oauth/introspect"); n != 1 {
		t.Fatalf("opaque tokens are cached in hybrid mode: %d", n)
	}
	// Claims of opaque tokens are checked after introspection.
	_, err = v.Verify(ctx, opaque, "orders:write")
	wantCode(t, err, "insufficient_scope", 403)
	other := OpaquePrefix + "other-api"
	active.Store(other, activeClaims(f.issuer, map[string]any{"aud": "https://other.acme.test"}))
	_, err = v.Verify(ctx, other)
	wantDescription(t, err, "audience mismatch")
	evil := OpaquePrefix + "other-issuer"
	active.Store(evil, activeClaims("https://evil.9in.io", nil))
	_, err = v.Verify(ctx, evil)
	wantDescription(t, err, "issuer mismatch")
	stale := OpaquePrefix + "expired"
	active.Store(stale, activeClaims(f.issuer, map[string]any{"exp": time.Now().Unix() - 120}))
	_, err = v.Verify(ctx, stale)
	wantDescription(t, err, "expired")

	// A refused opaque token without an expiry is remembered for a minute.
	unknown := OpaquePrefix + "unknown"
	before := f.count("/oauth/introspect")
	for i := 0; i < 3; i++ {
		_, err = v.Verify(ctx, unknown)
		wantCode(t, err, "invalid_token", 401)
	}
	if f.count("/oauth/introspect") != before+1 {
		t.Fatal("refusal not cached")
	}
	c.Advance(61 * time.Second)
	_, _ = v.Verify(ctx, unknown)
	if f.count("/oauth/introspect") != before+2 {
		t.Fatal("refusal cached past a minute")
	}

	// A refresh token presented as an access token is refused.
	refresh := OpaquePrefix + "looks-like-access"
	active.Store(refresh, map[string]any{"active": true, "token_type": "refresh_token", "iss": f.issuer, "exp": time.Now().Unix() + 60})
	_, err = v.Verify(ctx, refresh)
	wantCode(t, err, "invalid_token", 401)

	// Local mode can't check opaque tokens.
	local := newTestVerifier(t, f, VerifierConfig{})
	_, err = local.Verify(ctx, opaque)
	wantDescription(t, err, "opaque tokens need hybrid or introspect mode")
}

func TestIntrospectionFailuresAreNotInvalidTokens(t *testing.T) {
	f := newFakeIssuer(t)
	f.setKeys(asymmetricKeys(t)...)
	f.introspect = func(r *http.Request, form url.Values) (int, any) {
		return 401, map[string]any{"error": "invalid_client", "error_description": "wrong secret"}
	}
	v := newTestVerifier(t, f, VerifierConfig{ClientID: "app_server", ClientSecret: "wrong"})
	_, err := v.Verify(ctx, makeToken(t, "ES256", nil, claimsFor(f.issuer, nil)))
	wantCode(t, err, "invalid_client", 401)
	// Not cached: the next call asks again.
	_, _ = v.Verify(ctx, makeToken(t, "ES256", nil, claimsFor(f.issuer, nil)))
	if f.count("/oauth/introspect") != 2 {
		t.Fatal("failures must not be cached")
	}
	f.introspect = func(*http.Request, url.Values) (int, any) { return 500, nil }
	_, err = v.Verify(ctx, OpaquePrefix+"x")
	wantCode(t, err, "introspection_failed", 500)
}

func TestConcurrentIdenticalIntrospectionsShareOneRequest(t *testing.T) {
	f := newFakeIssuer(t)
	f.setKeys(asymmetricKeys(t)...)
	token := makeToken(t, "ES256", nil, claimsFor(f.issuer, nil))
	release := make(chan struct{})
	var calls atomic.Int32
	f.introspect = func(*http.Request, url.Values) (int, any) {
		calls.Add(1)
		<-release
		return 200, activeClaims(f.issuer, nil)
	}
	v := newTestVerifier(t, f, VerifierConfig{ClientID: "a", ClientSecret: "b", Mode: ModeIntrospect})
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := v.Verify(ctx, token); err != nil {
				errs <- err
			}
		}()
	}
	time.Sleep(100 * time.Millisecond)
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("%d introspections for 20 concurrent calls", n)
	}
}

func TestAWaitingCallerCanGiveUp(t *testing.T) {
	f := newFakeIssuer(t)
	f.setKeys(asymmetricKeys(t)...)
	release := make(chan struct{})
	f.introspect = func(*http.Request, url.Values) (int, any) {
		<-release
		return 200, activeClaims(f.issuer, nil)
	}
	defer close(release)
	v := newTestVerifier(t, f, VerifierConfig{ClientID: "a", ClientSecret: "b"})
	short, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	_, err := v.Verify(short, makeToken(t, "ES256", nil, claimsFor(f.issuer, nil)))
	if err != context.DeadlineExceeded {
		t.Fatalf("want the context's error, got %v", err)
	}
}

// A custom AnswerCache sees every Set, Get and Evict.
type recordingCache struct {
	*MemoryAnswerCache
	mu     sync.Mutex
	events []string
}

func (r *recordingCache) Set(ctx context.Context, key string, a CachedAnswer) {
	r.mu.Lock()
	r.events = append(r.events, "set")
	r.mu.Unlock()
	r.MemoryAnswerCache.Set(ctx, key, a)
}

func (r *recordingCache) Evict(ctx context.Context, claim, value string) int {
	r.mu.Lock()
	r.events = append(r.events, "evict:"+claim+"="+value)
	r.mu.Unlock()
	return r.MemoryAnswerCache.Evict(ctx, claim, value)
}

func TestPluggableAnswerCache(t *testing.T) {
	f := newFakeIssuer(t)
	f.setKeys(asymmetricKeys(t)...)
	token := makeToken(t, "ES256", nil, claimsFor(f.issuer, nil))
	f.introspect = func(*http.Request, url.Values) (int, any) { return 200, activeClaims(f.issuer, nil) }
	cache := &recordingCache{MemoryAnswerCache: NewMemoryAnswerCache(0)}
	v := newTestVerifier(t, f, VerifierConfig{ClientID: "a", ClientSecret: "b", Cache: cache})
	_, _ = v.Verify(ctx, token)
	v.HandleEvent(ctx, &WebhookEvent{EventType: "session.revoked", Data: map[string]any{"sid": "sid_1"}})
	if strings.Join(cache.events, ",") != "set,evict:sid=sid_1" {
		t.Fatalf("events %v", cache.events)
	}
	v.Clear(ctx)
	if cache.Len() != 0 {
		t.Fatal("Clear")
	}
}

func TestMemoryAnswerCacheIsLRU(t *testing.T) {
	c := NewMemoryAnswerCache(2)
	until := time.Now().Add(time.Hour)
	c.Set(ctx, "a", CachedAnswer{Claims: Claims{"sub": "a"}, Until: until})
	c.Set(ctx, "b", CachedAnswer{Claims: Claims{"sub": "b"}, Until: until})
	c.Get(ctx, "a") // a is now the most recently used
	c.Set(ctx, "c", CachedAnswer{Claims: Claims{"sub": "c"}, Until: until})
	if _, ok := c.Get(ctx, "b"); ok {
		t.Fatal("b should have been dropped")
	}
	if _, ok := c.Get(ctx, "a"); !ok {
		t.Fatal("a should be kept")
	}
	c.Set(ctx, "old", CachedAnswer{Until: time.Now().Add(-time.Second)})
	if _, ok := c.Get(ctx, "old"); ok {
		t.Fatal("expired answers are misses")
	}
	if c.Evict(ctx, "sub", "") != 0 {
		t.Fatal("an empty value evicts nothing")
	}
}
