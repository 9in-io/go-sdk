package nine

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Two "processes" (verifiers) of one API sharing a Store, with one fake 9in and one clock.
type sharedSetup struct {
	f      *fakeIssuer
	active *sync.Map
	store  *MemoryStore
	clock  *clock
	a, b   *Verifier
}

func newSharedSetup(t *testing.T, store Store) *sharedSetup {
	t.Helper()
	f := newFakeIssuer(t)
	f.setKeys(asymmetricKeys(t)...)
	active := &sync.Map{}
	f.introspect = introspectFrom(t, active)
	c := newClock()
	mem := NewMemoryStore()
	mem.now = c.Now
	if store == nil {
		store = mem
	}
	mk := func() *Verifier {
		v := newTestVerifier(t, f, VerifierConfig{Audience: "https://api.acme.test", ClientID: "app_server", ClientSecret: "s3cret:with/chars", Store: store})
		v.now = c.Now
		return v
	}
	return &sharedSetup{f: f, active: active, store: mem, clock: c, a: mk(), b: mk()}
}

func (s *sharedSetup) token(t *testing.T, extra map[string]any) string {
	t.Helper()
	token := makeToken(t, "ES256", nil, claimsFor(s.f.issuer, extra))
	s.active.Store(token, activeClaims(s.f.issuer, extra))
	return token
}

func mustVerify(t *testing.T, v *Verifier, token string, scopes ...string) Claims {
	t.Helper()
	claims, err := v.Verify(ctx, token, scopes...)
	if err != nil {
		t.Fatal(err)
	}
	return claims
}

func TestSharedStoreAnswersAreShared(t *testing.T) {
	s := newSharedSetup(t, nil)
	token := s.token(t, nil)
	mustVerify(t, s.a, token)
	mustVerify(t, s.b, token, "orders:read")
	mustVerify(t, s.a, token)
	if n := s.f.count("/oauth/introspect"); n != 1 {
		t.Fatalf("introspected %d times across two processes, want 1", n)
	}
}

// The process that receives a webhook makes every other process ask 9in again.
func TestSharedStoreEvictionReachesEveryProcess(t *testing.T) {
	s := newSharedSetup(t, nil)
	cases := []struct {
		name  string
		extra map[string]any
		event *WebhookEvent
	}{
		{"token.revoked", map[string]any{"jti": "jti_x", "sid": "sid_x", "sub": "usr_x"},
			&WebhookEvent{EventType: "token.revoked", Data: map[string]any{"token_type": "access_token", "jti": "jti_x"}}},
		{"session.revoked", map[string]any{"jti": "jti_y", "sid": "sid_y", "sub": "usr_y"},
			&WebhookEvent{EventType: "session.revoked", Data: map[string]any{"sid": "sid_y"}}},
		{"user.deleted", map[string]any{"jti": "jti_z", "sid": "sid_z", "sub": "usr_z"},
			&WebhookEvent{EventType: "user.deleted", Data: map[string]any{"user": map[string]any{"id": "usr_z"}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token := s.token(t, tc.extra)
			mustVerify(t, s.a, token)
			s.clock.Advance(time.Minute) // well past the allowed clock skew
			s.active.Delete(token)       // revoked at 9in
			mustVerify(t, s.a, token)    // still trusted: no webhook yet
			n, err := s.b.HandleEvent(ctx, tc.event)
			if err != nil || n != 1 {
				t.Fatalf("HandleEvent = %d, %v", n, err)
			}
			_, err = s.a.Verify(ctx, token)
			wantCode(t, err, "invalid_token", 401)
			wantDescription(t, err, "revoked")
		})
	}
}

func TestSharedStoreMarkersOnlyHitTheirTokens(t *testing.T) {
	s := newSharedSetup(t, nil)
	mine := s.token(t, map[string]any{"jti": "jti_1", "sid": "sid_1", "sub": "usr_1"})
	other := s.token(t, map[string]any{"jti": "jti_2", "sid": "sid_2", "sub": "usr_2"})
	mustVerify(t, s.a, mine)
	mustVerify(t, s.a, other)
	s.clock.Advance(time.Minute)
	if _, err := s.b.HandleEvent(ctx, &WebhookEvent{EventType: "session.revoked", Data: map[string]any{"sid": "sid_1"}}); err != nil {
		t.Fatal(err)
	}
	before := s.f.count("/oauth/introspect")
	mustVerify(t, s.a, other)
	if s.f.count("/oauth/introspect") != before {
		t.Fatal("an unrelated answer was dropped")
	}
	mustVerify(t, s.a, mine)
	if s.f.count("/oauth/introspect") != before+1 {
		t.Fatal("the revoked session's answer was kept")
	}
	// Answers cached after the revocation (well after: clocks may differ) are trusted.
	s.clock.Advance(time.Minute)
	mustVerify(t, s.a, mine)
	mustVerify(t, s.b, mine)
	if s.f.count("/oauth/introspect") != before+2 {
		t.Fatalf("a fresh answer must be trusted again: %d", s.f.count("/oauth/introspect")-before)
	}
	// Events that concern no cached token write nothing.
	for _, e := range []*WebhookEvent{
		nil,
		{EventType: "token.revoked", Data: map[string]any{"token_type": "refresh_token", "jti": "jti_1"}},
		{EventType: "user.login", Data: map[string]any{"user": map[string]any{"id": "usr_1"}}},
		{EventType: "session.revoked", Data: map[string]any{}},
	} {
		if n, err := s.b.HandleEvent(ctx, e); n != 0 || err != nil {
			t.Fatalf("%v: %d %v", e, n, err)
		}
	}
}

func TestSharedStoreClearReachesEveryProcess(t *testing.T) {
	s := newSharedSetup(t, nil)
	token := s.token(t, nil)
	mustVerify(t, s.a, token)
	s.clock.Advance(time.Minute)
	if err := s.b.Clear(ctx); err != nil {
		t.Fatal(err)
	}
	mustVerify(t, s.a, token)
	if n := s.f.count("/oauth/introspect"); n != 2 {
		t.Fatalf("Clear in one process must reach the others: %d", n)
	}
}

// Clocks of two servers disagree a little: an answer cached just "after" a revocation, by
// the other server's clock, is still treated as stale.
func TestSharedStoreAllowsForClockSkew(t *testing.T) {
	s := newSharedSetup(t, nil)
	token := s.token(t, map[string]any{"sid": "sid_skew"})
	if _, err := s.b.HandleEvent(ctx, &WebhookEvent{EventType: "session.revoked", Data: map[string]any{"sid": "sid_skew"}}); err != nil {
		t.Fatal(err)
	}
	s.clock.Advance(10 * time.Second) // within the 30-second leeway
	mustVerify(t, s.a, token)
	mustVerify(t, s.a, token)
	if n := s.f.count("/oauth/introspect"); n != 2 {
		t.Fatalf("within the skew allowance every check asks 9in: %d", n)
	}
}

// A revocation that lands while the introspection request is in flight still makes the
// answer stale: answers are dated when 9in was asked.
func TestSharedStoreRevocationDuringIntrospection(t *testing.T) {
	s := newSharedSetup(t, nil)
	token := s.token(t, map[string]any{"jti": "jti_race"})
	inner := s.f.introspect
	var once sync.Once
	s.f.introspect = func(r *http.Request, form url.Values) (int, any) {
		status, body := inner(r, form) // 9in answers "active"…
		once.Do(func() {
			s.clock.Advance(time.Minute) // …and the revocation arrives before the answer is cached.
			if _, err := s.b.HandleEvent(context.Background(), &WebhookEvent{EventType: "token.revoked", Data: map[string]any{"token_type": "access_token", "jti": "jti_race"}}); err != nil {
				t.Error(err)
			}
		})
		return status, body
	}
	mustVerify(t, s.a, token)
	s.active.Delete(token)
	_, err := s.a.Verify(ctx, token)
	wantCode(t, err, "invalid_token", 401)
}

func TestSharedStoreRefusalsAndExpiry(t *testing.T) {
	s := newSharedSetup(t, nil)
	revoked := makeToken(t, "ES256", nil, claimsFor(s.f.issuer, map[string]any{"exp": time.Now().Unix() + 600}))
	for _, v := range []*Verifier{s.a, s.b, s.a} {
		_, err := v.Verify(ctx, revoked)
		wantCode(t, err, "invalid_token", 401)
	}
	if n := s.f.count("/oauth/introspect"); n != 1 {
		t.Fatalf("a refusal is shared too: %d", n)
	}
	// A positive answer is trusted for CacheTTL at most.
	token := s.token(t, map[string]any{"jti": "jti_ttl"})
	before := s.f.count("/oauth/introspect")
	mustVerify(t, s.a, token)
	s.clock.Advance(4 * time.Minute)
	mustVerify(t, s.b, token)
	s.clock.Advance(2 * time.Minute)
	mustVerify(t, s.b, token)
	if s.f.count("/oauth/introspect") != before+2 {
		t.Fatalf("CacheTTL across processes: %d", s.f.count("/oauth/introspect")-before)
	}
}

func TestSharedStoreOpaqueTokensSurviveTheRoundTrip(t *testing.T) {
	s := newSharedSetup(t, nil)
	opaque := OpaquePrefix + "shared"
	s.active.Store(opaque, activeClaims(s.f.issuer, map[string]any{"scope": "orders:read", "jti": "jti_o"}))
	claims := mustVerify(t, s.a, opaque, "orders:read")
	again := mustVerify(t, s.b, opaque, "orders:read") // from the store: JSON numbers, checked again
	if again.Subject() != claims.Subject() || again.Time("exp").IsZero() {
		t.Fatalf("%v", again)
	}
	_, err := s.b.Verify(ctx, opaque, "orders:write")
	wantCode(t, err, "insufficient_scope", 403)
	if n := s.f.count("/oauth/introspect"); n != 1 {
		t.Fatalf("%d", n)
	}
}

// A store that fails, or counts what it is asked.
type flakyStore struct {
	*MemoryStore
	failGet, failSet atomic.Bool
	gets, many       atomic.Int32
}

func (f *flakyStore) Get(ctx context.Context, key string) (string, bool, error) {
	f.gets.Add(1)
	if f.failGet.Load() {
		return "", false, errors.New("redis down")
	}
	return f.MemoryStore.Get(ctx, key)
}

func (f *flakyStore) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	if f.failSet.Load() {
		return errors.New("redis down")
	}
	return f.MemoryStore.Set(ctx, key, value, ttl)
}

// multiStore adds GetMany.
type multiStore struct{ *flakyStore }

func (m multiStore) GetMany(ctx context.Context, keys []string) ([]string, []bool, error) {
	m.many.Add(1)
	values := make([]string, len(keys))
	found := make([]bool, len(keys))
	for i, k := range keys {
		values[i], found[i], _ = m.MemoryStore.Get(ctx, k)
	}
	return values, found, nil
}

func TestSharedStoreFailuresAreMisses(t *testing.T) {
	store := &flakyStore{MemoryStore: NewMemoryStore()}
	s := newSharedSetup(t, store)
	token := s.token(t, nil)
	store.failSet.Store(true) // can't cache: every check asks 9in, and still works
	mustVerify(t, s.a, token)
	mustVerify(t, s.a, token)
	store.failSet.Store(false)
	mustVerify(t, s.a, token)
	store.failGet.Store(true) // can't read: ask 9in rather than trust nothing
	mustVerify(t, s.a, token)
	if n := s.f.count("/oauth/introspect"); n != 4 {
		t.Fatalf("%d", n)
	}
	store.failGet.Store(false)
	// A marker that can't be written is an error the webhook must surface.
	store.failSet.Store(true)
	if _, err := s.b.HandleEvent(ctx, &WebhookEvent{EventType: "session.revoked", Data: map[string]any{"sid": "sid_1"}}); err == nil {
		t.Fatal("HandleEvent must report a store failure")
	}
	if err := s.b.Clear(ctx); err == nil {
		t.Fatal("Clear must report a store failure")
	}
	// Unreadable entries are misses too.
	store.failSet.Store(false)
	before := s.f.count("/oauth/introspect")
	_ = store.MemoryStore.Set(ctx, s.a.answers.(*storeAnswers).prefix+"a:"+tokenKey(token), "{not json", time.Hour)
	mustVerify(t, s.a, token)
	_ = store.MemoryStore.Set(ctx, s.a.answers.(*storeAnswers).prefix+"r:sid:sid_1", "garbage", time.Hour)
	mustVerify(t, s.a, token)
	if s.f.count("/oauth/introspect") != before+2 {
		t.Fatal("unreadable answers and markers must be misses")
	}
}

func TestSharedStoreUsesGetMany(t *testing.T) {
	inner := &flakyStore{MemoryStore: NewMemoryStore()}
	s := newSharedSetup(t, multiStore{inner})
	token := s.token(t, nil)
	mustVerify(t, s.a, token)
	s.clock.Advance(time.Minute)
	inner.gets.Store(0)
	mustVerify(t, s.b, token)
	if g, m := inner.gets.Load(), inner.many.Load(); g != 1 || m != 1 {
		t.Fatalf("a hit should be one Get and one GetMany, got %d and %d", g, m)
	}
	// Without GetMany: one Get per marker (all, jti, sid, sub) plus the answer.
	plain := &flakyStore{MemoryStore: NewMemoryStore()}
	p := newSharedSetup(t, plain)
	other := p.token(t, nil)
	mustVerify(t, p.a, other)
	p.clock.Advance(time.Minute)
	plain.gets.Store(0)
	mustVerify(t, p.b, other)
	if g := plain.gets.Load(); g != 5 {
		t.Fatalf("got %d Gets", g)
	}
}

func TestSharedStoreKeysAreNamespacedByIssuer(t *testing.T) {
	store := NewMemoryStore()
	a := newStoreAnswers(store, "https://acme.9in.io", time.Minute, time.Second, time.Now)
	b := newStoreAnswers(store, "https://other.9in.io", time.Minute, time.Second, time.Now)
	if a.prefix == b.prefix || !strings.HasPrefix(a.prefix, "9in:hybrid:") {
		t.Fatalf("%q %q", a.prefix, b.prefix)
	}
	a.set(ctx, "k", cachedAnswer{Claims: Claims{"sub": "x"}, Until: time.Now().Add(time.Minute), At: time.Now().Add(-time.Minute)})
	if _, ok := b.get(ctx, "k"); ok {
		t.Fatal("another tenant's answer was visible")
	}
	if got, ok := a.get(ctx, "k"); !ok || got.Claims.Subject() != "x" {
		t.Fatal("own answer")
	}
	if n, err := a.evict(ctx, "sub", ""); n != 0 || err != nil {
		t.Fatal("an empty value writes no marker")
	}
}

func TestWebhookHandlerStoreFailureWhileEvicting(t *testing.T) {
	store := &flakyStore{MemoryStore: NewMemoryStore()}
	s := newSharedSetup(t, store)
	store.failSet.Store(true)
	var reported error
	handled := false
	h := WebhookHandler(WebhookConfig{Secret: webhookSecret, Verifier: s.b, Store: NewMemoryStore(),
		Handle:  func(context.Context, *WebhookEvent) error { handled = true; return nil },
		OnError: func(r *http.Request, err error) { reported = err }})
	body := []byte(`{"id":"evt_rev","event_type":"session.revoked","created_at":"2026-11-22T00:00:00.000Z","tenant":"tnt_1","environment":"production","data":{"sid":"sid_1"}}`)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, signedWebhook("/nine/webhook", body, webhookSecret))
	if w.Code != 500 || !strings.Contains(w.Body.String(), "store_failed") || reported == nil || handled {
		t.Fatalf("%d %s %v handled=%v", w.Code, w.Body.String(), reported, handled)
	}
	// Once the store is back, 9in's retry goes through.
	store.failSet.Store(false)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, signedWebhook("/nine/webhook", body, webhookSecret))
	if w.Code != 204 || !handled {
		t.Fatalf("retry: %d", w.Code)
	}
}

func TestDeprecatedStoreNames(t *testing.T) {
	var s EventStore = NewMemoryEventStore()
	var _ *MemoryEventStore = NewMemoryStore()
	if ok, err := s.Add(ctx, "k", "v", time.Minute); !ok || err != nil {
		t.Fatal(ok, err)
	}
}
