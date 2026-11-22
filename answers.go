package nine

import (
	"bytes"
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"sync"
	"time"
)

// cachedAnswer is what hybrid verification remembers about a token.
type cachedAnswer struct {
	// Claims are the token's claims, or nil when 9in said it is not active.
	Claims Claims
	// Until is when 9in must be asked again.
	Until time.Time
	// At is when 9in was asked.
	At time.Time
}

// answerCache keeps hybrid answers. memoryAnswers serves one process and evicts entries
// directly; storeAnswers keeps them in a shared [Store] and evicts them with revocation
// markers that every process checks.
type answerCache interface {
	get(ctx context.Context, key string) (cachedAnswer, bool)
	set(ctx context.Context, key string, answer cachedAnswer)
	evict(ctx context.Context, claim, value string) (int, error)
	clear(ctx context.Context) error
}

// ---------------------------------------------------------------------------
// In memory, one process

// memoryAnswers is an in-memory, least-recently-used answer cache.
type memoryAnswers struct {
	mu    sync.Mutex
	size  int
	order *list.List // front: most recently used
	items map[string]*list.Element
	now   func() time.Time
}

type memoryAnswer struct {
	key    string
	answer cachedAnswer
}

// newMemoryAnswers returns an in-memory cache of at most size answers (default 10 000).
func newMemoryAnswers(size int, now func() time.Time) *memoryAnswers {
	if size <= 0 {
		size = 10000
	}
	return &memoryAnswers{size: size, order: list.New(), items: make(map[string]*list.Element), now: now}
}

func (c *memoryAnswers) get(_ context.Context, key string) (cachedAnswer, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		return cachedAnswer{}, false
	}
	entry := el.Value.(*memoryAnswer)
	if !entry.answer.Until.After(c.now()) {
		c.order.Remove(el)
		delete(c.items, key)
		return cachedAnswer{}, false
	}
	c.order.MoveToFront(el)
	return entry.answer, true
}

func (c *memoryAnswers) set(_ context.Context, key string, answer cachedAnswer) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		el.Value.(*memoryAnswer).answer = answer
		c.order.MoveToFront(el)
		return
	}
	c.items[key] = c.order.PushFront(&memoryAnswer{key: key, answer: answer})
	for c.order.Len() > c.size {
		oldest := c.order.Back()
		c.order.Remove(oldest)
		delete(c.items, oldest.Value.(*memoryAnswer).key)
	}
}

func (c *memoryAnswers) evict(_ context.Context, claim, value string) (int, error) {
	if value == "" {
		return 0, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	evicted := 0
	for key, el := range c.items {
		entry := el.Value.(*memoryAnswer)
		if entry.answer.Claims != nil && entry.answer.Claims.String(claim) == value {
			c.order.Remove(el)
			delete(c.items, key)
			evicted++
		}
	}
	return evicted, nil
}

func (c *memoryAnswers) clear(context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.order.Init()
	c.items = make(map[string]*list.Element)
	return nil
}

func (c *memoryAnswers) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}

// ---------------------------------------------------------------------------
// In a shared Store, every process

// storeAnswers keeps answers in a shared Store. An eviction can't find the answers that
// mention a jti, sid or user in a plain key-value store, so it writes a revocation marker
// instead ("r:sid:<sid>" → when). Before trusting a cached answer, every process reads the
// markers for the answer's jti, sid and sub, and the "clear everything" marker; an answer
// cached before any of them is stale. So the process that receives the webhook makes every
// other process ask 9in again, with nothing but Get and Set.
type storeAnswers struct {
	store  Store
	prefix string        // "9in:hybrid:<issuer hash>:"
	ttl    time.Duration // CacheTTL: the longest a positive answer is kept
	skew   time.Duration // clock difference allowed between processes
	now    func() time.Time
}

// storedAnswer is the JSON kept under "a:<token hash>". Times are unix milliseconds.
type storedAnswer struct {
	Claims Claims `json:"c"`
	Until  int64  `json:"u"`
	At     int64  `json:"t"`
}

func newStoreAnswers(store Store, issuer string, ttl, skew time.Duration, now func() time.Time) *storeAnswers {
	sum := sha256.Sum256([]byte(issuer))
	return &storeAnswers{store: store, prefix: "9in:hybrid:" + hex.EncodeToString(sum[:6]) + ":", ttl: ttl, skew: skew, now: now}
}

// markerTTL: a marker must outlive every positive answer cached before it.
func (s *storeAnswers) markerTTL() time.Duration { return s.ttl + s.skew + time.Minute }

func (s *storeAnswers) markerKeys(claims Claims) []string {
	keys := []string{s.prefix + "r:*"}
	for _, claim := range []string{"jti", "sid", "sub"} {
		if value := claims.String(claim); value != "" {
			keys = append(keys, s.prefix+"r:"+claim+":"+value)
		}
	}
	return keys
}

func (s *storeAnswers) getMany(ctx context.Context, keys []string) ([]string, []bool, error) {
	if m, ok := s.store.(MultiGetter); ok {
		values, found, err := m.GetMany(ctx, keys)
		if err == nil && (len(values) != len(keys) || len(found) != len(keys)) {
			return nil, nil, newError("store_failed", "GetMany returned the wrong number of values", 0)
		}
		return values, found, err
	}
	values := make([]string, len(keys))
	found := make([]bool, len(keys))
	for i, key := range keys {
		value, ok, err := s.store.Get(ctx, key)
		if err != nil {
			return nil, nil, err
		}
		values[i], found[i] = value, ok
	}
	return values, found, nil
}

// get treats a store failure, an unreadable entry or an unreadable marker as a miss, so the
// verifier asks 9in instead of trusting something it can't check.
func (s *storeAnswers) get(ctx context.Context, key string) (cachedAnswer, bool) {
	raw, ok, err := s.store.Get(ctx, s.prefix+"a:"+key)
	if err != nil || !ok {
		return cachedAnswer{}, false
	}
	var stored storedAnswer
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	dec.UseNumber()
	if dec.Decode(&stored) != nil {
		return cachedAnswer{}, false
	}
	answer := cachedAnswer{Claims: stored.Claims, Until: time.UnixMilli(stored.Until), At: time.UnixMilli(stored.At)}
	if !answer.Until.After(s.now()) {
		return cachedAnswer{}, false
	}
	if answer.Claims == nil {
		return answer, true // a refusal stands until it expires
	}
	keys := s.markerKeys(answer.Claims)
	values, found, err := s.getMany(ctx, keys)
	if err != nil {
		return cachedAnswer{}, false
	}
	for i := range keys {
		if !found[i] {
			continue
		}
		ms, err := strconv.ParseInt(values[i], 10, 64)
		if err != nil {
			return cachedAnswer{}, false
		}
		// Cached before the revocation (allowing for clocks that disagree): ask again.
		if !answer.At.After(time.UnixMilli(ms).Add(s.skew)) {
			return cachedAnswer{}, false
		}
	}
	return answer, true
}

// set is best effort: a cache that can't be written only costs another introspection.
func (s *storeAnswers) set(ctx context.Context, key string, answer cachedAnswer) {
	ttl := answer.Until.Sub(s.now())
	if ttl <= 0 {
		return
	}
	raw, err := json.Marshal(storedAnswer{Claims: answer.Claims, Until: answer.Until.UnixMilli(), At: answer.At.UnixMilli()})
	if err != nil {
		return
	}
	_ = s.store.Set(ctx, s.prefix+"a:"+key, string(raw), ttl)
}

func (s *storeAnswers) mark(ctx context.Context, key string) error {
	return s.store.Set(ctx, key, strconv.FormatInt(s.now().UnixMilli(), 10), s.markerTTL())
}

// evict writes the marker and reports 1: the answers it covers can't be counted.
func (s *storeAnswers) evict(ctx context.Context, claim, value string) (int, error) {
	if value == "" {
		return 0, nil
	}
	if err := s.mark(ctx, s.prefix+"r:"+claim+":"+value); err != nil {
		return 0, err
	}
	return 1, nil
}

func (s *storeAnswers) clear(ctx context.Context) error { return s.mark(ctx, s.prefix+"r:*") }
