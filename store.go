package nine

import (
	"context"
	"sync"
	"time"
)

// Store is a small key-value store with expiry, for state the SDK shares across requests
// and, with a shared implementation, across processes: processed webhook ids
// ([EventDeduplicator], [WebhookHandler]) and hybrid verification answers with their
// revocation markers ([VerifierConfig].Store).
//
// Keys are short ASCII strings and values are strings. Add must be atomic: store the value
// only when the key is missing or expired, and report whether it did (Redis SET NX PX, an
// SQL insert on a unique key, a conditional put). A store that drops keys early under
// memory pressure (Redis with an allkeys eviction policy) can let a webhook be handled
// twice, so use one that keeps keys until they expire.
//
// [MemoryStore] is the implementation for one process.
type Store interface {
	// Get returns the value of key, and whether it exists and hasn't expired.
	Get(ctx context.Context, key string) (value string, ok bool, err error)
	// Set stores value under key for ttl.
	Set(ctx context.Context, key, value string, ttl time.Duration) error
	// Add stores value under key for ttl only if key is missing or expired, atomically,
	// and reports whether it stored it.
	Add(ctx context.Context, key, value string, ttl time.Duration) (bool, error)
	// Delete removes key.
	Delete(ctx context.Context, key string) error
}

// MultiGetter is an optional method of a [Store] that reads several keys in one round
// trip (Redis MGET). When the store has it, a hybrid [Verifier] reads a cached answer's
// revocation markers with one call instead of one per marker.
type MultiGetter interface {
	// GetMany returns the values of keys and whether each exists, in the same order.
	GetMany(ctx context.Context, keys []string) (values []string, ok []bool, err error)
}

// MemoryStore is an in-memory [Store] for one process: tests, a single server, or the
// default of [WebhookHandler]. It is safe for concurrent use.
type MemoryStore struct {
	mu    sync.Mutex
	items map[string]memoryItem
	now   func() time.Time
}

type memoryItem struct {
	value   string
	expires time.Time
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{items: make(map[string]memoryItem), now: time.Now}
}

func (s *MemoryStore) live(key string) (memoryItem, bool) {
	item, ok := s.items[key]
	if ok && !item.expires.After(s.now()) {
		delete(s.items, key)
		return memoryItem{}, false
	}
	return item, ok
}

// sweep drops expired items once the map grows large.
func (s *MemoryStore) sweep() {
	if len(s.items) > 10000 {
		for k := range s.items {
			s.live(k)
		}
	}
}

// Get implements Store.
func (s *MemoryStore) Get(_ context.Context, key string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.live(key)
	return item.value, ok, nil
}

// Set implements Store.
func (s *MemoryStore) Set(_ context.Context, key, value string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[key] = memoryItem{value: value, expires: s.now().Add(ttl)}
	s.sweep()
	return nil
}

// Add implements Store.
func (s *MemoryStore) Add(_ context.Context, key, value string, ttl time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.live(key); ok {
		return false, nil
	}
	s.items[key] = memoryItem{value: value, expires: s.now().Add(ttl)}
	s.sweep()
	return true, nil
}

// Delete implements Store.
func (s *MemoryStore) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, key)
	return nil
}
