package nine

import (
	"context"
	"sync"
	"time"
)

// EventStore is a key-value store for processing each event once. Add must be atomic:
// insert only when the key is absent or expired, and report whether it did. Use Redis
// SET NX EX, an SQL table with a unique key, or [MemoryEventStore] for one process.
type EventStore interface {
	Add(ctx context.Context, key, value string, ttl time.Duration) (bool, error)
	Get(ctx context.Context, key string) (value string, ok bool, err error)
	Set(ctx context.Context, key, value string, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
}

// MemoryEventStore is an in-memory EventStore for one process (tests, a single server).
type MemoryEventStore struct {
	mu    sync.Mutex
	items map[string]memoryItem
	now   func() time.Time
}

type memoryItem struct {
	value   string
	expires time.Time
}

// NewMemoryEventStore returns an empty MemoryEventStore.
func NewMemoryEventStore() *MemoryEventStore {
	return &MemoryEventStore{items: make(map[string]memoryItem), now: time.Now}
}

func (s *MemoryEventStore) live(key string) (memoryItem, bool) {
	item, ok := s.items[key]
	if ok && !item.expires.After(s.now()) {
		delete(s.items, key)
		return memoryItem{}, false
	}
	return item, ok
}

// Add implements EventStore.
func (s *MemoryEventStore) Add(_ context.Context, key, value string, ttl time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.live(key); ok {
		return false, nil
	}
	s.items[key] = memoryItem{value: value, expires: s.now().Add(ttl)}
	if len(s.items) > 10000 {
		for k := range s.items {
			s.live(k)
		}
	}
	return true, nil
}

// Get implements EventStore.
func (s *MemoryEventStore) Get(_ context.Context, key string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.live(key)
	return item.value, ok, nil
}

// Set implements EventStore.
func (s *MemoryEventStore) Set(_ context.Context, key, value string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[key] = memoryItem{value: value, expires: s.now().Add(ttl)}
	return nil
}

// Delete implements EventStore.
func (s *MemoryEventStore) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, key)
	return nil
}

// ProcessStatus is the outcome of processing an event once.
type ProcessStatus string

const (
	// Processed: the first delivery, and the handler succeeded. Answer 2xx.
	Processed ProcessStatus = "processed"
	// Duplicate: already processed. Answer 2xx so 9in stops retrying.
	Duplicate ProcessStatus = "duplicate"
	// InProgress: another delivery of the same event is still running. Answer 409 so 9in
	// tries again later.
	InProgress ProcessStatus = "in_progress"
)

// EventDeduplicator runs a handler at most once per event id. 9in keeps the id on every
// retry and redelivery, and retries until it gets a 2xx (for about a day).
type EventDeduplicator struct {
	// Store keeps the ids (required). Its Add must be atomic.
	Store EventStore
	// TTL is how long a processed id is remembered. Default 3 days.
	TTL time.Duration
	// LockTTL is how long a running handler holds the id before another delivery may
	// take over. Default 5 minutes.
	LockTTL time.Duration
	// Prefix starts every key. Default "9in:event:".
	Prefix string
}

// Process claims eventID and runs handler:
//
//   - Processed: first delivery, handler succeeded (the id is then remembered for TTL).
//   - Duplicate: already processed; handler not run.
//   - InProgress: another delivery is running it; handler not run.
//   - handler failed (or panicked): the claim is released so 9in's retry runs it again,
//     and the error is returned (or the panic continues).
//
// When the handler succeeded but marking the id as done failed, it returns Processed
// with that error.
func (d *EventDeduplicator) Process(ctx context.Context, eventID string, handler func(context.Context) error) (ProcessStatus, error) {
	if eventID == "" {
		return "", newError("invalid_event", "event id required", 400)
	}
	if d.Store == nil {
		return "", invalidOptions("EventDeduplicator needs a Store")
	}
	ttl, lock, prefix := d.TTL, d.LockTTL, d.Prefix
	if ttl <= 0 {
		ttl = 72 * time.Hour
	}
	if lock <= 0 {
		lock = 5 * time.Minute
	}
	if prefix == "" {
		prefix = "9in:event:"
	}
	key := prefix + eventID
	claimed, err := d.Store.Add(ctx, key, "processing", lock)
	if err != nil {
		return "", err
	}
	if !claimed {
		value, ok, err := d.Store.Get(ctx, key)
		if err != nil {
			return "", err
		}
		if ok && value == "done" {
			return Duplicate, nil
		}
		return InProgress, nil
	}
	if err := runReleasing(ctx, d.Store, key, handler); err != nil {
		return "", err
	}
	return Processed, d.Store.Set(ctx, key, "done", ttl)
}

// runReleasing runs handler and deletes key when it fails or panics.
func runReleasing(ctx context.Context, store EventStore, key string, handler func(context.Context) error) (err error) {
	succeeded := false
	defer func() {
		if !succeeded {
			// Released even when ctx was cancelled, so a retry can run the handler.
			_ = store.Delete(context.WithoutCancel(ctx), key)
		}
	}()
	if err = handler(ctx); err != nil {
		return err
	}
	succeeded = true
	return nil
}

// ProcessEventOnce runs handler at most once per event id with the default TTLs. See
// [EventDeduplicator.Process].
//
//	status, err := nine.ProcessEventOnce(ctx, store, event.ID, func(ctx context.Context) error { return handle(ctx, event) })
func ProcessEventOnce(ctx context.Context, store EventStore, eventID string, handler func(context.Context) error) (ProcessStatus, error) {
	d := EventDeduplicator{Store: store}
	return d.Process(ctx, eventID, handler)
}
