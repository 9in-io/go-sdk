package nine

import (
	"context"
	"time"
)

// EventStore is the [Store] that [EventDeduplicator] and [WebhookHandler] keep event ids in.
//
// Deprecated: use [Store], the same interface (renamed in 0.2.0, when the hybrid
// [Verifier] started using it too).
type EventStore = Store

// MemoryEventStore is the in-memory [Store].
//
// Deprecated: use [MemoryStore] (renamed in 0.2.0).
type MemoryEventStore = MemoryStore

// NewMemoryEventStore returns an empty in-memory [Store].
//
// Deprecated: use [NewMemoryStore] (renamed in 0.2.0).
func NewMemoryEventStore() *MemoryStore { return NewMemoryStore() }

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
	Store Store
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
func runReleasing(ctx context.Context, store Store, key string, handler func(context.Context) error) (err error) {
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
func ProcessEventOnce(ctx context.Context, store Store, eventID string, handler func(context.Context) error) (ProcessStatus, error) {
	d := EventDeduplicator{Store: store}
	return d.Process(ctx, eventID, handler)
}
