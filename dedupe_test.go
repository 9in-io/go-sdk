package nine

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestProcessEventOnce(t *testing.T) {
	store := NewMemoryEventStore()
	runs := 0
	handler := func(context.Context) error { runs++; return nil }
	if s, err := ProcessEventOnce(ctx, store, "evt_1", handler); s != Processed || err != nil {
		t.Fatalf("%s %v", s, err)
	}
	if s, err := ProcessEventOnce(ctx, store, "evt_1", handler); s != Duplicate || err != nil {
		t.Fatalf("%s %v", s, err)
	}
	if runs != 1 {
		t.Fatalf("ran %d times", runs)
	}
	if v, ok, _ := store.Get(ctx, "9in:event:evt_1"); !ok || v != "done" {
		t.Fatalf("stored %q", v)
	}
	_, err := ProcessEventOnce(ctx, store, "", handler)
	wantCode(t, err, "invalid_event", 400)
	_, err = (&EventDeduplicator{}).Process(ctx, "x", handler)
	wantCode(t, err, "invalid_options", 0)
}

func TestProcessEventOnceReleasesOnFailureAndPanic(t *testing.T) {
	store := NewMemoryEventStore()
	boom := errors.New("boom")
	if s, err := ProcessEventOnce(ctx, store, "evt_2", func(context.Context) error { return boom }); s != "" || !errors.Is(err, boom) {
		t.Fatalf("%s %v", s, err)
	}
	if _, ok, _ := store.Get(ctx, "9in:event:evt_2"); ok {
		t.Fatal("the claim must be released")
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("the panic must continue")
			}
		}()
		_, _ = ProcessEventOnce(ctx, store, "evt_3", func(context.Context) error { panic("oops") })
	}()
	if _, ok, _ := store.Get(ctx, "9in:event:evt_3"); ok {
		t.Fatal("the claim must be released after a panic")
	}
	if s, _ := ProcessEventOnce(ctx, store, "evt_3", func(context.Context) error { return nil }); s != Processed {
		t.Fatalf("retry: %s", s)
	}
}

func TestProcessEventOnceInProgressAndLockExpiry(t *testing.T) {
	store := NewMemoryEventStore()
	c := newClock()
	store.now = c.Now
	d := &EventDeduplicator{Store: store, LockTTL: time.Minute, TTL: time.Hour, Prefix: "p:"}
	started := make(chan struct{})
	release := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = d.Process(ctx, "evt", func(context.Context) error { close(started); <-release; return nil })
	}()
	<-started
	if s, _ := d.Process(ctx, "evt", func(context.Context) error { return nil }); s != InProgress {
		t.Fatalf("concurrent: %s", s)
	}
	// A handler that hangs past the lock: another delivery may take over.
	c.Advance(61 * time.Second)
	var ran atomic.Bool
	if s, _ := d.Process(ctx, "evt", func(context.Context) error { ran.Store(true); return nil }); s != Processed || !ran.Load() {
		t.Fatalf("after the lock expired: %s", s)
	}
	close(release)
	wg.Wait()
	// Done ids are remembered for TTL, then forgotten.
	c.Advance(59 * time.Minute)
	if s, _ := d.Process(ctx, "evt", func(context.Context) error { return nil }); s != Duplicate {
		t.Fatalf("within TTL: %s", s)
	}
	c.Advance(2 * time.Minute)
	if s, _ := d.Process(ctx, "evt", func(context.Context) error { return nil }); s != Processed {
		t.Fatalf("after TTL: %s", s)
	}
}

func TestMemoryEventStore(t *testing.T) {
	s := NewMemoryEventStore()
	c := newClock()
	s.now = c.Now
	if ok, _ := s.Add(ctx, "k", "v", time.Second); !ok {
		t.Fatal("add")
	}
	if ok, _ := s.Add(ctx, "k", "w", time.Second); ok {
		t.Fatal("add must not replace a live key")
	}
	c.Advance(2 * time.Second)
	if ok, _ := s.Add(ctx, "k", "w", time.Second); !ok {
		t.Fatal("an expired key is free")
	}
	_ = s.Set(ctx, "k", "x", time.Minute)
	if v, ok, _ := s.Get(ctx, "k"); !ok || v != "x" {
		t.Fatal("set/get")
	}
	_ = s.Delete(ctx, "k")
	if _, ok, _ := s.Get(ctx, "k"); ok {
		t.Fatal("delete")
	}
	// Many concurrent adds of one key: exactly one wins.
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, _ := s.Add(ctx, "race", "v", time.Minute); ok {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d winners", wins.Load())
	}
}
