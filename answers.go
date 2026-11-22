package nine

import (
	"container/list"
	"context"
	"sync"
	"time"
)

// CachedAnswer is what hybrid verification remembers about a token.
type CachedAnswer struct {
	// Claims are the token's claims, or nil when 9in said it is not active.
	Claims Claims `json:"claims"`
	// Until is when the answer must be asked again.
	Until time.Time `json:"until"`
}

// AnswerCache keeps hybrid verification answers, keyed by a SHA-256 hash of the token.
// The default is in memory, per process ([NewMemoryAnswerCache]). A shared
// implementation (Redis, your database) lets every process see an eviction made by the
// one that received the webhook; it must also find entries by claim for Evict. Methods
// are called concurrently and should not fail: treat a backend error as a miss.
type AnswerCache interface {
	// Get returns the answer for key, if there is one.
	Get(ctx context.Context, key string) (CachedAnswer, bool)
	// Set stores an answer until answer.Until.
	Set(ctx context.Context, key string, answer CachedAnswer)
	// Evict removes every answer whose claims have claim (jti, sid or sub) equal to
	// value, and returns how many it removed.
	Evict(ctx context.Context, claim, value string) int
	// Clear removes every answer.
	Clear(ctx context.Context)
}

// MemoryAnswerCache is an in-memory, least-recently-used AnswerCache for one process.
type MemoryAnswerCache struct {
	mu    sync.Mutex
	size  int
	order *list.List // front: most recently used
	items map[string]*list.Element
	now   func() time.Time
}

type memoryAnswer struct {
	key    string
	answer CachedAnswer
}

// NewMemoryAnswerCache returns an in-memory cache of at most size answers (default 10 000).
func NewMemoryAnswerCache(size int) *MemoryAnswerCache {
	if size <= 0 {
		size = 10000
	}
	return &MemoryAnswerCache{size: size, order: list.New(), items: make(map[string]*list.Element), now: time.Now}
}

// Get implements AnswerCache.
func (c *MemoryAnswerCache) Get(_ context.Context, key string) (CachedAnswer, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		return CachedAnswer{}, false
	}
	entry := el.Value.(*memoryAnswer)
	if !entry.answer.Until.After(c.now()) {
		c.order.Remove(el)
		delete(c.items, key)
		return CachedAnswer{}, false
	}
	c.order.MoveToFront(el)
	return entry.answer, true
}

// Set implements AnswerCache.
func (c *MemoryAnswerCache) Set(_ context.Context, key string, answer CachedAnswer) {
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

// Evict implements AnswerCache.
func (c *MemoryAnswerCache) Evict(_ context.Context, claim, value string) int {
	if value == "" {
		return 0
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
	return evicted
}

// Clear implements AnswerCache.
func (c *MemoryAnswerCache) Clear(context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.order.Init()
	c.items = make(map[string]*list.Element)
}

// Len is the number of answers held (expired ones included until they are looked up).
func (c *MemoryAnswerCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}
