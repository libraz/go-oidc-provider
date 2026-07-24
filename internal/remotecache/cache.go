// Package remotecache provides the bounded in-process cache primitive used by
// remote, client-controlled URL resolvers. Protocol-specific fetch and
// validation stay at the call site; this package owns only TTL/LRU accounting,
// expired-entry removal, per-key singleflight, and short negative caching.
//
//nolint:ireturn // Generic cache methods intentionally return the caller-selected concrete V.
package remotecache

import (
	"container/list"
	"context"
	"errors"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/libraz/go-oidc-provider/internal/timex"
)

const (
	// DefaultMaxEntries bounds URL cardinality when a caller does not provide
	// an explicit deployment budget.
	DefaultMaxEntries = 256

	// DefaultNegativeTTL collapses bursts against a failing upstream without
	// delaying recovery for more than a few seconds.
	DefaultNegativeTTL = 5 * time.Second

	defaultTTL = 5 * time.Minute
)

var errUnexpectedResult = errors.New("remotecache: singleflight returned an unexpected result")

// Config defines one cache's resource budget. Zero and negative values select
// safe defaults; they never disable the bound or expiry.
type Config struct {
	Clock       timex.Clock
	TTL         time.Duration
	NegativeTTL time.Duration
	MaxEntries  int

	// ShouldCacheError may exclude protocol signals that should be observable
	// once but retried immediately. nil caches every non-context loader error.
	ShouldCacheError func(error) bool
}

// Loader fetches a value for key. When an expired positive entry existed,
// stale and hasStale let the protocol layer perform change detection without
// retaining the expired entry in the cache map.
type Loader[V any] func(ctx context.Context, stale V, hasStale bool) (V, error)

// Cache is a concurrency-safe, size-bounded TTL/LRU cache. Positive and
// negative entries share one cardinality budget.
type Cache[V any] struct {
	mu      sync.Mutex
	entries map[string]*entry[V]
	lru     *list.List
	clock   timex.Clock

	ttl              time.Duration
	negativeTTL      time.Duration
	maxEntries       int
	shouldCacheError func(error) bool
	flight           singleflight.Group
}

type entry[V any] struct {
	key      string
	value    V
	err      error
	negative bool
	hasStale bool
	expiry   time.Time
	element  *list.Element
}

type loadResult[V any] struct {
	value V
	err   error
}

type probeResult[V any] struct {
	value V
	err   error
	ok    bool
}

type staleResult[V any] struct {
	value V
	ok    bool
}

// New returns a ready-to-use cache. The zero Config uses bounded production
// defaults.
func New[V any](cfg Config) *Cache[V] {
	if cfg.Clock == nil {
		cfg.Clock = timex.SystemClock
	}
	if cfg.TTL <= 0 {
		cfg.TTL = defaultTTL
	}
	if cfg.NegativeTTL <= 0 {
		cfg.NegativeTTL = DefaultNegativeTTL
	}
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = DefaultMaxEntries
	}
	return &Cache[V]{
		entries:          make(map[string]*entry[V]),
		lru:              list.New(),
		clock:            cfg.Clock,
		ttl:              cfg.TTL,
		negativeTTL:      cfg.NegativeTTL,
		maxEntries:       cfg.MaxEntries,
		shouldCacheError: cfg.ShouldCacheError,
	}
}

// Load returns a fresh cached value or invokes loader. Concurrent misses for
// the same key share one loader call.
func (c *Cache[V]) Load(ctx context.Context, key string, loader Loader[V]) (V, error) {
	if cached := c.getFresh(key); cached.ok {
		return cached.value, cached.err
	}

	raw, _, _ := c.flight.Do(key, func() (any, error) {
		if cached := c.getFresh(key); cached.ok {
			return loadResult[V]{value: cached.value, err: cached.err}, nil
		}
		stale := c.removeExpired(key)
		value, err := loader(ctx, stale.value, stale.ok)
		if err != nil {
			if c.cacheableError(err) {
				c.putNegative(key, err, stale.value, stale.ok)
			}
			return loadResult[V]{err: err}, nil
		}
		c.putPositive(key, value)
		return loadResult[V]{value: value}, nil
	})
	result, ok := raw.(loadResult[V])
	if !ok {
		var zero V
		return zero, errUnexpectedResult
	}
	return result.value, result.err
}

// Get returns a fresh positive value. Negative entries return their cached
// error; expired entries are physically removed.
func (c *Cache[V]) Get(key string) (V, bool, error) {
	if cached := c.getFresh(key); cached.ok {
		return cached.value, true, cached.err
	}
	c.removeExpired(key)
	var zero V
	return zero, false, nil
}

// Put stores a positive value using the configured positive TTL.
func (c *Cache[V]) Put(key string, value V) {
	c.putPositive(key, value)
}

// Delete removes key from both the map and LRU list.
func (c *Cache[V]) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deleteLocked(key)
}

// Len returns the number of retained positive and negative entries after
// pruning all expired entries.
func (c *Cache[V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneExpiredLocked(c.clock.Now())
	return len(c.entries)
}

func (c *Cache[V]) getFresh(key string) probeResult[V] {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok || !c.clock.Now().Before(e.expiry) {
		return probeResult[V]{}
	}
	c.lru.MoveToFront(e.element)
	return probeResult[V]{value: e.value, err: e.err, ok: true}
}

func (c *Cache[V]) removeExpired(key string) staleResult[V] {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok || c.clock.Now().Before(e.expiry) {
		return staleResult[V]{}
	}
	hasStale := !e.negative || e.hasStale
	c.deleteEntryLocked(e)
	return staleResult[V]{value: e.value, ok: hasStale}
}

func (c *Cache[V]) putPositive(key string, value V) {
	c.put(key, value, nil, false, false, c.ttl)
}

func (c *Cache[V]) putNegative(key string, err error, stale V, hasStale bool) {
	c.put(key, stale, err, true, hasStale, c.negativeTTL)
}

func (c *Cache[V]) put(key string, value V, err error, negative, hasStale bool, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.clock.Now()
	c.pruneExpiredLocked(now)
	c.deleteLocked(key)
	for len(c.entries) >= c.maxEntries {
		oldest := c.lru.Back()
		if oldest == nil {
			break
		}
		c.deleteEntryLocked(oldest.Value.(*entry[V]))
	}
	e := &entry[V]{
		key:      key,
		value:    value,
		err:      err,
		negative: negative,
		hasStale: hasStale,
		expiry:   now.Add(ttl),
	}
	e.element = c.lru.PushFront(e)
	c.entries[key] = e
}

func (c *Cache[V]) cacheableError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	return c.shouldCacheError == nil || c.shouldCacheError(err)
}

func (c *Cache[V]) pruneExpiredLocked(now time.Time) {
	for key, e := range c.entries {
		if !now.Before(e.expiry) {
			c.deleteLocked(key)
		}
	}
}

func (c *Cache[V]) deleteLocked(key string) {
	if e, ok := c.entries[key]; ok {
		c.deleteEntryLocked(e)
	}
}

func (c *Cache[V]) deleteEntryLocked(e *entry[V]) {
	delete(c.entries, e.key)
	c.lru.Remove(e.element)
}
