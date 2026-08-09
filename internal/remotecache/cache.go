// Package remotecache provides the bounded in-process cache primitive used by
// remote, client-controlled URL resolvers. Protocol-specific fetch and
// validation stay at the call site; this package owns only TTL/LRU accounting,
// expired-entry removal, per-key singleflight, short negative caching, and the
// forced-refresh entry point a protocol layer needs when the cached value is
// fresh but demonstrably out of date.
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

	// refreshFlightSuffix separates a forced refresh's singleflight key from
	// the plain load's. The NUL byte cannot occur in a URL, so no key can
	// collide with another key's refresh flight.
	refreshFlightSuffix = "\x00refresh"
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

// TTLLoader is a [Loader] whose upstream advertises its own freshness lifetime
// (an HTTP Cache-Control max-age, say). A non-positive TTL selects the cache's
// configured [Config.TTL], so a loader that has nothing to advertise simply
// returns zero.
type TTLLoader[V any] func(ctx context.Context, stale V, hasStale bool) (V, time.Duration, error)

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
// the same key share one loader call. Entries stored through Load expire after
// the configured [Config.TTL].
func (c *Cache[V]) Load(ctx context.Context, key string, loader Loader[V]) (V, error) {
	return c.LoadTTL(ctx, key, func(ctx context.Context, stale V, hasStale bool) (V, time.Duration, error) {
		value, err := loader(ctx, stale, hasStale)
		return value, 0, err
	})
}

// LoadTTL is [Cache.Load] for an upstream that advertises its own freshness
// lifetime; the loader's TTL replaces [Config.TTL] for the entry it produces.
func (c *Cache[V]) LoadTTL(ctx context.Context, key string, loader TTLLoader[V]) (V, error) {
	if cached := c.getFresh(key); cached.ok {
		return cached.value, cached.err
	}

	return c.await(ctx, c.flight.DoChan(key, func() (any, error) {
		// Re-check inside the singleflight so a concurrent winner that
		// completed between the probe above and the call here does not force a
		// redundant load.
		if cached := c.getFresh(key); cached.ok {
			return loadResult[V]{value: cached.value, err: cached.err}, nil
		}
		stale := c.removeExpired(key)
		value, ttl, err := loader(ctx, stale.value, stale.ok)
		if err != nil {
			if c.cacheableError(err) {
				c.putNegative(key, err, stale.value, stale.ok)
			}
			return loadResult[V]{err: err}, nil
		}
		c.putPositive(key, value, ttl)
		return loadResult[V]{value: value}, nil
	}))
}

// RefreshTTL invokes loader even when a fresh entry exists, so a protocol layer
// can recover from an upstream rotation it can already prove happened (a
// signature naming a key id the cached value does not contain) without waiting
// out the TTL. The currently stored value is handed to the loader for change
// detection.
//
// A failed refresh leaves an existing value in place instead of replacing it
// with a negative entry. The refresh is triggered by an unrecognised identifier,
// which any peer can supply at will; caching the failure would let that peer
// discard a value the cache holds and is still serving correctly. Only a key
// that holds no usable value takes a negative entry, which is the same outcome
// a plain [Cache.LoadTTL] would have produced there.
//
// The refresh runs under its own singleflight key so it never collapses onto a
// concurrent [Cache.LoadTTL], whose inner re-check would hand back the very
// entry the refresh exists to replace.
func (c *Cache[V]) RefreshTTL(ctx context.Context, key string, loader TTLLoader[V]) (V, error) {
	return c.await(ctx, c.flight.DoChan(key+refreshFlightSuffix, func() (any, error) {
		current := c.peek(key)
		value, ttl, err := loader(ctx, current.value, current.ok)
		if err != nil {
			if !current.ok && c.cacheableError(err) {
				var zero V
				c.putNegative(key, err, zero, false)
			}
			return loadResult[V]{err: err}, nil
		}
		c.putPositive(key, value, ttl)
		return loadResult[V]{value: value}, nil
	}))
}

// await blocks on a singleflight result while still honouring the caller's
// context. A caller that gives up abandons only its own wait: the loader keeps
// running and its result lands in the cache for the next caller, so a peer that
// hangs up mid-load neither stalls nor poisons the key for everyone collapsed
// onto the same flight. The channel singleflight returns is buffered, so the
// abandoned send does not leak a goroutine.
func (c *Cache[V]) await(ctx context.Context, ch <-chan singleflight.Result) (V, error) {
	var zero V
	select {
	case <-ctx.Done():
		return zero, ctx.Err()
	case raw := <-ch:
		if raw.Err != nil {
			return zero, raw.Err
		}
		result, ok := raw.Val.(loadResult[V])
		if !ok {
			return zero, errUnexpectedResult
		}
		return result.value, result.err
	}
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

// PeekFresh returns the value stored under key when it is a positive entry
// still inside its TTL. Unlike [Cache.Get] it touches nothing: the LRU ordering
// is unchanged and an expired entry is left in place, so a caller deciding
// whether to force a refresh does not destroy the change-detection state that
// refresh is about to use.
func (c *Cache[V]) PeekFresh(key string) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok || e.negative || !c.clock.Now().Before(e.expiry) {
		var zero V
		return zero, false
	}
	return e.value, true
}

// Put stores a positive value using the configured positive TTL.
func (c *Cache[V]) Put(key string, value V) {
	c.putPositive(key, value, 0)
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

// peek returns the value currently stored under key without touching the LRU
// ordering and without removing anything. The boolean reports whether the entry
// carries a usable prior value: a positive entry always does, a negative entry
// only when it retained the value it replaced.
func (c *Cache[V]) peek(key string) staleResult[V] {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return staleResult[V]{}
	}
	return staleResult[V]{value: e.value, ok: !e.negative || e.hasStale}
}

func (c *Cache[V]) putPositive(key string, value V, ttl time.Duration) {
	if ttl <= 0 {
		ttl = c.ttl
	}
	c.put(key, value, nil, false, false, ttl)
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
