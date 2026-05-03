package clientencjwks

import (
	"sync"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/timex"
)

// jwksCache is a small TTL cache for parsed [josev4.JSONWebKeySet]
// values keyed by the source URL. Entries expire after the TTL the
// resolver was constructed with; there is no LRU eviction.
//
// A fresh keyset is fetched on every miss. The cache is intentionally
// conservative: an OP serves a finite number of clients, so the
// memory budget is bounded by the registered RP count rather than by
// arbitrary growth, and entries are reclaimed lazily when their
// expiry passes (the entry stays in the map but a [get] hit returns
// false, so the next [put] overwrites it).
//
// Concurrency: every read and write goes through the [sync.RWMutex];
// the cache is safe for use from multiple goroutines.
type jwksCache struct {
	mu      sync.RWMutex
	entries map[string]*jwksEntry
	clock   timex.Clock
	ttl     time.Duration
}

// jwksEntry is the stored projection of one keyset. Expiry is
// computed at put time and compared against the resolver's clock on
// every get; the parsed shape ([*josev4.JSONWebKeySet]) lives in
// memory verbatim so the resolver does not re-parse on cache hits.
type jwksEntry struct {
	keys   *josev4.JSONWebKeySet
	expiry time.Time
}

// newJWKSCache returns an initialised cache. A nil clock falls back
// to [timex.SystemClock]; a zero or negative ttl falls back to
// [defaultJWKSCacheTTL] so callers that pass the zero
// [Config.JWKSCacheTTL] still observe a sensible expiry.
func newJWKSCache(clock timex.Clock, ttl time.Duration) *jwksCache {
	if clock == nil {
		clock = timex.SystemClock
	}
	if ttl <= 0 {
		ttl = defaultJWKSCacheTTL
	}
	return &jwksCache{
		entries: make(map[string]*jwksEntry),
		clock:   clock,
		ttl:     ttl,
	}
}

// get returns the cached entry for url if it is still within its
// TTL. A cache miss or expired entry returns (nil, false) so the
// caller falls back to the network fetch.
func (c *jwksCache) get(url string) (*josev4.JSONWebKeySet, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[url]
	if !ok {
		return nil, false
	}
	if c.clock.Now().Before(e.expiry) {
		return e.keys, true
	}
	return nil, false
}

// put records keys against url. The entry expires after the cache's
// configured TTL relative to the resolver's clock; subsequent put
// calls overwrite the previous entry verbatim.
func (c *jwksCache) put(url string, keys *josev4.JSONWebKeySet) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[url] = &jwksEntry{
		keys:   keys,
		expiry: c.clock.Now().Add(c.ttl),
	}
}
