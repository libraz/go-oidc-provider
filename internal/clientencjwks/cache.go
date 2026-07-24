package clientencjwks

import (
	"context"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/remotecache"
	"github.com/libraz/go-oidc-provider/internal/timex"
)

// jwksCache adapts the shared bounded remote cache to parsed JWKS values.
type jwksCache struct {
	inner       *remotecache.Cache[*josev4.JSONWebKeySet]
	clock       timex.Clock
	ttl         time.Duration
	negativeTTL time.Duration
	maxEntries  int
}

// newJWKSCache returns an initialised cache. A nil clock falls back
// to [timex.SystemClock]; a zero or negative ttl falls back to
// [defaultJWKSCacheTTL] so callers that pass the zero
// [Config.JWKSCacheTTL] still observe a sensible expiry.
func newJWKSCache(clock timex.Clock, ttl, negativeTTL time.Duration, maxEntries int) *jwksCache {
	if clock == nil {
		clock = timex.SystemClock
	}
	if ttl <= 0 {
		ttl = defaultJWKSCacheTTL
	}
	if negativeTTL <= 0 {
		negativeTTL = defaultJWKSNegativeCacheTTL
	}
	if maxEntries <= 0 {
		maxEntries = defaultJWKSCacheMaxEntries
	}
	return &jwksCache{
		inner: remotecache.New[*josev4.JSONWebKeySet](remotecache.Config{
			Clock:       clock,
			TTL:         ttl,
			NegativeTTL: negativeTTL,
			MaxEntries:  maxEntries,
		}),
		clock:       clock,
		ttl:         ttl,
		negativeTTL: negativeTTL,
		maxEntries:  maxEntries,
	}
}

// get returns the cached entry for url if it is still within its
// TTL. A cache miss or expired entry returns (nil, false) so the
// caller falls back to the network fetch.
func (c *jwksCache) get(url string) (*josev4.JSONWebKeySet, bool) {
	keys, ok, err := c.inner.Get(url)
	return keys, ok && err == nil
}

// put records keys against url. The entry expires after the cache's
// configured TTL relative to the resolver's clock; subsequent put
// calls overwrite the previous entry verbatim.
func (c *jwksCache) put(url string, keys *josev4.JSONWebKeySet) {
	c.inner.Put(url, keys)
}

func (c *jwksCache) load(
	ctx context.Context,
	url string,
	loader func(context.Context) (*josev4.JSONWebKeySet, error),
) (*josev4.JSONWebKeySet, error) {
	return c.inner.Load(ctx, url, func(ctx context.Context, _ *josev4.JSONWebKeySet, _ bool) (*josev4.JSONWebKeySet, error) {
		return loader(ctx)
	})
}

func (c *jwksCache) len() int {
	return c.inner.Len()
}
