// White-box tests against the package-private cache. Living in the
// same package avoids exporting the cache solely so tests can reach
// it.
//
//nolint:testpackage // intentional white-box test for unexported helpers.
package clientencjwks

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
)

// movableClock is a [timex.Clock] whose Now reading callers can
// shift. Tests use it to drive the cache's TTL expiry without
// sleeping.
type movableClock struct {
	now time.Time
}

func (m *movableClock) Now() time.Time { return m.now }

var _ timex.Clock = (*movableClock)(nil)

// fakeJWKS returns a single-entry JWKS suitable for cache tests. The
// content of the key does not matter; only the pointer identity does
// because the cache returns whatever was stored verbatim.
func fakeJWKS(t *testing.T) *josev4.JSONWebKeySet {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return &josev4.JSONWebKeySet{
		Keys: []josev4.JSONWebKey{{
			Key:   &priv.PublicKey,
			KeyID: "k1",
			Use:   "enc",
		}},
	}
}

func TestJWKSCache_HitWithinTTL(t *testing.T) {
	t.Parallel()

	clock := &movableClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}
	c := newJWKSCache(clock, 60*time.Second, 0, 0)

	keys := fakeJWKS(t)
	c.put("https://rp.example/jwks", keys)

	clock.now = clock.now.Add(30 * time.Second)
	got, ok := c.get("https://rp.example/jwks")
	if !ok {
		t.Fatal("get returned ok=false within TTL")
	}
	if got != keys {
		t.Errorf("get returned different pointer; want cached value")
	}
}

func TestJWKSCache_MissAfterTTL(t *testing.T) {
	t.Parallel()

	clock := &movableClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}
	c := newJWKSCache(clock, 60*time.Second, 0, 0)

	c.put("https://rp.example/jwks", fakeJWKS(t))

	// Step past the TTL boundary.
	clock.now = clock.now.Add(120 * time.Second)
	if _, ok := c.get("https://rp.example/jwks"); ok {
		t.Fatal("get returned ok=true after TTL expired")
	}
}

func TestJWKSCache_MissOnUnknownURL(t *testing.T) {
	t.Parallel()

	c := newJWKSCache(timex.SystemClock, time.Minute, 0, 0)
	if _, ok := c.get("https://other.example/jwks"); ok {
		t.Fatal("get returned ok=true for unknown URL")
	}
}

func TestJWKSCache_PutOverwrites(t *testing.T) {
	t.Parallel()

	clock := &movableClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}
	c := newJWKSCache(clock, 60*time.Second, 0, 0)

	first := fakeJWKS(t)
	second := fakeJWKS(t)
	c.put("https://rp.example/jwks", first)
	c.put("https://rp.example/jwks", second)

	got, ok := c.get("https://rp.example/jwks")
	if !ok {
		t.Fatal("get returned ok=false after put")
	}
	if got != second {
		t.Errorf("get returned the first put; want the second (overwrite)")
	}
}

func TestJWKSCache_NilClockFallsBackToSystem(t *testing.T) {
	t.Parallel()

	c := newJWKSCache(nil, time.Minute, 0, 0)
	if c.clock == nil {
		t.Fatal("clock is nil after nil-clock construction")
	}
}

func TestJWKSCache_ZeroTTLFallsBackToDefault(t *testing.T) {
	t.Parallel()

	c := newJWKSCache(timex.SystemClock, 0, 0, 0)
	if c.ttl != defaultJWKSCacheTTL {
		t.Errorf("ttl=%v want defaultJWKSCacheTTL=%v", c.ttl, defaultJWKSCacheTTL)
	}
	if c.negativeTTL != defaultJWKSNegativeCacheTTL {
		t.Errorf("negativeTTL=%v want default=%v", c.negativeTTL, defaultJWKSNegativeCacheTTL)
	}
	if c.maxEntries != defaultJWKSCacheMaxEntries {
		t.Errorf("maxEntries=%d want default=%d", c.maxEntries, defaultJWKSCacheMaxEntries)
	}
}

func TestResolverCache_CardinalityStaysBounded(t *testing.T) {
	t.Parallel()

	body, err := json.Marshal(fakeJWKS(t))
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	r := New(Config{AllowPrivateNetwork: true, JWKSCacheMaxEntries: 4})

	for i := range 40 {
		client := &store.Client{JWKsURI: fmt.Sprintf("%s?client=%d", srv.URL, i)}
		if _, err := r.resolveJWKS(context.Background(), client); err != nil {
			t.Fatalf("resolveJWKS(%d): %v", i, err)
		}
		if got := r.cache.len(); got > 4 {
			t.Fatalf("cache entries=%d exceeds max=4 after URL %d", got, i)
		}
	}
}

func TestResolverCache_ExpiredEntryIsEvicted(t *testing.T) {
	t.Parallel()

	body, err := json.Marshal(fakeJWKS(t))
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	clock := &movableClock{now: time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)}
	r := New(Config{
		Clock:               clock,
		JWKSCacheTTL:        time.Minute,
		AllowPrivateNetwork: true,
	})
	if _, err := r.resolveJWKS(context.Background(), &store.Client{JWKsURI: srv.URL}); err != nil {
		t.Fatalf("resolveJWKS: %v", err)
	}
	clock.now = clock.now.Add(2 * time.Minute)
	if got := r.cache.len(); got != 0 {
		t.Fatalf("cache entries=%d want 0 after TTL expiry", got)
	}
}

func TestResolverCache_SingleflightCollapsesConcurrentFetches(t *testing.T) {
	t.Parallel()

	body, err := json.Marshal(fakeJWKS(t))
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var hits atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) == 1 {
			close(entered)
		}
		<-release
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	r := New(Config{AllowPrivateNetwork: true})
	client := &store.Client{JWKsURI: srv.URL}

	const concurrent = 24
	start := make(chan struct{})
	errs := make(chan error, concurrent)
	var wg sync.WaitGroup
	for range concurrent {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := r.resolveJWKS(context.Background(), client)
			errs <- err
		}()
	}
	close(start)
	<-entered
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("resolveJWKS: %v", err)
		}
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("upstream hits=%d want 1", got)
	}
}

func TestResolverCache_NegativeCacheRecoversAfterTTL(t *testing.T) {
	t.Parallel()

	body, err := json.Marshal(fakeJWKS(t))
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var (
		hits atomic.Int32
		fail atomic.Bool
	)
	fail.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		if fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	clock := &movableClock{now: time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)}
	r := New(Config{
		Clock:                clock,
		JWKSNegativeCacheTTL: 5 * time.Second,
		AllowPrivateNetwork:  true,
	})
	client := &store.Client{JWKsURI: srv.URL}

	if _, err := r.resolveJWKS(context.Background(), client); !errors.Is(err, ErrJWKSFetch) {
		t.Fatalf("first resolveJWKS err=%v want ErrJWKSFetch", err)
	}
	if _, err := r.resolveJWKS(context.Background(), client); !errors.Is(err, ErrJWKSFetch) {
		t.Fatalf("negative-cache resolveJWKS err=%v want ErrJWKSFetch", err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("upstream hits=%d want 1 inside negative TTL", got)
	}

	clock.now = clock.now.Add(6 * time.Second)
	fail.Store(false)
	if _, err := r.resolveJWKS(context.Background(), client); err != nil {
		t.Fatalf("recovery resolveJWKS: %v", err)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("upstream hits=%d want 2 after negative TTL", got)
	}
}
