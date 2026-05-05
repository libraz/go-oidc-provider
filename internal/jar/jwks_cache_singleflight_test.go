// White-box tests for the singleflight + negative-cache plumbing in
// the JWKS fetcher. Living in the same package keeps the tests next
// to the unexported helpers they exercise.
//
//nolint:testpackage // intentional white-box test for unexported helpers.
package jar

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/timex"
)

// TestJWKSCache_SingleflightCollapsesConcurrentFetches drives N
// goroutines at the same fresh JWKs URL and confirms the upstream
// only saw one round-trip. The check is the structural defence
// against a hostile RP that drives /authorize with the same JAR N
// times to amplify outbound traffic at the OP.
func TestJWKSCache_SingleflightCollapsesConcurrentFetches(t *testing.T) {
	t.Parallel()

	hits := &atomic.Int32{}
	gate := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		<-gate // hold the request open so concurrent fetches collapse
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(jwksJSON))
	}))
	defer srv.Close()

	f := NewFetcher(timex.SystemClock)
	f.SetAllowPrivate(true)

	const concurrent = 16
	var (
		wg     sync.WaitGroup
		errs   = make(chan error, concurrent)
		ctx    = context.Background()
		ready  = make(chan struct{})
		launch sync.Once
	)
	for range concurrent {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Wait for the launch signal so all goroutines pile in
			// at the same time.
			<-ready
			_, err := f.Fetch(ctx, srv.URL)
			errs <- err
		}()
	}
	launch.Do(func() { close(ready) })
	// Give all goroutines a chance to register; then release the
	// upstream so the singleflight winner can complete.
	time.Sleep(50 * time.Millisecond)
	close(gate)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("fetch returned %v; want nil", err)
		}
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("upstream hits=%d; want 1 (singleflight should collapse %d concurrent fetches)", got, concurrent)
	}
}

// TestJWKSCache_NegativeCacheShortCircuits drives a fetch against a
// 500-returning upstream and confirms the second fetch within the
// negative-cache window short-circuits without re-issuing the
// network round-trip. The check is the amplification-DoS defence:
// without it, an attacker who replays a JAR naming an unreachable
// URL would force one outbound socket per inbound request.
func TestJWKSCache_NegativeCacheShortCircuits(t *testing.T) {
	t.Parallel()

	hits := &atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	f := NewFetcher(timex.SystemClock)
	f.SetAllowPrivate(true)
	ctx := context.Background()

	if _, err := f.Fetch(ctx, srv.URL); !errors.Is(err, ErrJWKSFetch) {
		t.Fatalf("first fetch err=%v want ErrJWKSFetch", err)
	}
	first := hits.Load()
	if first != 1 {
		t.Fatalf("first fetch hits=%d want 1", first)
	}
	// Second fetch within the negative-cache window MUST NOT hit the
	// upstream.
	if _, err := f.Fetch(ctx, srv.URL); !errors.Is(err, ErrJWKSFetch) {
		t.Fatalf("second fetch err=%v want ErrJWKSFetch", err)
	}
	if got := hits.Load(); got != first {
		t.Fatalf("upstream hits=%d after second fetch; want %d (negative cache should short-circuit)", got, first)
	}
}

// TestJWKSCache_NegativeCacheClearsOnSuccess confirms a successful
// fetch clears any previously-cached negative entry so an upstream
// that recovers does not stay broken until the negative TTL expires.
func TestJWKSCache_NegativeCacheClearsOnSuccess(t *testing.T) {
	t.Parallel()

	var fail atomic.Bool
	fail.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(jwksJSON))
	}))
	defer srv.Close()

	clock := &movableClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	f := NewFetcher(clock)
	f.SetAllowPrivate(true)
	ctx := context.Background()

	if _, err := f.Fetch(ctx, srv.URL); !errors.Is(err, ErrJWKSFetch) {
		t.Fatalf("first fetch err=%v want ErrJWKSFetch", err)
	}
	// Roll the clock past the negative TTL so a second fetch retries
	// the upstream rather than short-circuiting.
	clock.now = clock.now.Add(2 * defaultJWKSNegativeTTL)
	fail.Store(false)
	if _, err := f.Fetch(ctx, srv.URL); err != nil {
		t.Fatalf("second fetch err=%v; want nil after upstream recovery", err)
	}
	// Third fetch should hit the positive cache.
	if _, err := f.Fetch(ctx, srv.URL); err != nil {
		t.Fatalf("third fetch err=%v; want nil", err)
	}
}
