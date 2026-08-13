//nolint:testpackage // intentional white-box test for the cache and throttle state.
package rpjwks

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/timex"
)

// errSentinel stands in for a calling package's own fetch sentinel, so the
// tests exercise the same wrapping contract jar and clientencjwks rely on.
var errSentinel = errors.New("test: jwks fetch failed")

// movableClock is a [timex.Clock] whose Now reading callers can shift. Tests
// use it to drive TTL expiry and the forced-refresh throttle without sleeping.
type movableClock struct {
	now time.Time
}

func (m *movableClock) Now() time.Time { return m.now }

var _ timex.Clock = (*movableClock)(nil)

func testClock() *movableClock {
	return &movableClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
}

// newTestFetcher returns a fetcher pointed at loopback-hosted test servers.
func newTestFetcher(t *testing.T, cfg Config) *Fetcher {
	t.Helper()
	cfg.FetchError = errSentinel
	cfg.AllowPrivateNetwork = true // httptest binds to 127.0.0.1.
	return New(cfg)
}

// jwksHandler serves jwksJSON with the configured Cache-Control / ETag headers
// and counts the requests that reached it, so cache tests can assert which
// fetches went to the network.
func jwksHandler(cacheControl, etag string, hits *atomic.Int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if etag != "" && r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		if cacheControl != "" {
			w.Header().Set("Cache-Control", cacheControl)
		}
		if etag != "" {
			w.Header().Set("ETag", etag)
		}
		_, _ = w.Write([]byte(jwksJSON))
	})
}

// TestFetch_AdvertisedFreshnessMayOnlyShorten pins the one direction an RP is
// allowed to move the cache lifetime in. A max-age below the configured TTL is
// honoured, because an RP asking to be refetched sooner costs the OP nothing;
// the opposite direction is the security-relevant one and is covered by
// [TestFetch_AdvertisedFreshnessCannotOutliveTheConfiguredTTL].
func TestFetch_AdvertisedFreshnessMayOnlyShorten(t *testing.T) {
	t.Parallel()

	hits := &atomic.Int32{}
	srv := httptest.NewServer(jwksHandler("max-age=30", "", hits))
	defer srv.Close()

	clock := testClock()
	f := newTestFetcher(t, Config{Clock: clock, TTL: 10 * time.Minute})
	if _, err := f.Fetch(context.Background(), srv.URL); err != nil {
		t.Fatalf("fetch 1: %v", err)
	}
	clock.now = clock.now.Add(15 * time.Second)
	if _, err := f.Fetch(context.Background(), srv.URL); err != nil {
		t.Fatalf("fetch 2: %v", err)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("hits=%d want 1 inside the advertised freshness", got)
	}
	clock.now = clock.now.Add(16 * time.Second)
	if _, err := f.Fetch(context.Background(), srv.URL); err != nil {
		t.Fatalf("fetch 3: %v", err)
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("hits=%d want 2; the shorter advertised freshness was ignored", got)
	}
}

// TestFetch_AdvertisedFreshnessCannotOutliveTheConfiguredTTL is the other
// direction: the Cache-Control header is written by the relying party, so
// letting it extend the entry would hand an RP the power to decide how long the
// OP keeps trusting a key. An RP advertising a year would keep a leaked or
// withdrawn key usable for that year, with no operator-visible signal and no
// forced refetch short of restarting the process.
func TestFetch_AdvertisedFreshnessCannotOutliveTheConfiguredTTL(t *testing.T) {
	t.Parallel()

	hits := &atomic.Int32{}
	srv := httptest.NewServer(jwksHandler("max-age=31536000", "", hits))
	defer srv.Close()

	clock := testClock()
	f := newTestFetcher(t, Config{Clock: clock, TTL: time.Minute})
	if _, err := f.Fetch(context.Background(), srv.URL); err != nil {
		t.Fatalf("fetch 1: %v", err)
	}
	clock.now = clock.now.Add(30 * time.Second)
	if _, err := f.Fetch(context.Background(), srv.URL); err != nil {
		t.Fatalf("fetch 2: %v", err)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("hits=%d want 1 inside the configured TTL", got)
	}
	clock.now = clock.now.Add(31 * time.Second)
	if _, err := f.Fetch(context.Background(), srv.URL); err != nil {
		t.Fatalf("fetch 3: %v", err)
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("hits=%d want 2; a year of advertised max-age outlived the configured TTL", got)
	}
}

// TestFetch_WithdrawnKeyStopsBeingServedWithinTheConfiguredTTL states the
// consequence the clamp exists for, in the vocabulary of the callers. An RP
// that removes a key from its JWKS — after a leak, say — must stop being able
// to authenticate with it, and every caller that resolves a jwks_uri
// (client-assertion verification, request-object verification, outbound JWE)
// reads the same cached keyset this test observes. The withdrawn key must be
// gone within one configured TTL no matter what the RP advertised.
func TestFetch_WithdrawnKeyStopsBeingServedWithinTheConfiguredTTL(t *testing.T) {
	t.Parallel()

	withdrawn := &atomic.Bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		w.Header().Set("Cache-Control", "max-age=31536000")
		kid := "k1"
		if withdrawn.Load() {
			kid = "k2"
		}
		_, _ = w.Write([]byte(`{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","kid":"` + kid + `"}]}`))
	}))
	defer srv.Close()

	clock := testClock()
	f := newTestFetcher(t, Config{Clock: clock, TTL: time.Minute})
	keys, err := f.Fetch(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("prime fetch: %v", err)
	}
	if len(keys.Keys) != 1 || keys.Keys[0].KeyID != "k1" {
		t.Fatalf("prime fetch returned kids %v, want [k1]", keyIDs(keys))
	}

	withdrawn.Store(true)
	clock.now = clock.now.Add(time.Minute + time.Second)
	keys, err = f.Fetch(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("fetch after the TTL elapsed: %v", err)
	}
	for _, kid := range keyIDs(keys) {
		if kid == "k1" {
			t.Fatalf("withdrawn kid k1 still served past the configured TTL; kids=%v", keyIDs(keys))
		}
	}
	if len(keys.Keys) != 1 || keys.Keys[0].KeyID != "k2" {
		t.Fatalf("fetch after the TTL returned kids %v, want [k2]", keyIDs(keys))
	}
}

// TestFetch_ConfiguredTTLAppliesWithoutCacheControl pins that an upstream
// advertising nothing leaves the caller's configured TTL in force, rather than
// silently swapping in the package default.
func TestFetch_ConfiguredTTLAppliesWithoutCacheControl(t *testing.T) {
	t.Parallel()

	hits := &atomic.Int32{}
	srv := httptest.NewServer(jwksHandler("", "", hits))
	defer srv.Close()

	clock := testClock()
	f := newTestFetcher(t, Config{Clock: clock, TTL: time.Minute})
	if _, err := f.Fetch(context.Background(), srv.URL); err != nil {
		t.Fatalf("fetch 1: %v", err)
	}
	clock.now = clock.now.Add(2 * time.Minute)
	if _, err := f.Fetch(context.Background(), srv.URL); err != nil {
		t.Fatalf("fetch 2: %v", err)
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("hits=%d want 2 after the configured TTL elapsed", got)
	}
}

func TestFetch_RevalidatesViaETag(t *testing.T) {
	t.Parallel()

	hits := &atomic.Int32{}
	srv := httptest.NewServer(jwksHandler("max-age=10", `"abc"`, hits))
	defer srv.Close()

	clock := testClock()
	f := newTestFetcher(t, Config{Clock: clock})
	if _, err := f.Fetch(context.Background(), srv.URL); err != nil {
		t.Fatalf("fetch 1: %v", err)
	}
	// Move past the advertised freshness so the next fetch revalidates.
	clock.now = clock.now.Add(time.Hour)
	keys, err := f.Fetch(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("fetch 2: %v", err)
	}
	if len(keys.Keys) != 1 || keys.Keys[0].KeyID != "k1" {
		t.Fatalf("revalidated fetch returned kids %v, want [k1]", keyIDs(keys))
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("hits=%d want 2 (one full + one conditional)", got)
	}
}

// TestFetch_KeepsSupportedKeyBesideUnsupportedOne pins RFC 7517 §5 on the
// fetched path, not just the parser: an RP publishing a key type this build
// cannot represent next to its signing key stays verifiable.
func TestFetch_KeepsSupportedKeyBesideUnsupportedOne(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write([]byte(`{"keys":[` + unsupportedMemberJWK + `,` + ecMemberJWK + `]}`))
	}))
	defer srv.Close()

	f := newTestFetcher(t, Config{})
	keys, err := f.Fetch(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(keys.Keys) != 1 || keys.Keys[0].KeyID != "k1" {
		t.Fatalf("Fetch returned kids %v, want [k1]", keyIDs(keys))
	}
}

func TestFetch_RejectsOversizeBody(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"keys":[`)
		_, _ = fmt.Fprint(w, strings.Repeat("X", 4096))
		_, _ = fmt.Fprint(w, `]}`)
	}))
	defer srv.Close()

	f := newTestFetcher(t, Config{MaxBodyBytes: 128})
	_, err := f.Fetch(context.Background(), srv.URL)
	if !errors.Is(err, errSentinel) {
		t.Fatalf("err=%v want the configured sentinel", err)
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("err=%v want a descriptive 'exceeds' wrap", err)
	}
}

// TestFetch_RejectsExcessiveKeyCountOverTheWire pins that the member cap
// applies to a fetched document, so a keyset small enough to pass the body cap
// still cannot force an unbounded parse.
func TestFetch_RejectsExcessiveKeyCountOverTheWire(t *testing.T) {
	t.Parallel()

	body := `{"keys":[` + strings.Repeat(`{"kty":"EC"},`, MaxKeys) + `{"kty":"EC"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	f := newTestFetcher(t, Config{})
	_, err := f.Fetch(context.Background(), srv.URL)
	if !errors.Is(err, errSentinel) {
		t.Fatalf("err=%v want the configured sentinel", err)
	}
	if !strings.Contains(err.Error(), "limit") {
		t.Errorf("err=%v want the member-cap detail", err)
	}
}

func TestFetch_RejectsNonJSONAndNon2xx(t *testing.T) {
	t.Parallel()

	html := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html></html>"))
	}))
	defer html.Close()
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer broken.Close()

	f := newTestFetcher(t, Config{})
	if _, err := f.Fetch(context.Background(), html.URL); !errors.Is(err, errSentinel) ||
		!strings.Contains(err.Error(), "content-type") {
		t.Fatalf("non-JSON err=%v want a content-type refusal", err)
	}
	if _, err := f.Fetch(context.Background(), broken.URL); !errors.Is(err, errSentinel) ||
		!strings.Contains(err.Error(), "status 500") {
		t.Fatalf("non-2xx err=%v want a status refusal", err)
	}
}

// TestFetch_RejectsPrivateNetworkByDefault confirms the SSRF deny-list is the
// default posture: a client-controlled jwks_uri pointing at the OP's own
// network is refused unless the embedder opted in.
func TestFetch_RejectsPrivateNetworkByDefault(t *testing.T) {
	t.Parallel()

	f := New(Config{FetchError: errSentinel})
	for _, url := range []string{
		"http://127.0.0.1:1/jwks",
		"http://localhost/jwks",
		"http://10.0.0.1/jwks",
	} {
		if _, err := f.Fetch(context.Background(), url); !errors.Is(err, errSentinel) {
			t.Errorf("%s: err=%v want the configured sentinel", url, err)
		}
	}
}

// TestFetch_SingleflightCollapsesConcurrentFetches drives N goroutines at the
// same URL and confirms the upstream only saw one round-trip. The check is the
// structural defence against a peer that replays one request N times to
// amplify outbound traffic at the RP's host.
func TestFetch_SingleflightCollapsesConcurrentFetches(t *testing.T) {
	t.Parallel()

	hits := &atomic.Int32{}
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		once.Do(func() { close(entered) })
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(jwksJSON))
	}))
	defer srv.Close()

	f := newTestFetcher(t, Config{})

	const concurrent = 24
	start := make(chan struct{})
	errs := make(chan error, concurrent)
	var wg sync.WaitGroup
	for range concurrent {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := f.Fetch(context.Background(), srv.URL)
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
			t.Fatalf("Fetch: %v", err)
		}
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("upstream hits=%d want 1 (singleflight should collapse %d fetches)", got, concurrent)
	}
}

func TestFetch_InFlightLimitShedsDistinctURLsWithoutNegativeCaching(t *testing.T) {
	t.Parallel()

	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if block := r.URL.Query().Get("block"); block == "1" || block == "2" {
			entered <- struct{}{}
			<-release
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write([]byte(jwksJSON))
	}))
	defer srv.Close()

	f := newTestFetcher(t, Config{MaxInflight: 1, NegativeTTL: time.Hour})
	firstDone := make(chan error, 1)
	go func() {
		_, err := f.Fetch(context.Background(), srv.URL+"?block=1")
		firstDone <- err
	}()
	<-entered

	_, err := f.Fetch(context.Background(), srv.URL+"?block=2")
	if !errors.Is(err, errSentinel) {
		t.Fatalf("overloaded fetch err=%v want configured sentinel", err)
	}
	var transient *TransientError
	if !errors.As(err, &transient) || !errors.Is(err, ErrOverloaded) {
		t.Fatalf("overloaded err=%v want *TransientError wrapping ErrOverloaded", err)
	}
	if _, ok, _ := f.cache.Get(srv.URL + "?block=2"); ok {
		t.Fatal("overload was negative-cached")
	}

	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	if _, err := f.Fetch(context.Background(), srv.URL+"?block=2"); err != nil {
		t.Fatalf("retry after capacity release: %v", err)
	}
}

func TestFetch_InFlightLimitIsSharedAcrossFetcherInstances(t *testing.T) {
	t.Parallel()

	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if block := r.URL.Query().Get("block"); block == "1" || block == "2" {
			entered <- struct{}{}
			<-release
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write([]byte(jwksJSON))
	}))
	defer srv.Close()

	// Use a group distinct from the other parallel gate tests; the shared
	// process-wide property is what this test proves between these two
	// fetchers, not a fixed numeric value.
	first := newTestFetcher(t, Config{MaxInflight: 2})
	second := newTestFetcher(t, Config{MaxInflight: 2})
	firstDone := make(chan error, 1)
	secondDone := make(chan error, 1)
	go func() {
		_, err := first.Fetch(context.Background(), srv.URL+"?block=1")
		firstDone <- err
	}()
	<-entered
	go func() {
		_, err := second.Fetch(context.Background(), srv.URL+"?block=2")
		secondDone <- err
	}()
	<-entered
	third := newTestFetcher(t, Config{MaxInflight: 2})
	if _, err := third.Fetch(context.Background(), srv.URL+"?block=3"); !errors.Is(err, ErrOverloaded) {
		t.Fatalf("third fetch err=%v want ErrOverloaded", err)
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("second fetch: %v", err)
	}
}

// TestFetch_NegativeCacheShortCircuitsThenRecovers drives a fetch against a
// failing upstream and confirms the second fetch inside the negative window
// does not re-issue the round-trip, then that recovery is observable once the
// window elapses. Without the short-circuit, a peer replaying a request that
// names an unreachable URL would force one outbound socket per inbound request.
func TestFetch_NegativeCacheShortCircuitsThenRecovers(t *testing.T) {
	t.Parallel()

	hits := &atomic.Int32{}
	var fail atomic.Bool
	fail.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		if fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(jwksJSON))
	}))
	defer srv.Close()

	clock := testClock()
	f := newTestFetcher(t, Config{Clock: clock, NegativeTTL: 5 * time.Second})
	ctx := context.Background()

	if _, err := f.Fetch(ctx, srv.URL); !errors.Is(err, errSentinel) {
		t.Fatalf("first fetch err=%v want the configured sentinel", err)
	}
	if _, err := f.Fetch(ctx, srv.URL); !errors.Is(err, errSentinel) {
		t.Fatalf("negative-cached fetch err=%v want the configured sentinel", err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("hits=%d want 1 inside the negative window", got)
	}

	clock.now = clock.now.Add(6 * time.Second)
	fail.Store(false)
	if _, err := f.Fetch(ctx, srv.URL); err != nil {
		t.Fatalf("recovery fetch: %v", err)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("hits=%d want 2 after the negative window", got)
	}
}

// flakyTransport fails the first n round-trips with err and delegates the rest.
type flakyTransport struct {
	inner   http.RoundTripper
	err     error
	failing atomic.Int32
	hits    atomic.Int32
}

func (t *flakyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.hits.Add(1)
	if t.failing.Add(-1) >= 0 {
		return nil, t.err
	}
	return t.inner.RoundTrip(r)
}

// TestFetch_DoesNotNegativeCacheContextFailures pins that a fetch that ended in
// cancellation or a blown deadline leaves no negative entry. Those errors
// describe the attempt, not the upstream: caching them would let anyone who can
// trigger an outbound fetch suppress a client's keyset for the whole negative
// window, taking its request-object and private_key_jwt paths down with it.
func TestFetch_DoesNotNegativeCacheContextFailures(t *testing.T) {
	t.Parallel()

	for name, cause := range map[string]error{
		"canceled": context.Canceled,
		"deadline": context.DeadlineExceeded,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(jwksHandler("", "", &atomic.Int32{}))
			defer srv.Close()

			rt := &flakyTransport{inner: http.DefaultTransport, err: cause}
			rt.failing.Store(1)
			f := newTestFetcher(t, Config{NegativeTTL: time.Hour, BaseTransport: rt})

			if _, err := f.Fetch(context.Background(), srv.URL); !errors.Is(err, cause) {
				t.Fatalf("first fetch err=%v want %v", err, cause)
			}
			if _, ok, cached := f.cache.Get(srv.URL); ok {
				t.Fatalf("%v was negative-cached as %v", cause, cached)
			}
			// The retry must reach the upstream rather than replay a cached
			// failure, even though the negative TTL is an hour.
			if _, err := f.Fetch(context.Background(), srv.URL); err != nil {
				t.Fatalf("retry after %v: %v", cause, err)
			}
			if got := rt.hits.Load(); got != 2 {
				t.Fatalf("round-trips=%d want 2", got)
			}
		})
	}
}

// TestFetch_UpstreamFailureIsStillNegativeCached is the control for the test
// above: an error that does describe the upstream keeps the amplification guard
// the negative cache exists for.
func TestFetch_UpstreamFailureIsStillNegativeCached(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	f := newTestFetcher(t, Config{NegativeTTL: time.Hour})
	if _, err := f.Fetch(context.Background(), srv.URL); !errors.Is(err, errSentinel) {
		t.Fatalf("err=%v want the configured sentinel", err)
	}
	if _, ok, cached := f.cache.Get(srv.URL); !ok || cached == nil {
		t.Fatal("an upstream failure was not negative-cached")
	}
}

// TestFetch_CallerCancellationDoesNotPoisonTheFlight pins that a caller hanging
// up mid-fetch neither aborts the outbound request the other waiters share nor
// costs anyone a second one. The fetch runs inside a singleflight, so the first
// caller's request context would otherwise be the one every collapsed caller
// depends on: an unauthenticated peer could disconnect mid-fetch and keep a
// client's keyset unavailable by repeating it. The abandoning caller must
// return promptly, and the detached round-trip must still complete into the
// cache for the next caller.
func TestFetch_CallerCancellationDoesNotPoisonTheFlight(t *testing.T) {
	t.Parallel()

	hits := &atomic.Int32{}
	release := make(chan struct{})
	inflight := make(chan struct{})
	var once sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		once.Do(func() { close(inflight) })
		<-release
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write([]byte(jwksJSON))
	}))
	defer srv.Close()

	f := newTestFetcher(t, Config{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	abandoned := make(chan error, 1)
	go func() {
		_, err := f.Fetch(ctx, srv.URL)
		abandoned <- err
	}()

	<-inflight
	cancel()
	if err := <-abandoned; !errors.Is(err, context.Canceled) {
		t.Fatalf("abandoned Fetch err=%v want context.Canceled", err)
	}
	close(release)

	keys, err := f.Fetch(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Fetch after an abandoned one: %v", err)
	}
	if len(keys.Keys) != 1 || keys.Keys[0].KeyID != "k1" {
		t.Fatalf("Fetch returned kids %v, want [k1]", keyIDs(keys))
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("upstream hits=%d want 1; the abandoned fetch should have served the retry", got)
	}
}

func TestFetch_CancellationReleasesConfiguredInFlightSlot(t *testing.T) {
	t.Parallel()

	entered := make(chan struct{})
	release := make(chan struct{})
	var enteredOnce sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("block") == "1" {
			enteredOnce.Do(func() { close(entered) })
			<-release
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write([]byte(jwksJSON))
	}))
	defer srv.Close()

	f := newTestFetcher(t, Config{MaxInflight: 3})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	callerDone := make(chan error, 1)
	loaderDone := make(chan error, 1)
	go func() {
		_, err := f.Fetch(ctx, srv.URL+"?block=1")
		callerDone <- err
	}()
	<-entered
	cancel()
	if err := <-callerDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled caller err=%v want context.Canceled", err)
	}
	// The detached loader still owns the slot until the upstream returns.
	go func() {
		_, err := f.Fetch(context.Background(), srv.URL+"?block=1")
		loaderDone <- err
	}()
	close(release)
	if err := <-loaderDone; err != nil {
		t.Fatalf("detached loader: %v", err)
	}
	if _, err := f.Fetch(context.Background(), srv.URL+"?block=2"); err != nil {
		t.Fatalf("fetch after detached loader released slot: %v", err)
	}
}

// TestFetch_EvictsLeastRecentlyUsedURL pins that eviction under cardinality
// pressure is deterministic and drops the least-recently-used URL, so a flood
// of one-shot registrations cannot displace the keyset of a client the OP is
// actively serving.
func TestFetch_EvictsLeastRecentlyUsedURL(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	hits := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.RawQuery]++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write([]byte(jwksJSON))
	}))
	defer srv.Close()
	hitsFor := func(name string) int {
		mu.Lock()
		defer mu.Unlock()
		return hits["client="+name]
	}

	f := newTestFetcher(t, Config{Clock: testClock(), TTL: time.Hour, MaxEntries: 2})
	url := func(name string) string { return srv.URL + "?client=" + name }
	fetch := func(name string) {
		t.Helper()
		if _, err := f.Fetch(context.Background(), url(name)); err != nil {
			t.Fatalf("Fetch(%s): %v", name, err)
		}
	}

	fetch("a")
	fetch("b")
	fetch("a") // cache hit; a becomes the most recently used entry
	fetch("c") // evicts b, the least recently used
	if got := f.CacheLen(); got != 2 {
		t.Fatalf("CacheLen=%d want the configured bound of 2", got)
	}
	fetch("a")
	if got := hitsFor("a"); got != 1 {
		t.Errorf("a round-trips=%d want 1; the recently used entry was evicted", got)
	}
	fetch("b")
	if got := hitsFor("b"); got != 2 {
		t.Errorf("b round-trips=%d want 2; the least recently used entry survived", got)
	}
}

// TestFetch_CardinalityStaysBoundedUnderPressure drives far more distinct URLs
// than the budget allows and confirms the cache never grows past it, so hostile
// registrations cannot make process memory grow without bound.
func TestFetch_CardinalityStaysBoundedUnderPressure(t *testing.T) {
	t.Parallel()

	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Alternate success and failure so positive and negative entries
		// compete for the same budget.
		if fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write([]byte(jwksJSON))
	}))
	defer srv.Close()

	f := newTestFetcher(t, Config{Clock: testClock(), TTL: time.Hour, NegativeTTL: time.Hour, MaxEntries: 4})
	for i := range 40 {
		fail.Store(i%2 == 1)
		_, _ = f.Fetch(context.Background(), fmt.Sprintf("%s?client=%d", srv.URL, i))
		if got := f.CacheLen(); got > 4 {
			t.Fatalf("CacheLen=%d exceeds the bound of 4 after URL %d", got, i)
		}
	}
	if got := f.CacheLen(); got != 4 {
		t.Fatalf("CacheLen=%d want 4 after high-cardinality load", got)
	}
}

// TestTryForced_ThrottleStateStaysBounded confirms the forced-refresh bookkeeping
// is subject to the same cardinality budget as the keyset cache, so the throttle
// cannot itself become the unbounded map.
func TestTryForced_ThrottleStateStaysBounded(t *testing.T) {
	t.Parallel()

	f := New(Config{Clock: testClock(), MaxEntries: 4})
	for i := range 40 {
		if !f.tryForced(fmt.Sprintf("https://rp.example/%d/jwks", i)) {
			t.Fatalf("first forced refresh for URL %d was throttled", i)
		}
		if got := f.forced.Len(); got > 4 {
			t.Fatalf("throttle entries=%d exceeds the bound of 4 after URL %d", got, i)
		}
	}
}

// TestFetchFresh_BypassesFreshCacheThenThrottles pins the forced-refresh
// contract. The path exists so a key the RP rotated in after the OP last cached
// its keyset still verifies; the throttle is what keeps it from being an
// amplifier, because the trigger — a signature naming an unknown key id — is
// attacker-supplied. The interval is per URL and never consults the key id, so
// N distinct unknown ids inside one window still cost exactly one round-trip.
func TestFetchFresh_BypassesFreshCacheThenThrottles(t *testing.T) {
	t.Parallel()

	// A rotating server: the served kid flips after the first response so a
	// forced refetch observes a genuinely different keyset.
	hits := &atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := hits.Add(1)
		w.Header().Set("Content-Type", "application/jwk-set+json")
		w.Header().Set("Cache-Control", "max-age=300")
		kid := "k2"
		if n == 1 {
			kid = "k1"
		}
		_, _ = w.Write([]byte(`{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","kid":"` + kid + `"}]}`))
	}))
	defer srv.Close()

	clock := testClock()
	f := newTestFetcher(t, Config{Clock: clock})

	// Prime the positive cache (kid k1), well inside its 300s freshness.
	if _, err := f.Fetch(context.Background(), srv.URL); err != nil {
		t.Fatalf("prime fetch: %v", err)
	}

	got, err := f.FetchFresh(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("FetchFresh 1: %v", err)
	}
	if len(got.Keys) != 1 || got.Keys[0].KeyID != "k2" {
		t.Fatalf("FetchFresh returned kids %v, want [k2]", keyIDs(got))
	}
	if n := hits.Load(); n != 2 {
		t.Fatalf("hits=%d after the first FetchFresh, want 2", n)
	}

	// A second FetchFresh inside the throttle window must not hit the network;
	// it returns the cached (now k2) keyset.
	got, err = f.FetchFresh(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("FetchFresh 2: %v", err)
	}
	if len(got.Keys) != 1 || got.Keys[0].KeyID != "k2" {
		t.Fatalf("throttled FetchFresh returned kids %v, want cached [k2]", keyIDs(got))
	}
	if n := hits.Load(); n != 2 {
		t.Errorf("hits=%d after the throttled FetchFresh, want still 2", n)
	}

	// Past the throttle window a forced refetch is allowed again.
	clock.now = clock.now.Add(ForcedRefreshInterval + time.Second)
	if _, err := f.FetchFresh(context.Background(), srv.URL); err != nil {
		t.Fatalf("FetchFresh 3: %v", err)
	}
	if n := hits.Load(); n != 3 {
		t.Errorf("hits=%d after the throttle window elapsed, want 3", n)
	}
}

// TestFetchFresh_OverloadReleasesForcedMarker verifies that capacity pressure
// does not consume the forced-refresh throttle window. The positive cache must
// remain available while a slot is unavailable, and the next caller must be
// able to force a refetch immediately after the slot is released.
//
//nolint:paralleltest // It saturates the process-wide fetch-capacity gate to assert overload behavior.
func TestFetchFresh_OverloadReleasesForcedMarker(t *testing.T) {
	hits := &atomic.Int32{}
	version := &atomic.Int32{}
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("kind") == "block" {
			once.Do(func() { close(entered) })
			<-release
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		w.Header().Set("Cache-Control", "max-age=300")
		kid := "k1"
		if r.URL.Query().Get("kind") == "target" {
			hits.Add(1)
			if version.Load() != 0 {
				kid = "k2"
			}
		}
		_, _ = w.Write([]byte(`{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","kid":"` + kid + `"}]}`))
	}))
	defer srv.Close()

	f := newTestFetcher(t, Config{MaxInflight: 1})
	target := srv.URL + "?kind=target"
	block := srv.URL + "?kind=block"
	if _, err := f.Fetch(context.Background(), target); err != nil {
		t.Fatalf("prime target fetch: %v", err)
	}

	blockDone := make(chan error, 1)
	go func() {
		_, err := f.Fetch(context.Background(), block)
		blockDone <- err
	}()
	<-entered

	if _, err := f.FetchFresh(context.Background(), target); !errors.Is(err, ErrOverloaded) {
		t.Fatalf("overloaded FetchFresh err=%v want ErrOverloaded", err)
	}
	cached, ok, cacheErr := f.cache.Get(target)
	if cacheErr != nil || !ok || cached == nil || len(cached.keys.Keys) != 1 || cached.keys.Keys[0].KeyID != "k1" {
		t.Fatalf("cached keyset after overload=%+v ok=%t err=%v want fresh k1", cached, ok, cacheErr)
	}

	version.Store(1)
	close(release)
	if err := <-blockDone; err != nil {
		t.Fatalf("blocking fetch: %v", err)
	}
	keys, err := f.FetchFresh(context.Background(), target)
	if err != nil {
		t.Fatalf("FetchFresh after capacity release: %v", err)
	}
	if len(keys.Keys) != 1 || keys.Keys[0].KeyID != "k2" {
		t.Fatalf("FetchFresh after capacity release returned kids %v, want [k2]", keyIDs(keys))
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("target round-trips=%d want 2 (prime + immediate retry)", got)
	}
}

// TestFetchFresh_RevalidatesAnExpiredEntryConditionally pins that the throttle
// probe does not destroy the change-detection state the refresh is about to
// use: a forced refresh of an expired entry still sends If-None-Match, so an
// unchanged upstream costs a 304 rather than a full re-download.
func TestFetchFresh_RevalidatesAnExpiredEntryConditionally(t *testing.T) {
	t.Parallel()

	const etag = `"abc"`
	conditional := &atomic.Int32{}
	hits := &atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("If-None-Match") == etag {
			conditional.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		w.Header().Set("Cache-Control", "max-age=10")
		w.Header().Set("ETag", etag)
		_, _ = w.Write([]byte(jwksJSON))
	}))
	defer srv.Close()

	clock := testClock()
	f := newTestFetcher(t, Config{Clock: clock})
	if _, err := f.Fetch(context.Background(), srv.URL); err != nil {
		t.Fatalf("prime fetch: %v", err)
	}
	clock.now = clock.now.Add(time.Hour)

	keys, err := f.FetchFresh(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("FetchFresh: %v", err)
	}
	if len(keys.Keys) != 1 || keys.Keys[0].KeyID != "k1" {
		t.Fatalf("FetchFresh returned kids %v, want [k1]", keyIDs(keys))
	}
	if got := conditional.Load(); got != 1 {
		t.Errorf("conditional round-trips=%d want 1; the ETag was dropped", got)
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("hits=%d want 2", got)
	}
}

// TestFetchFresh_FailureKeepsTheCachedKeyset pins that a forced refresh which
// fails leaves the cached keyset serving. The refresh is triggered by an
// attacker-suppliable key id, so replacing a working keyset with a cached
// failure would hand any peer a way to lock a client out for the negative
// window by timing its probes against a brief RP outage.
func TestFetchFresh_FailureKeepsTheCachedKeyset(t *testing.T) {
	t.Parallel()

	hits := &atomic.Int32{}
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		if fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		w.Header().Set("Cache-Control", "max-age=300")
		_, _ = w.Write([]byte(jwksJSON))
	}))
	defer srv.Close()

	clock := testClock()
	f := newTestFetcher(t, Config{Clock: clock, NegativeTTL: time.Hour})
	if _, err := f.Fetch(context.Background(), srv.URL); err != nil {
		t.Fatalf("prime fetch: %v", err)
	}

	fail.Store(true)
	if _, err := f.FetchFresh(context.Background(), srv.URL); !errors.Is(err, errSentinel) {
		t.Fatalf("FetchFresh err=%v want the configured sentinel", err)
	}
	if n := hits.Load(); n != 2 {
		t.Fatalf("hits=%d want 2", n)
	}

	keys, err := f.Fetch(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Fetch after a failed refresh: %v", err)
	}
	if len(keys.Keys) != 1 || keys.Keys[0].KeyID != "k1" {
		t.Fatalf("Fetch returned kids %v, want the still-cached [k1]", keyIDs(keys))
	}
	if n := hits.Load(); n != 2 {
		t.Errorf("hits=%d want still 2; the cached keyset should have answered", n)
	}
}

// countingTransport delegates to its inner transport and counts round-trips.
type countingTransport struct {
	inner http.RoundTripper
	hits  atomic.Int32
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.hits.Add(1)
	return c.inner.RoundTrip(r)
}

// TestFetcher_TransportInjection confirms both the [Config] field and the
// post-construction setter reach the lazily-built client, so an embedder with a
// private CA or an instrumented transport is wired with one assignment.
func TestFetcher_TransportInjection(t *testing.T) {
	t.Parallel()

	for name, wire := range map[string]func(*countingTransport) *Fetcher{
		"config": func(ct *countingTransport) *Fetcher {
			return New(Config{FetchError: errSentinel, AllowPrivateNetwork: true, BaseTransport: ct})
		},
		"setter": func(ct *countingTransport) *Fetcher {
			f := New(Config{FetchError: errSentinel, AllowPrivateNetwork: true})
			f.SetBaseTransport(ct)
			return f
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(jwksHandler("", "", &atomic.Int32{}))
			defer srv.Close()

			ct := &countingTransport{inner: http.DefaultTransport}
			f := wire(ct)
			if _, err := f.Fetch(context.Background(), srv.URL); err != nil {
				t.Fatalf("Fetch: %v", err)
			}
			if got := ct.hits.Load(); got == 0 {
				t.Fatal("the injected transport saw 0 round-trips; injection lost")
			}
		})
	}
}

// TestFetcher_SetAllowPrivateAppliesAfterConstruction confirms the posture
// setter still lands, since the client is built lazily on first use.
func TestFetcher_SetAllowPrivateAppliesAfterConstruction(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(jwksHandler("", "", &atomic.Int32{}))
	defer srv.Close()

	f := New(Config{FetchError: errSentinel})
	f.SetAllowPrivate(true)
	if _, err := f.Fetch(context.Background(), srv.URL); err != nil {
		t.Fatalf("Fetch after SetAllowPrivate: %v", err)
	}
}
