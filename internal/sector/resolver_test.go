//nolint:testpackage // exercises unexported config fields and helpers (canonicaliseURIs, hashURIs, withResolverLookupHook).
package sector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/timex"
)

// fakeClock returns a clock fixed at the supplied instant; advance
// the embedded value across calls to test cache expiry deterministically.
type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }

func newJSONServer(t *testing.T, body []byte, ct string) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// resolverWithServer returns a Resolver that trusts the test
// httptest TLS server's certificate and skips the SSRF deny-list so
// the server's loopback address can be exercised.
func resolverWithServer(t *testing.T, srv *httptest.Server, opts ...Option) *Resolver {
	t.Helper()
	client := srv.Client()
	all := append([]Option{
		WithHTTPClient(client),
		AllowPrivateNetwork(),
	}, opts...)
	return New(all...)
}

func TestResolve_HappyPathReturnsHostAndCaches(t *testing.T) {
	t.Parallel()
	body, _ := json.Marshal([]string{
		"https://rp.example/cb",
		"https://rp.example/cb2",
	})
	srv := newJSONServer(t, body, "application/json")
	clock := &fakeClock{now: time.Date(2026, 5, 3, 0, 0, 0, 0, time.UTC)}
	r := resolverWithServer(t, srv, WithClock(clock))

	host, err := r.Resolve(context.Background(), srv.URL, []string{"https://rp.example/cb"})
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	wantHost, _, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	if !strings.EqualFold(host, wantHost) {
		t.Fatalf("Resolve host = %q, want %q", host, wantHost)
	}

	// Second call: server gone, resolver MUST hit the cache.
	srv.Close()
	host2, err := r.Resolve(context.Background(), srv.URL, []string{"https://rp.example/cb"})
	if err != nil {
		t.Fatalf("cached Resolve returned error: %v", err)
	}
	if host != host2 {
		t.Fatalf("cached host = %q, want %q", host2, host)
	}
}

func TestResolve_RejectsHTTPScheme(t *testing.T) {
	t.Parallel()
	r := New()
	_, err := r.Resolve(context.Background(), "http://rp.example/sector.json", nil)
	if err == nil {
		t.Fatal("expected error for http scheme, got nil")
	}
	if !errors.Is(err, ErrSectorFetch) {
		t.Fatalf("err = %v, want wrap of ErrSectorFetch", err)
	}
}

func TestResolve_RejectsLoopbackHostByName(t *testing.T) {
	t.Parallel()
	r := New()
	_, err := r.Resolve(context.Background(), "https://localhost/sector.json", nil)
	if !errors.Is(err, ErrSectorPrivateAddress) {
		t.Fatalf("err = %v, want wrap of ErrSectorPrivateAddress", err)
	}
}

func TestResolve_RejectsRFC1918Literal(t *testing.T) {
	t.Parallel()
	r := New()
	_, err := r.Resolve(context.Background(), "https://10.0.0.1/sector.json", nil)
	if !errors.Is(err, ErrSectorPrivateAddress) {
		t.Fatalf("err = %v, want wrap of ErrSectorPrivateAddress", err)
	}
}

func TestResolve_RejectsLoopbackLiteral(t *testing.T) {
	t.Parallel()
	r := New()
	_, err := r.Resolve(context.Background(), "https://127.0.0.1/sector.json", nil)
	if !errors.Is(err, ErrSectorPrivateAddress) {
		t.Fatalf("err = %v, want wrap of ErrSectorPrivateAddress", err)
	}
}

func TestResolve_RejectsLinkLocalLiteral(t *testing.T) {
	t.Parallel()
	r := New()
	_, err := r.Resolve(context.Background(), "https://169.254.169.254/sector.json", nil)
	if !errors.Is(err, ErrSectorPrivateAddress) {
		t.Fatalf("err = %v, want wrap of ErrSectorPrivateAddress", err)
	}
}

func TestResolve_RejectsIPv6ULA(t *testing.T) {
	t.Parallel()
	r := New()
	_, err := r.Resolve(context.Background(), "https://[fc00::1]/sector.json", nil)
	if !errors.Is(err, ErrSectorPrivateAddress) {
		t.Fatalf("err = %v, want wrap of ErrSectorPrivateAddress", err)
	}
}

func TestResolve_RejectsDNSResolvedToPrivate(t *testing.T) {
	t.Parallel()
	hook := func(_ context.Context, _ string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("10.1.2.3")}}, nil
	}
	r := New(withResolverLookupHook(hook))
	_, err := r.Resolve(context.Background(), "https://attacker.example/sector.json", nil)
	if !errors.Is(err, ErrSectorPrivateAddress) {
		t.Fatalf("err = %v, want wrap of ErrSectorPrivateAddress", err)
	}
}

func TestResolve_RefusesRedirect(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, "https://other.example/", http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	r := resolverWithServer(t, srv)
	_, err := r.Resolve(context.Background(), srv.URL, nil)
	if !errors.Is(err, ErrSectorRedirectFollowed) {
		t.Fatalf("err = %v, want wrap of ErrSectorRedirectFollowed", err)
	}
}

func TestResolve_RejectsNonJSONContentType(t *testing.T) {
	t.Parallel()
	body, _ := json.Marshal([]string{"https://rp.example/cb"})
	srv := newJSONServer(t, body, "text/html; charset=utf-8")
	r := resolverWithServer(t, srv)
	_, err := r.Resolve(context.Background(), srv.URL, []string{"https://rp.example/cb"})
	if err == nil {
		t.Fatal("expected error for text/html content-type, got nil")
	}
	if !errors.Is(err, ErrSectorFetch) {
		t.Fatalf("err = %v, want wrap of ErrSectorFetch", err)
	}
}

func TestResolve_RejectsBodyOverCap(t *testing.T) {
	t.Parallel()
	huge := make([]byte, defaultMaxBody+10)
	for i := range huge {
		huge[i] = '"'
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(huge)
	}))
	t.Cleanup(srv.Close)
	r := resolverWithServer(t, srv)
	_, err := r.Resolve(context.Background(), srv.URL, nil)
	if err == nil || !errors.Is(err, ErrSectorFetch) {
		t.Fatalf("err = %v, want wrap of ErrSectorFetch", err)
	}
}

func TestResolve_RejectsMalformedJSON(t *testing.T) {
	t.Parallel()
	srv := newJSONServer(t, []byte(`{"redirect_uris":["https://rp.example/cb"]}`), "application/json")
	r := resolverWithServer(t, srv)
	_, err := r.Resolve(context.Background(), srv.URL, []string{"https://rp.example/cb"})
	if !errors.Is(err, ErrSectorMalformed) {
		t.Fatalf("err = %v, want wrap of ErrSectorMalformed", err)
	}
}

func TestResolve_RejectsEmptyBody(t *testing.T) {
	t.Parallel()
	srv := newJSONServer(t, []byte{}, "application/json")
	r := resolverWithServer(t, srv)
	_, err := r.Resolve(context.Background(), srv.URL, nil)
	if !errors.Is(err, ErrSectorMalformed) {
		t.Fatalf("err = %v, want wrap of ErrSectorMalformed", err)
	}
}

func TestResolve_RejectsTrailingDataAfterJSONArray(t *testing.T) {
	t.Parallel()
	// A syntactically valid JSON array followed by trailing garbage:
	// the array alone would decode cleanly, but OIDC Core 1.0 §5
	// defines the document as exactly one JSON array, so the trailing
	// bytes must reject the whole document rather than being silently
	// ignored.
	body := []byte(`["https://rp.example/cb"]` + "\ngarbage-after-array")
	srv := newJSONServer(t, body, "application/json")
	r := resolverWithServer(t, srv)
	_, err := r.Resolve(context.Background(), srv.URL, []string{"https://rp.example/cb"})
	if !errors.Is(err, ErrSectorMalformed) {
		t.Fatalf("err = %v, want wrap of ErrSectorMalformed", err)
	}
}

func TestResolve_RejectsSecondJSONValueAfterArray(t *testing.T) {
	t.Parallel()
	// Two concatenated JSON values: the decoder accepts the first
	// (the array) and dec.More() must catch the second rather than
	// silently discarding it.
	body := []byte(`["https://rp.example/cb"]` + `["https://evil.example/cb"]`)
	srv := newJSONServer(t, body, "application/json")
	r := resolverWithServer(t, srv)
	_, err := r.Resolve(context.Background(), srv.URL, []string{"https://rp.example/cb"})
	if !errors.Is(err, ErrSectorMalformed) {
		t.Fatalf("err = %v, want wrap of ErrSectorMalformed", err)
	}
}

func TestResolve_RejectsRedirectURINotInDocument(t *testing.T) {
	t.Parallel()
	body, _ := json.Marshal([]string{"https://rp.example/cb"})
	srv := newJSONServer(t, body, "application/json")
	r := resolverWithServer(t, srv)
	_, err := r.Resolve(context.Background(), srv.URL, []string{"https://rp.example/cb-other"})
	if !errors.Is(err, ErrSectorRedirectMissing) {
		t.Fatalf("err = %v, want wrap of ErrSectorRedirectMissing", err)
	}
}

func TestResolve_AcceptsCanonicaliseHostCase(t *testing.T) {
	t.Parallel()
	body, _ := json.Marshal([]string{"https://RP.EXAMPLE/cb"})
	srv := newJSONServer(t, body, "application/json")
	r := resolverWithServer(t, srv)
	_, err := r.Resolve(context.Background(), srv.URL, []string{"https://rp.example/cb"})
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
}

func TestResolve_DetectsContentChangeAfterCacheExpiry(t *testing.T) {
	t.Parallel()
	original, _ := json.Marshal([]string{"https://rp.example/cb"})
	rotated, _ := json.Marshal([]string{"https://rp.example/cb", "https://rp.example/cb2"})
	current := original
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(current)
	}))
	t.Cleanup(srv.Close)

	clock := &fakeClock{now: time.Date(2026, 5, 3, 0, 0, 0, 0, time.UTC)}
	r := resolverWithServer(t, srv, WithClock(clock), WithTTL(time.Hour))

	if _, err := r.Resolve(context.Background(), srv.URL, []string{"https://rp.example/cb"}); err != nil {
		t.Fatalf("first Resolve: %v", err)
	}
	current = rotated
	clock.now = clock.now.Add(2 * time.Hour) // expire the cache
	_, err := r.Resolve(context.Background(), srv.URL, []string{"https://rp.example/cb"})
	if !errors.Is(err, ErrSectorContentChanged) {
		t.Fatalf("err = %v, want wrap of ErrSectorContentChanged", err)
	}
}

func TestResolve_RecoversAfterContentChangeWithoutRestart(t *testing.T) {
	t.Parallel()
	original, _ := json.Marshal([]string{"https://rp.example/cb"})
	rotated, _ := json.Marshal([]string{"https://rp.example/cb", "https://rp.example/cb2"})
	current := original
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(current)
	}))
	t.Cleanup(srv.Close)

	clock := &fakeClock{now: time.Date(2026, 5, 3, 0, 0, 0, 0, time.UTC)}
	r := resolverWithServer(t, srv, WithClock(clock), WithTTL(time.Hour))

	if _, err := r.Resolve(context.Background(), srv.URL, []string{"https://rp.example/cb"}); err != nil {
		t.Fatalf("first Resolve: %v", err)
	}
	current = rotated
	clock.now = clock.now.Add(2 * time.Hour) // expire the cache

	// The RP legitimately rotated its sector document: the resolver
	// MUST surface the change once...
	if _, err := r.Resolve(context.Background(), srv.URL, []string{"https://rp.example/cb", "https://rp.example/cb2"}); !errors.Is(err, ErrSectorContentChanged) {
		t.Fatalf("second Resolve err = %v, want wrap of ErrSectorContentChanged", err)
	}
	// ...but MUST NOT stay permanently poisoned: a subsequent resolve
	// against the now-stable rotated document succeeds without a
	// process restart, and a client sharing the same
	// sector_identifier_uri is not permanently broken.
	clock.now = clock.now.Add(2 * time.Hour) // expire the cache again
	if _, err := r.Resolve(context.Background(), srv.URL, []string{"https://rp.example/cb", "https://rp.example/cb2"}); err != nil {
		t.Fatalf("third Resolve (post-eviction recovery): %v", err)
	}
}

func TestResolve_AllowPrivateNetworkBypassesGate(t *testing.T) {
	t.Parallel()
	body, _ := json.Marshal([]string{"https://rp.example/cb"})
	srv := newJSONServer(t, body, "application/json")
	r := New(
		WithHTTPClient(srv.Client()),
		AllowPrivateNetwork(),
	)
	_, err := r.Resolve(context.Background(), srv.URL, []string{"https://rp.example/cb"})
	if err != nil {
		t.Fatalf("Resolve under AllowPrivateNetwork returned error: %v", err)
	}
}

func TestResolve_RejectsParseUnparseableURL(t *testing.T) {
	t.Parallel()
	r := New()
	_, err := r.Resolve(context.Background(), "://[not-a-url", nil)
	if !errors.Is(err, ErrSectorFetch) {
		t.Fatalf("err = %v, want wrap of ErrSectorFetch", err)
	}
}

func TestResolve_RejectsMissingHost(t *testing.T) {
	t.Parallel()
	r := New()
	_, err := r.Resolve(context.Background(), "https:///path", nil)
	if !errors.Is(err, ErrSectorFetch) {
		t.Fatalf("err = %v, want wrap of ErrSectorFetch", err)
	}
}

func TestResolve_StatusNon2xx(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	r := resolverWithServer(t, srv)
	_, err := r.Resolve(context.Background(), srv.URL, nil)
	if !errors.Is(err, ErrSectorFetch) {
		t.Fatalf("err = %v, want wrap of ErrSectorFetch", err)
	}
}

func TestResolve_EmptyRegisteredListIsAccepted(t *testing.T) {
	// A client with no registered redirect_uris (e.g. client_credentials)
	// MUST NOT trip the subset check; the OIDC Core invariant holds
	// vacuously.
	t.Parallel()
	body, _ := json.Marshal([]string{"https://rp.example/cb"})
	srv := newJSONServer(t, body, "application/json")
	r := resolverWithServer(t, srv)
	_, err := r.Resolve(context.Background(), srv.URL, nil)
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
}

func TestCanonicaliseURIs_LowercasesHostAndSorts(t *testing.T) {
	t.Parallel()
	got := canonicaliseURIs([]string{
		"https://B.EXAMPLE/cb",
		"https://a.example/cb",
	})
	want := []string{"https://a.example/cb", "https://b.example/cb"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestHashURIs_StableAcrossOrder(t *testing.T) {
	t.Parallel()
	a := hashURIs([]string{"https://a.example/cb", "https://b.example/cb"})
	b := hashURIs([]string{"https://b.example/cb", "https://a.example/cb"})
	if a != b {
		t.Fatalf("hash differed across input order: %q vs %q", a, b)
	}
}

func TestNew_DefaultsApplied(t *testing.T) {
	t.Parallel()
	r := New()
	if r.cfg.timeout != defaultTimeout {
		t.Fatalf("timeout = %v, want %v", r.cfg.timeout, defaultTimeout)
	}
	if r.cfg.maxBody != defaultMaxBody {
		t.Fatalf("maxBody = %d, want %d", r.cfg.maxBody, defaultMaxBody)
	}
	if r.cfg.ttl != timex.SectorURICacheTTLDefault {
		t.Fatalf("ttl = %v, want %v", r.cfg.ttl, timex.SectorURICacheTTLDefault)
	}
	if r.cfg.negativeTTL != defaultNegativeTTL {
		t.Fatalf("negativeTTL = %v, want %v", r.cfg.negativeTTL, defaultNegativeTTL)
	}
	if r.cfg.cacheMaxEntries != defaultCacheMaxEntries {
		t.Fatalf("cacheMaxEntries = %d, want %d", r.cfg.cacheMaxEntries, defaultCacheMaxEntries)
	}
	if r.cfg.clock != timex.SystemClock {
		t.Fatalf("clock not defaulted to timex.SystemClock")
	}
}

func TestResolve_CacheCardinalityStaysBounded(t *testing.T) {
	t.Parallel()

	body, _ := json.Marshal([]string{"https://rp.example/cb"})
	srv := newJSONServer(t, body, jsonContentType)
	r := resolverWithServer(t, srv, WithCacheMaxEntries(4))

	for i := range 40 {
		uri := fmt.Sprintf("%s?client=%d", srv.URL, i)
		if _, err := r.Resolve(context.Background(), uri, []string{"https://rp.example/cb"}); err != nil {
			t.Fatalf("Resolve(%d): %v", i, err)
		}
		if got := r.cache.Len(); got > 4 {
			t.Fatalf("cache entries=%d exceeds max=4 after URL %d", got, i)
		}
	}
}

func TestResolve_ExpiredEntryIsEvicted(t *testing.T) {
	t.Parallel()

	body, _ := json.Marshal([]string{"https://rp.example/cb"})
	srv := newJSONServer(t, body, jsonContentType)
	clock := &fakeClock{now: time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)}
	r := resolverWithServer(t, srv, WithClock(clock), WithTTL(time.Minute))
	if _, err := r.Resolve(context.Background(), srv.URL, []string{"https://rp.example/cb"}); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	clock.now = clock.now.Add(2 * time.Minute)
	if got := r.cache.Len(); got != 0 {
		t.Fatalf("cache entries=%d want 0 after TTL expiry", got)
	}
}

func TestResolve_SingleflightCollapsesConcurrentFetches(t *testing.T) {
	t.Parallel()

	body, _ := json.Marshal([]string{"https://rp.example/cb"})
	var hits atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) == 1 {
			close(entered)
		}
		<-release
		w.Header().Set("Content-Type", jsonContentType)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	r := resolverWithServer(t, srv)

	const concurrent = 24
	start := make(chan struct{})
	errs := make(chan error, concurrent)
	var wg sync.WaitGroup
	for range concurrent {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := r.Resolve(context.Background(), srv.URL, []string{"https://rp.example/cb"})
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
			t.Fatalf("Resolve: %v", err)
		}
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("upstream hits=%d want 1", got)
	}
}

func TestResolve_NegativeCacheRecoversAfterTTL(t *testing.T) {
	t.Parallel()

	body, _ := json.Marshal([]string{"https://rp.example/cb"})
	var (
		hits atomic.Int32
		fail atomic.Bool
	)
	fail.Store(true)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		if fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", jsonContentType)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	clock := &fakeClock{now: time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)}
	r := resolverWithServer(t, srv, WithClock(clock), WithNegativeCacheTTL(5*time.Second))

	if _, err := r.Resolve(context.Background(), srv.URL, []string{"https://rp.example/cb"}); !errors.Is(err, ErrSectorFetch) {
		t.Fatalf("first Resolve err=%v want ErrSectorFetch", err)
	}
	if _, err := r.Resolve(context.Background(), srv.URL, []string{"https://rp.example/cb"}); !errors.Is(err, ErrSectorFetch) {
		t.Fatalf("negative-cache Resolve err=%v want ErrSectorFetch", err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("upstream hits=%d want 1 inside negative TTL", got)
	}

	clock.now = clock.now.Add(6 * time.Second)
	fail.Store(false)
	if _, err := r.Resolve(context.Background(), srv.URL, []string{"https://rp.example/cb"}); err != nil {
		t.Fatalf("recovery Resolve: %v", err)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("upstream hits=%d want 2 after negative TTL", got)
	}
}
