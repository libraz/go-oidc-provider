// White-box tests against the package-private fetcher helpers. Living
// in the same package avoids exporting the inline-keyset parser solely
// so the tests can reach it.
//
//nolint:testpackage // intentional white-box test for unexported helpers.
package jar

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

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/rpjwks"
	"github.com/libraz/go-oidc-provider/internal/timex"
)

// jwksJSON is the canonical RP-side JWKS document used in cache tests.
// The exact bytes are not material; only the parser-level shape and
// the headers the server emits are.
const jwksJSON = `{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","kid":"k1"}]}`

// unsupportedMemberJWK is a JWK the JOSE layer cannot turn into a key: an
// OKP curve outside the Ed25519 it implements. RPs publish members of this
// shape for ECDH-ES key agreement alongside their signing keys.
const unsupportedMemberJWK = `{"kty":"OKP","crv":"X25519","x":"hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo","use":"enc","kid":"enc-1"}`

// movableClock is a [timex.Clock] whose Now reading callers can shift.
// Tests use it to drive the cache's TTL expiry without sleeping.
type movableClock struct {
	now time.Time
}

func (m *movableClock) Now() time.Time { return m.now }

var _ timex.Clock = (*movableClock)(nil)

// jwksHandler returns an http.Handler that serves jwksJSON with the
// configured Cache-Control / ETag headers and counts the requests the
// caller observed. The atomic counter lets cache tests assert that
// the second fetch did not hit the network.
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

func TestJWKSCache_HitWithinTTL(t *testing.T) {
	t.Parallel()

	hits := &atomic.Int32{}
	srv := httptest.NewServer(jwksHandler("max-age=60", "", hits))
	defer srv.Close()

	clock := &movableClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	f := NewFetcher(clock)
	f.SetAllowPrivate(true) // httptest binds to 127.0.0.1.
	if _, err := f.Fetch(context.Background(), srv.URL); err != nil {
		t.Fatalf("fetch 1: %v", err)
	}
	clock.now = clock.now.Add(30 * time.Second)
	if _, err := f.Fetch(context.Background(), srv.URL); err != nil {
		t.Fatalf("fetch 2: %v", err)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("hits=%d want 1", got)
	}
}

// TestFetch_CallerCancellationDoesNotPoisonCache pins that a caller hanging
// up mid-fetch neither aborts the outbound request the other waiters share
// nor leaves a negative entry behind. The fetch runs inside a singleflight,
// so before the fix the first caller's request context was the one every
// collapsed caller depended on: an unauthenticated peer could disconnect
// mid-fetch and keep a client's keyset negative-cached indefinitely by
// repeating it.
func TestFetch_CallerCancellationDoesNotPoisonCache(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	inflight := make(chan struct{})
	var once sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(inflight) })
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write([]byte(jwksJSON))
	}))
	defer srv.Close()

	f := NewFetcher(timex.SystemClock)
	f.SetAllowPrivate(true) // httptest binds to 127.0.0.1.

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
}

// TestParseJWKS_KeepsSupportedKeyBesideUnsupportedOne pins RFC 7517 §5 on
// the fetched-keyset path: an RP publishing a key type this build cannot
// represent (an X25519 key for ECDH-ES, say) next to its signing key stays
// usable for JAR instead of failing the whole document.
func TestParseJWKS_KeepsSupportedKeyBesideUnsupportedOne(t *testing.T) {
	t.Parallel()

	body := `{"keys":[` + unsupportedMemberJWK + `,{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","kid":"k1"}]}`
	keys, err := parseJWKS([]byte(body))
	if err != nil {
		t.Fatalf("parseJWKS: %v", err)
	}
	if len(keys.Keys) != 1 || keys.Keys[0].KeyID != "k1" {
		t.Fatalf("parseJWKS returned kids %v, want [k1]", keyIDs(keys))
	}
}

// TestParseJWKS_RejectsKeysetWithoutAnySupportedKey confirms the tolerant
// decode still fails when nothing usable is left, so the verifier reports a
// fetch failure rather than silently holding an empty keyset.
func TestParseJWKS_RejectsKeysetWithoutAnySupportedKey(t *testing.T) {
	t.Parallel()

	if _, err := parseJWKS([]byte(`{"keys":[` + unsupportedMemberJWK + `]}`)); !errors.Is(err, ErrJWKSFetch) {
		t.Fatalf("err=%v want ErrJWKSFetch", err)
	}
}

func TestParseJWKS_RejectsExcessiveKeyCount(t *testing.T) {
	t.Parallel()

	body := `{"keys":[` + strings.Repeat(`{"kty":"EC"},`, rpjwks.MaxKeys) + `{"kty":"EC"}]}`
	if _, err := parseJWKS([]byte(body)); err == nil {
		t.Fatal("parseJWKS accepted an excessive key count")
	}
}

// Tracks: CVE-2026-48524 (PyJWT) — PyJWKClient refetched the JWKS
// endpoint whenever a token named a "kid" it had not cached, so an
// attacker minting tokens with random kid values turned each one into
// an outbound request at the client's JWKS host. The forced-refresh
// path exists here for the same legitimate reason (a rotated key the
// cache has not seen yet), and the throttle below is what keeps it from
// being an amplifier: the interval is per URL and does not consult the
// kid at all, so N distinct unknown kids inside one window still cost
// exactly one round-trip.
func TestFetchFresh_BypassesFreshCacheThenThrottles(t *testing.T) {
	t.Parallel()

	// A rotating server: the served kid flips after the first response so
	// a forced refetch observes a genuinely different keyset. hits counts
	// the network round-trips FetchFresh actually made.
	hits := &atomic.Int32{}
	body := func(kid string) string {
		return `{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","kid":"` + kid + `"}]}`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := hits.Add(1)
		w.Header().Set("Content-Type", "application/jwk-set+json")
		w.Header().Set("Cache-Control", "max-age=300")
		if n == 1 {
			_, _ = w.Write([]byte(body("k1")))
			return
		}
		_, _ = w.Write([]byte(body("k2")))
	}))
	defer srv.Close()

	clock := &movableClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	f := NewFetcher(clock)
	f.SetAllowPrivate(true) // httptest binds to 127.0.0.1.

	// Prime the positive cache (kid k1), well inside its 300s TTL.
	if _, err := f.Fetch(context.Background(), srv.URL); err != nil {
		t.Fatalf("prime fetch: %v", err)
	}

	// FetchFresh must bypass the still-fresh cache and observe the rotated
	// keyset (kid k2), even though a plain Fetch would return k1.
	got, err := f.FetchFresh(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("FetchFresh 1: %v", err)
	}
	if len(got.Keys) != 1 || got.Keys[0].KeyID != "k2" {
		t.Fatalf("FetchFresh returned kid %v, want k2", keyIDs(got))
	}
	if n := hits.Load(); n != 2 {
		t.Fatalf("hits=%d after first FetchFresh, want 2", n)
	}

	// A second FetchFresh inside the throttle window must not hit the
	// network; it returns the cached (now k2) keyset.
	got, err = f.FetchFresh(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("FetchFresh 2: %v", err)
	}
	if len(got.Keys) != 1 || got.Keys[0].KeyID != "k2" {
		t.Fatalf("throttled FetchFresh returned kid %v, want cached k2", keyIDs(got))
	}
	if n := hits.Load(); n != 2 {
		t.Errorf("hits=%d after throttled FetchFresh, want still 2", n)
	}

	// Past the throttle window a forced refetch is allowed again.
	clock.now = clock.now.Add(rpjwks.ForcedRefreshInterval + time.Second)
	if _, err := f.FetchFresh(context.Background(), srv.URL); err != nil {
		t.Fatalf("FetchFresh 3: %v", err)
	}
	if n := hits.Load(); n != 3 {
		t.Errorf("hits=%d after throttle window elapsed, want 3", n)
	}
}

func keyIDs(set *josev4.JSONWebKeySet) []string {
	out := make([]string, 0, len(set.Keys))
	for i := range set.Keys {
		out = append(out, set.Keys[i].KeyID)
	}
	return out
}

func TestJWKSCache_RevalidatesViaETag(t *testing.T) {
	t.Parallel()

	hits := &atomic.Int32{}
	srv := httptest.NewServer(jwksHandler("max-age=10", `"abc"`, hits))
	defer srv.Close()

	clock := &movableClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	f := NewFetcher(clock)
	f.SetAllowPrivate(true)
	if _, err := f.Fetch(context.Background(), srv.URL); err != nil {
		t.Fatalf("fetch 1: %v", err)
	}
	// Move past the cache TTL so the next fetch issues a conditional GET.
	clock.now = clock.now.Add(time.Hour)
	if _, err := f.Fetch(context.Background(), srv.URL); err != nil {
		t.Fatalf("fetch 2: %v", err)
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("hits=%d want 2 (one full + one conditional)", got)
	}
}

func TestJWKSCache_RejectsOversizeBody(t *testing.T) {
	t.Parallel()

	huge := strings.Repeat("X", int(rpjwks.DefaultMaxBodyBytes+1))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"keys":[`)
		_, _ = fmt.Fprint(w, huge)
		_, _ = fmt.Fprint(w, `]}`)
	}))
	defer srv.Close()
	f := NewFetcher(timex.SystemClock)
	f.SetAllowPrivate(true)
	_, err := f.Fetch(context.Background(), srv.URL)
	if !errors.Is(err, ErrJWKSFetch) {
		t.Fatalf("err=%v want ErrJWKSFetch", err)
	}
}

func TestJWKSCache_RejectsNonJSON(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html></html>"))
	}))
	defer srv.Close()
	f := NewFetcher(timex.SystemClock)
	f.SetAllowPrivate(true)
	_, err := f.Fetch(context.Background(), srv.URL)
	if !errors.Is(err, ErrJWKSFetch) {
		t.Fatalf("err=%v want ErrJWKSFetch", err)
	}
}

func TestJWKSCache_RejectsNon2xx(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	f := NewFetcher(timex.SystemClock)
	f.SetAllowPrivate(true)
	_, err := f.Fetch(context.Background(), srv.URL)
	if !errors.Is(err, ErrJWKSFetch) {
		t.Fatalf("err=%v want ErrJWKSFetch", err)
	}
}

func TestJWKSCache_RejectsLoopbackByDefault(t *testing.T) {
	t.Parallel()

	f := NewFetcher(timex.SystemClock)
	_, err := f.Fetch(context.Background(), "http://127.0.0.1:1/jwks")
	if !errors.Is(err, ErrJWKSFetch) {
		t.Fatalf("err=%v want ErrJWKSFetch", err)
	}
}

func TestJWKSCache_RejectsLocalhostByDefault(t *testing.T) {
	t.Parallel()

	f := NewFetcher(timex.SystemClock)
	_, err := f.Fetch(context.Background(), "http://localhost/jwks")
	if !errors.Is(err, ErrJWKSFetch) {
		t.Fatalf("err=%v want ErrJWKSFetch", err)
	}
}

func TestJWKSCache_RejectsRFC1918ByDefault(t *testing.T) {
	t.Parallel()

	f := NewFetcher(timex.SystemClock)
	_, err := f.Fetch(context.Background(), "http://10.0.0.1/jwks")
	if !errors.Is(err, ErrJWKSFetch) {
		t.Fatalf("err=%v want ErrJWKSFetch", err)
	}
}

// TestParseJWKS_EmptyBody confirms parseJWKS rejects an empty body
// rather than silently returning a zero-key set.
func TestParseJWKS_EmptyBody(t *testing.T) {
	t.Parallel()
	if _, err := parseJWKS(nil); !errors.Is(err, ErrJWKSFetch) {
		t.Fatalf("err=%v want ErrJWKSFetch", err)
	}
}

// TestParseJWKS_HappyPath confirms parseJWKS accepts a valid body and
// surfaces the parsed key.
func TestParseJWKS_HappyPath(t *testing.T) {
	t.Parallel()
	keys, err := parseJWKS([]byte(jwksJSON))
	if err != nil {
		t.Fatalf("parseJWKS: %v", err)
	}
	if len(keys.Keys) != 1 {
		t.Fatalf("Keys=%d want 1", len(keys.Keys))
	}
	jwk := keys.Keys[0]
	if jwk.KeyID != "k1" {
		t.Errorf("KeyID=%q want k1", jwk.KeyID)
	}
}

// countingTransport is a [http.RoundTripper] that delegates to its
// inner client but tags responses with the count of round-trips it
// observed. The fetcher's lazy client construction picks up exactly
// one transport, so a >0 count after a successful Fetch confirms the
// injection point flowed through.
type countingTransport struct {
	inner http.RoundTripper
	hits  atomic.Int32
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.hits.Add(1)
	return c.inner.RoundTrip(r)
}

// TestFetcher_SetBaseTransport confirms the injected transport is the
// one the lazy client uses. The test pairs SetBaseTransport with a
// countingTransport so a >0 hit count rules out the package-default
// transport silently winning under a misconfigured option layer.
func TestFetcher_SetBaseTransport(t *testing.T) {
	t.Parallel()

	hits := &atomic.Int32{}
	srv := httptest.NewServer(jwksHandler("max-age=60", "", hits))
	defer srv.Close()

	ct := &countingTransport{inner: http.DefaultTransport}
	f := NewFetcher(timex.SystemClock)
	f.SetAllowPrivate(true)
	f.SetBaseTransport(ct)
	if _, err := f.Fetch(context.Background(), srv.URL); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if got := ct.hits.Load(); got == 0 {
		t.Fatalf("custom transport saw 0 round-trips; injection lost")
	}
}
