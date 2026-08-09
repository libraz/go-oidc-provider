package jwks_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/jwks"
	"github.com/libraz/go-oidc-provider/internal/keys"
)

func newECDSAKey(tb testing.TB) *ecdsa.PrivateKey {
	tb.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("generate key: %v", err)
	}
	return priv
}

func newTestSet(tb testing.TB) *keys.Set {
	tb.Helper()
	set, err := keys.NewSet([]keys.Entry{{KeyID: "sig-1", Signer: newECDSAKey(tb)}})
	if err != nil {
		tb.Fatalf("NewSet: %v", err)
	}
	return set
}

// fetchETag performs an unconditional GET and returns the emitted
// validator.
func fetchETag(tb testing.TB, srv *httptest.Server) string {
	tb.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, http.NoBody)
	resp, err := srv.Client().Do(req)
	if err != nil {
		tb.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	etag := resp.Header.Get("ETag")
	if etag == "" {
		tb.Fatal("response missing ETag")
	}
	return etag
}

// fetchKids performs an unconditional GET and returns the published
// kid list in document order alongside the emitted validator.
func fetchKids(tb testing.TB, srv *httptest.Server) ([]string, string) {
	tb.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, http.NoBody)
	resp, err := srv.Client().Do(req)
	if err != nil {
		tb.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	var payload struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		tb.Fatalf("decode: %v", err)
	}
	kids := make([]string, 0, len(payload.Keys))
	for _, k := range payload.Keys {
		kids = append(kids, k.Kid)
	}
	return kids, resp.Header.Get("ETag")
}

// conditionalGET issues method against srv with the supplied
// If-None-Match value and returns the status code, asserting that a
// 304 carries no body.
func conditionalGET(tb testing.TB, srv *httptest.Server, method, ifNoneMatch string) int {
	tb.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), method, srv.URL, http.NoBody)
	req.Header.Set("If-None-Match", ifNoneMatch)
	resp, err := srv.Client().Do(req)
	if err != nil {
		tb.Fatalf("%s: %v", method, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		tb.Fatalf("read body: %v", err)
	}
	if len(body) != 0 && (resp.StatusCode == http.StatusNotModified || method == http.MethodHead) {
		tb.Errorf("%s status=%d returned %d body bytes, want none", method, resp.StatusCode, len(body))
	}
	return resp.StatusCode
}

func TestHandler_GetReturnsJWKSJSON(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(jwks.Handler(newTestSet(t)))
	t.Cleanup(srv.Close)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, http.NoBody)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/jwk-set+json" {
		t.Errorf("Content-Type=%q want application/jwk-set+json", got)
	}
	if got := resp.Header.Get("Cache-Control"); got != jwks.CacheControl {
		t.Errorf("Cache-Control=%q want %q", got, jwks.CacheControl)
	}
	if jwks.CacheControl != "public, max-age=3600, stale-while-revalidate=3600" {
		t.Fatalf("CacheControl = %q, want 1h default cache", jwks.CacheControl)
	}

	var payload struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(payload.Keys) != 1 {
		t.Fatalf("keys=%d want 1", len(payload.Keys))
	}
	if payload.Keys[0]["kid"] != "sig-1" {
		t.Errorf("kid=%v want sig-1", payload.Keys[0]["kid"])
	}
}

func TestHandler_HeadOmitsBody(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(jwks.Handler(newTestSet(t)))
	t.Cleanup(srv.Close)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodHead, srv.URL, http.NoBody)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("HEAD: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Cache-Control"); got != jwks.CacheControl {
		t.Errorf("Cache-Control missing on HEAD")
	}
}

func TestHandler_RejectsNonGet(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(jwks.Handler(newTestSet(t)))
	t.Cleanup(srv.Close)

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		req, _ := http.NewRequestWithContext(context.Background(), method, srv.URL, http.NoBody)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("%s: %v", method, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s status=%d want 405", method, resp.StatusCode)
		}
		if got := resp.Header.Get("Allow"); got != "GET, HEAD" {
			t.Errorf("%s Allow=%q want GET, HEAD", method, got)
		}
	}
}

// TestHandler_EmitsETag locks down the strong validator we serve with
// every successful JWKS response. RFC 7232 §2.3 requires the value to
// be quoted; the implementation hashes the marshalled body so any
// kid / public key change rolls the ETag without manual bookkeeping.
func TestHandler_EmitsETag(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(jwks.Handler(newTestSet(t)))
	t.Cleanup(srv.Close)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, http.NoBody)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	etag := resp.Header.Get("ETag")
	if etag == "" {
		t.Fatal("ETag header missing")
	}
	if etag[0] != '"' || etag[len(etag)-1] != '"' {
		t.Errorf("ETag=%q must be RFC 7232 quoted", etag)
	}
}

// TestHandler_IfNoneMatchReturns304 covers conditional GET. RPs that
// already cached the JWKS replay the ETag in If-None-Match; the
// handler must answer 304 with no body and stamp the same ETag /
// Cache-Control on the response so downstream caches stay coherent.
func TestHandler_IfNoneMatchReturns304(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(jwks.Handler(newTestSet(t)))
	t.Cleanup(srv.Close)

	first, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, http.NoBody)
	resp1, err := srv.Client().Do(first)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp1.Body.Close()
	etag := resp1.Header.Get("ETag")
	if etag == "" {
		t.Fatal("first response missing ETag")
	}

	cond, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, http.NoBody)
	cond.Header.Set("If-None-Match", etag)
	resp2, err := srv.Client().Do(cond)
	if err != nil {
		t.Fatalf("conditional GET: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusNotModified {
		t.Errorf("status=%d want 304", resp2.StatusCode)
	}
	if got := resp2.Header.Get("ETag"); got != etag {
		t.Errorf("304 ETag=%q want %q", got, etag)
	}
}

// TestHandler_IfNoneMatchWeakValidatorReturns304 pins the weak
// comparison function RFC 9110 §8.8.3.2 mandates for If-None-Match: an
// intermediary that weakens the strong ETag we emitted still gets a
// 304, because only the opaque portion of the entity-tag participates
// in the comparison.
func TestHandler_IfNoneMatchWeakValidatorReturns304(t *testing.T) {
	t.Parallel()

	// Cleanup, not defer: the parallel subtests below resume only after
	// this function returns, so a deferred Close would shut the server
	// down before any of them dials it.
	srv := httptest.NewServer(jwks.Handler(newTestSet(t)))
	t.Cleanup(srv.Close)

	etag := fetchETag(t, srv)

	for name, header := range map[string]string{
		"weak":            "W/" + etag,
		"strong":          etag,
		"list":            `"other", ` + etag,
		"weak in list":    `W/"other",W/` + etag,
		"padded list":     "  " + etag + "  ,  \"other\"",
		"malformed mixed": `W/, "unterminated, , ` + etag,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := conditionalGET(t, srv, http.MethodGet, header); got != http.StatusNotModified {
				t.Errorf("If-None-Match %q: status=%d want 304", header, got)
			}
		})
	}
}

// TestHandler_IfNoneMatchNonMatchingReturns200 covers the inputs that
// must NOT satisfy the comparison: a different opaque tag, and entries
// too malformed to be entity-tags at all. The malformed cases also
// guard the parser against panicking on short or unterminated input.
func TestHandler_IfNoneMatchNonMatchingReturns200(t *testing.T) {
	t.Parallel()

	// Cleanup, not defer: see TestHandler_IfNoneMatchWeakValidatorReturns304.
	srv := httptest.NewServer(jwks.Handler(newTestSet(t)))
	t.Cleanup(srv.Close)

	etag := fetchETag(t, srv)
	unquoted := etag[1 : len(etag)-1]

	for name, header := range map[string]string{
		"different tag":    `"stale"`,
		"weak different":   `W/"stale"`,
		"unquoted":         unquoted,
		"weak unquoted":    "W/" + unquoted,
		"lowercase weak":   "w/" + etag,
		"empty list":       ",,,",
		"lone quote":       `"`,
		"weak marker only": "W/",
		"blank":            "   ",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := conditionalGET(t, srv, http.MethodGet, header); got != http.StatusOK {
				t.Errorf("If-None-Match %q: status=%d want 200", header, got)
			}
		})
	}
}

// TestHandler_HeadHonoursIfNoneMatch covers the conditional HEAD an RP
// issues to check its cached copy without paying for the body.
func TestHandler_HeadHonoursIfNoneMatch(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(jwks.Handler(newTestSet(t)))
	t.Cleanup(srv.Close)

	etag := fetchETag(t, srv)
	if got := conditionalGET(t, srv, http.MethodHead, "W/"+etag); got != http.StatusNotModified {
		t.Errorf("conditional HEAD status=%d want 304", got)
	}
}

// TestHandler_IfNoneMatchWildcardReturns304 covers the RFC 9110
// §8.8.3.2 wildcard, which RPs sometimes use during cache warm-up.
func TestHandler_IfNoneMatchWildcardReturns304(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(jwks.Handler(newTestSet(t)))
	t.Cleanup(srv.Close)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, http.NoBody)
	req.Header.Set("If-None-Match", "*")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotModified {
		t.Errorf("status=%d want 304", resp.StatusCode)
	}
}

func TestHandler_IfNoneMatchMismatchReturns200(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(jwks.Handler(newTestSet(t)))
	t.Cleanup(srv.Close)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, http.NoBody)
	req.Header.Set("If-None-Match", `"stale"`)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status=%d want 200", resp.StatusCode)
	}
}

// TestHandler_RotationAwareCacheControl pins the cache window against
// the rotation state: while RotationActive reports true the handler
// emits the short Cache-Control header, so an RP holding a cached JWKS
// revalidates well before the normal window would have expired and
// picks up the incoming key. Once the predicate flips back to false
// the long-cache header returns.
func TestHandler_RotationAwareCacheControl(t *testing.T) {
	t.Parallel()

	var rotating atomic.Bool
	h := jwks.HandlerWithOptions(newTestSet(t), jwks.HandlerOptions{
		RotationActive: rotating.Load,
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	get := func() string {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, http.NoBody)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		return resp.Header.Get("Cache-Control")
	}

	if got := get(); got != jwks.CacheControl {
		t.Errorf("idle Cache-Control=%q want %q", got, jwks.CacheControl)
	}

	rotating.Store(true)
	if got := get(); got != jwks.CacheControlRotating {
		t.Errorf("rotating Cache-Control=%q want %q", got, jwks.CacheControlRotating)
	}

	rotating.Store(false)
	if got := get(); got != jwks.CacheControl {
		t.Errorf("post-rotation Cache-Control=%q want %q", got, jwks.CacheControl)
	}
}

// TestHandler_RetirementRerendersBody pins the invalidation of the
// memoised body. An encryption key leaves the published JWKS once its
// retirement deadline passes, so the handler must re-render and roll
// the ETag; a cache that is never invalidated keeps advertising the
// retired kid under the old validator, and RPs would encrypt to a
// recipient the OP no longer decrypts for.
func TestHandler_RetirementRerendersBody(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var nanos atomic.Int64
	nanos.Store(base.UnixNano())
	clock := func() time.Time { return time.Unix(0, nanos.Load()).UTC() }

	encSet, err := keys.NewEncryptionSet([]keys.EncryptionEntry{
		{KeyID: "enc-live", PrivateKey: newECDSAKey(t)},
		{KeyID: "enc-retiring", PrivateKey: newECDSAKey(t), NotAfter: base.Add(time.Hour)},
	}, keys.WithClock(clock))
	if err != nil {
		t.Fatalf("NewEncryptionSet: %v", err)
	}

	srv := httptest.NewServer(jwks.HandlerWithOptions(newTestSet(t), jwks.HandlerOptions{
		EncryptionSet: encSet,
	}))
	t.Cleanup(srv.Close)

	beforeKids, beforeETag := fetchKids(t, srv)
	if want := []string{"sig-1", "enc-live", "enc-retiring"}; !slices.Equal(beforeKids, want) {
		t.Fatalf("kids=%v want %v", beforeKids, want)
	}
	if _, repeatETag := fetchKids(t, srv); repeatETag != beforeETag {
		t.Errorf("ETag changed without a key change: %q then %q", beforeETag, repeatETag)
	}

	nanos.Store(base.Add(2 * time.Hour).UnixNano())

	afterKids, afterETag := fetchKids(t, srv)
	if want := []string{"sig-1", "enc-live"}; !slices.Equal(afterKids, want) {
		t.Errorf("post-retirement kids=%v want %v", afterKids, want)
	}
	if afterETag == beforeETag {
		t.Errorf("ETag=%q unchanged across retirement", afterETag)
	}
	if conditionalGET(t, srv, http.MethodGet, beforeETag) != http.StatusOK {
		t.Error("retired ETag still satisfies If-None-Match")
	}
	if conditionalGET(t, srv, http.MethodGet, afterETag) != http.StatusNotModified {
		t.Error("current ETag does not satisfy If-None-Match")
	}
}

// TestHandler_RetiredSigningKidStaysPublished pins the invariant the
// body cache rests on: the signing half of the document is fixed for
// the lifetime of a [keys.Set], so only the encryption half can vary
// between two requests. Signing keys past their retirement deadline
// stay in JWKS for RP cache warmth — the OP withdraws trust on the
// verification path instead — which is what keeps the signing half
// clock-independent.
func TestHandler_RetiredSigningKidStaysPublished(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	set, err := keys.NewSet(
		[]keys.Entry{
			{KeyID: "sig-active", Signer: newECDSAKey(t)},
			{KeyID: "sig-retired", Signer: newECDSAKey(t), NotAfter: base},
		},
		keys.WithClock(func() time.Time { return base.Add(2 * time.Hour) }),
	)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}

	srv := httptest.NewServer(jwks.Handler(set))
	t.Cleanup(srv.Close)

	kids, _ := fetchKids(t, srv)
	if want := []string{"sig-active", "sig-retired"}; !slices.Equal(kids, want) {
		t.Errorf("kids=%v want %v", kids, want)
	}
}

// TestHandler_RotationActiveNilTreatedAsInactive verifies the
// zero-value HandlerOptions behaves like the no-rotation default.
func TestHandler_RotationActiveNilTreatedAsInactive(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(jwks.HandlerWithOptions(newTestSet(t), jwks.HandlerOptions{}))
	t.Cleanup(srv.Close)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, http.NoBody)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("Cache-Control"); got != jwks.CacheControl {
		t.Errorf("Cache-Control=%q want %q", got, jwks.CacheControl)
	}
}
