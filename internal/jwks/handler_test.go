package jwks_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/jwks"
	"github.com/libraz/go-oidc-provider/internal/keys"
)

func newTestSet(tb testing.TB) *keys.Set {
	tb.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("generate key: %v", err)
	}
	set, err := keys.NewSet([]keys.Entry{{KeyID: "sig-1", Signer: priv}})
	if err != nil {
		tb.Fatalf("NewSet: %v", err)
	}
	return set
}

func TestHandler_GetReturnsJWKSJSON(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(jwks.Handler(newTestSet(t)))
	defer srv.Close()

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
	defer srv.Close()

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
	defer srv.Close()

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
	defer srv.Close()

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
	defer srv.Close()

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

// TestHandler_IfNoneMatchWildcardReturns304 covers the RFC 7232 §3.2
// wildcard, which RPs sometimes use during cache warm-up.
func TestHandler_IfNoneMatchWildcardReturns304(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(jwks.Handler(newTestSet(t)))
	defer srv.Close()

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
	defer srv.Close()

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

// TestHandler_RotationAwareCacheControl pins the L-JOSE-CACHE remediation:
// while RotationActive is true the handler emits the short
// Cache-Control header so RPs revalidate before the normal default
// expires; once the predicate flips back to false the long-cache
// header returns.
func TestHandler_RotationAwareCacheControl(t *testing.T) {
	t.Parallel()

	var rotating atomic.Bool
	h := jwks.HandlerWithOptions(newTestSet(t), jwks.HandlerOptions{
		RotationActive: rotating.Load,
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

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

// TestHandler_RotationActiveNilTreatedAsInactive verifies the
// zero-value HandlerOptions behaves like the no-rotation default.
func TestHandler_RotationActiveNilTreatedAsInactive(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(jwks.HandlerWithOptions(newTestSet(t), jwks.HandlerOptions{}))
	defer srv.Close()

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
