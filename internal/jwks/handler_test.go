package jwks_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
