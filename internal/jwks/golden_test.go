package jwks_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/jwks"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/testutil/golden"
)

// fixedTestKey is the RFC 7517 §A.2 ECDSA P-256 sample. Using a published
// test vector keeps the JWKS golden fixture stable across machines and
// makes the cryptographic provenance auditable: a reader can grep the RFC
// to confirm we are not pasting a real key.
const (
	fixedTestKeyX = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"
	fixedTestKeyY = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
	fixedTestKeyD = "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
)

func newFixedSet(tb testing.TB) *keys.Set {
	tb.Helper()
	priv := decodeFixedKey(tb)
	set, err := keys.NewSet([]keys.Entry{{KeyID: "sig-golden", Signer: priv}})
	if err != nil {
		tb.Fatalf("NewSet: %v", err)
	}
	return set
}

func decodeFixedKey(tb testing.TB) *ecdsa.PrivateKey {
	tb.Helper()
	xb := mustB64(tb, fixedTestKeyX)
	yb := mustB64(tb, fixedTestKeyY)
	db := mustB64(tb, fixedTestKeyD)
	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(xb),
			Y:     new(big.Int).SetBytes(yb),
		},
		D: new(big.Int).SetBytes(db),
	}
	return priv
}

func mustB64(tb testing.TB, s string) []byte {
	tb.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		tb.Fatalf("decode %q: %v", s, err)
	}
	return b
}

// TestJWKS_Golden_DocumentShape locks the JSON shape (keys array, kid /
// kty / crv / x / y order, alg / use values) the OP advertises at /jwks.
// RP libraries cache this document; field reordering or rename would force
// every downstream cache to invalidate.
func TestJWKS_Golden_DocumentShape(t *testing.T) {
	t.Parallel()

	set := newFixedSet(t)
	got := set.JWKS()
	golden.JSON(t, got, "testdata/jwks.golden.json")
}

// TestJWKS_Golden_HandlerHeaders pins the response headers the handler
// stamps on every successful read. The Cache-Control window is part of the
// rotation contract from §F.6 of the product design.
func TestJWKS_Golden_HandlerHeaders(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(jwks.Handler(newFixedSet(t)))
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	type capture struct {
		Status      int    `json:"status"`
		ContentType string `json:"content_type"`
		CacheCtrl   string `json:"cache_control"`
	}
	got := capture{
		Status:      resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		CacheCtrl:   resp.Header.Get("Cache-Control"),
	}
	golden.JSON(t, got, "testdata/jwks_response.golden.json")

	// Decode the body to confirm it round-trips through json.Decoder; the
	// raw byte stream is tested via the JWKS shape golden above.
	var body struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Keys) != 1 {
		t.Fatalf("keys=%d want 1", len(body.Keys))
	}
}
