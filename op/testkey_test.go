package op_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

// newTestKey returns a freshly generated ES256 signing key suitable for
// satisfying [op.WithKeyset] in unit tests. Call sites supply their own
// stable kid so failures pin the specific key under test.
func newTestKey(tb testing.TB, kid string) op.SigningKey {
	tb.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("generate key: %v", err)
	}
	return op.SigningKey{KeyID: kid, Signer: priv}
}

// validKeyset returns a single-entry [op.Keyset] for tests that just need
// [op.WithKeyset] to satisfy validation.
func validKeyset(tb testing.TB) op.Keyset {
	tb.Helper()
	return op.Keyset{newTestKey(tb, "test-1")}
}
