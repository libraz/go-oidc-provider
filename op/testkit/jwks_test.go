package testkit_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// TestSignedJWT_ES256Key confirms the happy path still produces a compact
// JWS, so the guard added for the mismatch cases does not reject the key
// NewProvider generates.
func TestSignedJWT_ES256Key(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	got, err := tk.SignedJWT(map[string]any{"iss": tk.Issuer})
	if err != nil {
		t.Fatalf("SignedJWT: %v", err)
	}
	if got == "" {
		t.Fatal("SignedJWT returned an empty serialisation")
	}
}

// TestSignedJWT_NonES256SignerMismatch pins the documented contract of
// ErrSignerMismatch. SigningKey is an exported mutable field, so a test may
// swap in a key the ES256 policy does not admit; every such key must come
// back as the sentinel rather than as a wrapped go-jose error.
func TestSignedJWT_NonES256SignerMismatch(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate p384 key: %v", err)
	}

	cases := map[string]crypto.Signer{
		"rsa":         rsaKey,
		"ed25519":     edKey,
		"ecdsa p-384": p384Key,
		"nil":         nil,
		"typed nil":   (*ecdsa.PrivateKey)(nil),
	}
	for name, signer := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tk := testkit.NewProvider(t)
			tk.SigningKey = op.SigningKey{KeyID: tk.SigningKey.KeyID, Signer: signer}
			if _, err := tk.SignedJWT(map[string]any{"iss": tk.Issuer}); !errors.Is(err, testkit.ErrSignerMismatch) {
				t.Errorf("SignedJWT error = %v, want ErrSignerMismatch", err)
			}
		})
	}
}
