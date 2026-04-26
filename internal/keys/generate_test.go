package keys_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/keys"
)

func TestGenerateES256_ReturnsP256Signer(t *testing.T) {
	t.Parallel()

	entry, err := keys.GenerateES256("kid-1")
	if err != nil {
		t.Fatalf("GenerateES256: %v", err)
	}
	if entry.KeyID != "kid-1" {
		t.Fatalf("KeyID=%q want %q", entry.KeyID, "kid-1")
	}
	pub, ok := entry.Signer.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key type %T, want *ecdsa.PublicKey", entry.Signer.Public())
	}
	if pub.Curve != elliptic.P256() {
		t.Fatalf("curve=%v want P-256", pub.Curve.Params().Name)
	}
}

func TestGenerateES256_RejectsEmptyKeyID(t *testing.T) {
	t.Parallel()

	_, err := keys.GenerateES256("")
	if !errors.Is(err, keys.ErrInvalidKey) {
		t.Fatalf("err=%v want ErrInvalidKey", err)
	}
}

func TestGenerateES256_AcceptedByNewSet(t *testing.T) {
	t.Parallel()

	entry, err := keys.GenerateES256("kid-set")
	if err != nil {
		t.Fatalf("GenerateES256: %v", err)
	}
	if _, err := keys.NewSet([]keys.Entry{entry}); err != nil {
		t.Fatalf("NewSet: %v", err)
	}
}
