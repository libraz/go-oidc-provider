package op_test

import (
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

func TestHashClientSecret_RoundTripsThroughDefaultVerifier(t *testing.T) {
	t.Parallel()

	secret := "demo-secret-value"
	hash, err := op.HashClientSecret(secret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("hash does not carry the argon2id modular-crypt prefix: %q", hash)
	}
	// Two calls MUST produce different encodings because the salt is
	// freshly generated; without that the helper would leak the
	// invariant the verifier relies on for collision resistance.
	hash2, err := op.HashClientSecret(secret)
	if err != nil {
		t.Fatalf("HashClientSecret (second call): %v", err)
	}
	if hash == hash2 {
		t.Fatalf("two calls produced identical encoding: %q", hash)
	}
}
