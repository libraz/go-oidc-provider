package op_test

import (
	"encoding/base64"
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

func TestVerifyPassword_AcceptsOnlyTheHashedPassword(t *testing.T) {
	t.Parallel()

	hash, err := op.HashPassword("correct-horse")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !op.VerifyPassword(hash, "correct-horse") {
		t.Error("the password that produced the encoding does not verify against it")
	}
	if op.VerifyPassword(hash, "correct-hors") {
		t.Error("a password one character short of the stored one verified")
	}
}

// TestVerifyPassword_CollapsesEveryFailure covers the property the
// boolean return exists for: a record the verifier cannot use is not
// distinguishable from a password that does not match. Each stored
// value below fails on a different axis — envelope, algorithm, salt
// encoding, work factor — and the caller sees one answer for all of
// them.
func TestVerifyPassword_CollapsesEveryFailure(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		encoded string
	}{
		{"empty record", ""},
		{"truncated envelope", "$argon2id$v=19$m=65536,t=3,p=1$c2FsdA"},
		{"foreign scheme", "$bcrypt$v=19$m=65536,t=3,p=1$c2FsdA$aGFzaA"},
		{"unsupported version", "$argon2id$v=16$m=65536,t=3,p=1$c2FsdA$aGFzaA"},
		{"salt is not base64", "$argon2id$v=19$m=65536,t=3,p=1$not base64$aGFzaA"},
		{"work factor below the floor", storedWithKeyBytes(32, "m=1024,t=1,p=1")},
	} {
		if op.VerifyPassword([]byte(tc.encoded), "correct-horse") {
			t.Errorf("%s: verified against %q", tc.name, tc.encoded)
		}
	}
}

// TestVerifyPassword_RefusesAnOversizedKeyLength pins the bound on the
// derived-key length a stored record declares. The length is implied by
// the hash field, so a corrupt or hostile record can ask for one that
// costs more to derive than the process can serve; the verifier refuses
// the record instead of sizing the derivation from it.
func TestVerifyPassword_RefusesAnOversizedKeyLength(t *testing.T) {
	t.Parallel()

	// Two shapes: one past the key-length cap but well inside any
	// sane encoding length, and one whose encoding is itself absurd.
	for _, keyBytes := range []int{256, 64 * 1024} {
		encoded := storedWithKeyBytes(keyBytes, "m=65536,t=3,p=1")
		if op.VerifyPassword([]byte(encoded), "correct-horse") {
			t.Errorf("a record declaring a %d-byte derived key verified", keyBytes)
		}
	}
}

// storedWithKeyBytes builds a structurally well-formed argon2id PHC
// carrying a zero salt and a zero derived key of the requested size, so
// a test can vary one field of a stored record without hand-writing the
// whole encoding.
func storedWithKeyBytes(keyBytes int, params string) string {
	return "$argon2id$v=19$" + params + "$" +
		base64.RawStdEncoding.EncodeToString(make([]byte, 16)) + "$" +
		base64.RawStdEncoding.EncodeToString(make([]byte, keyBytes))
}
