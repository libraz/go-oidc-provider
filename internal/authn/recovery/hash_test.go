package recovery_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authn/recovery"
)

func TestHashCode_RoundTrip(t *testing.T) {
	t.Parallel()

	const plain = "ABCDE-12345"
	enc, err := recovery.HashCodeForTest(plain)
	if err != nil {
		t.Fatalf("hashCode: %v", err)
	}
	if !strings.HasPrefix(enc, "$argon2id$") {
		t.Errorf("encoding=%q does not start with $argon2id$", enc)
	}
	if err := recovery.VerifyCodeForTest(plain, enc); err != nil {
		t.Errorf("verifyCode roundtrip: %v", err)
	}
}

func TestVerifyCode_NormalisesCaseAndHyphen(t *testing.T) {
	t.Parallel()

	const stored = "ABCDE-12345"
	enc, err := recovery.HashCodeForTest(stored)
	if err != nil {
		t.Fatalf("hashCode: %v", err)
	}
	// Lowercase, missing hyphen, surrounding whitespace — all
	// canonicalise to the same form.
	for _, variant := range []string{
		"ABCDE-12345",
		"abcde-12345",
		"ABCDE12345",
		"abcde12345",
		"  ABCDE-12345  ",
		"abcde 12345",
	} {
		t.Run(variant, func(t *testing.T) {
			t.Parallel()
			if err := recovery.VerifyCodeForTest(variant, enc); err != nil {
				t.Errorf("verifyCode(%q): %v", variant, err)
			}
		})
	}
}

func TestVerifyCode_RejectsWrongCode(t *testing.T) {
	t.Parallel()

	enc, err := recovery.HashCodeForTest("ABCDE-12345")
	if err != nil {
		t.Fatalf("hashCode: %v", err)
	}
	if err := recovery.VerifyCodeForTest("FGHJK-67890", enc); !errors.Is(err, recovery.ErrCodeInvalid) {
		t.Errorf("err=%v want ErrCodeInvalid", err)
	}
}

func TestVerifyCode_RejectsMalformedEncoding(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"empty":            "",
		"not_argon2id":     "$bcrypt$v=19$m=65536,t=3,p=1$c2FsdA$aGFzaA",
		"missing_segments": "$argon2id$v=19$m=65536,t=3,p=1$c2FsdA",
		"bad_version":      "$argon2id$v=99$m=65536,t=3,p=1$c2FsdA$aGFzaA",
		"bad_param_kv":     "$argon2id$v=19$mem=65536,t=3,p=1$c2FsdA$aGFzaA",
		"non_numeric_m":    "$argon2id$v=19$m=abc,t=3,p=1$c2FsdA$aGFzaA",
		"missing_p":        "$argon2id$v=19$m=65536,t=3$c2FsdA$aGFzaA",
		"bad_salt_b64":     "$argon2id$v=19$m=65536,t=3,p=1$!!!$aGFzaA",
		"bad_hash_b64":     "$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$!!!",
	}
	for name, enc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := recovery.VerifyCodeForTest("anything", enc); !errors.Is(err, recovery.ErrInvalidHash) {
				t.Errorf("err=%v want ErrInvalidHash", err)
			}
		})
	}
}

func TestHashCode_SaltsAreDistinct(t *testing.T) {
	t.Parallel()

	const plain = "ABCDE-12345"
	a, err := recovery.HashCodeForTest(plain)
	if err != nil {
		t.Fatalf("hashCode a: %v", err)
	}
	b, err := recovery.HashCodeForTest(plain)
	if err != nil {
		t.Fatalf("hashCode b: %v", err)
	}
	if a == b {
		t.Errorf("two encodings of the same plaintext are identical (salt is reused)")
	}
}
