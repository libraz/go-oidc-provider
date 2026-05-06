package recovery_test

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"

	"github.com/libraz/go-oidc-provider/internal/authn/recovery"
)

// hashWith builds a recovery-style argon2id PHC under arbitrary
// parameters so the policy-violation tests do not depend on the
// in-tree generator (which always uses production parameters).
func hashWith(t *testing.T, plain string, mem, iter uint32, par uint8, salt []byte) string {
	t.Helper()
	key := argon2.IDKey([]byte(strings.ToLower(strings.ReplaceAll(plain, "-", ""))),
		salt, iter, mem, par, 32)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, mem, iter, par,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)
}

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

// TestVerifyCode_RejectsBelowOWASPFloor pins the rule that a stored
// hash whose Argon2id parameters fall below the OWASP 2024 floor
// (m≥19MiB, t≥2) MUST collapse onto [recovery.ErrInvalidHash]
// before any derivation runs. The code is then untouched but the
// verifier wall-clock cost is bounded.
func TestVerifyCode_RejectsBelowOWASPFloor(t *testing.T) {
	t.Parallel()
	salt := []byte("0123456789abcdef")
	cases := map[string]struct {
		mem  uint32
		iter uint32
	}{
		"memory-below-min":     {18 * 1024, 2},
		"iterations-below-min": {19 * 1024, 1},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			enc := hashWith(t, "ABCDE-12345", tc.mem, tc.iter, 1, salt)
			if err := recovery.VerifyCodeForTest("ABCDE-12345", enc); !errors.Is(err, recovery.ErrInvalidHash) {
				t.Fatalf("VerifyCode(%s) err=%v want ErrInvalidHash", name, err)
			}
		})
	}
}

// TestVerifyCode_RejectsOversizedSalt confirms the salt-length clamp
// catches a stored hash whose salt exceeds the
// [argon2id.DefaultPolicy] cap. Without the bound, a corrupted store
// could feed the verifier a kilobyte salt per slot and turn one
// recovery flow into a memory-amplification vector.
func TestVerifyCode_RejectsOversizedSalt(t *testing.T) {
	t.Parallel()
	bigSalt := make([]byte, 256)
	for i := range bigSalt {
		bigSalt[i] = byte(i)
	}
	enc := hashWith(t, "ABCDE-12345", 19*1024, 2, 1, bigSalt)
	if err := recovery.VerifyCodeForTest("ABCDE-12345", enc); !errors.Is(err, recovery.ErrInvalidHash) {
		t.Fatalf("VerifyCode(oversized-salt) err=%v want ErrInvalidHash", err)
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
