package password_test

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"

	"github.com/libraz/go-oidc-provider/internal/authn/password"
)

// hashWith produces a PHC argon2id encoding of plain under the
// supplied parameters. The helper uses [argon2.IDKey] directly so the
// tests do not depend on any package-internal hash production path
// the verifier might also exercise.
func hashWith(t *testing.T, plain string, memory, iterations uint32, parallelism uint8, salt []byte) []byte {
	t.Helper()
	key := argon2.IDKey([]byte(plain), salt, iterations, memory, parallelism, 32)
	return []byte(fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		memory, iterations, parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	))
}

func TestVerify_HappyPath(t *testing.T) {
	t.Parallel()
	salt := []byte("0123456789abcdef")
	enc := hashWith(t, "correct horse", 64*1024, 3, 1, salt)
	if err := password.Verify(enc, "correct horse"); err != nil {
		t.Fatalf("Verify: unexpected error on matching candidate: %v", err)
	}
}

func TestVerify_Mismatch(t *testing.T) {
	t.Parallel()
	salt := []byte("0123456789abcdef")
	enc := hashWith(t, "correct horse", 64*1024, 3, 1, salt)
	err := password.Verify(enc, "battery staple")
	if !errors.Is(err, password.ErrPasswordMismatch) {
		t.Fatalf("Verify: expected ErrPasswordMismatch, got %v", err)
	}
}

func TestVerify_RejectsCaseDifference(t *testing.T) {
	t.Parallel()
	salt := []byte("0123456789abcdef")
	enc := hashWith(t, "Correct Horse", 64*1024, 3, 1, salt)
	// password verify is case-sensitive: case-folded candidate must NOT match.
	if err := password.Verify(enc, "correct horse"); !errors.Is(err, password.ErrPasswordMismatch) {
		t.Fatalf("Verify: case-folded match should fail, got %v", err)
	}
}

func TestVerify_RejectsEmptyEncoding(t *testing.T) {
	t.Parallel()
	if err := password.Verify(nil, "pw"); !errors.Is(err, password.ErrInvalidHash) {
		t.Fatalf("Verify(nil): expected ErrInvalidHash, got %v", err)
	}
	if err := password.Verify([]byte{}, "pw"); !errors.Is(err, password.ErrInvalidHash) {
		t.Fatalf("Verify(\"\"): expected ErrInvalidHash, got %v", err)
	}
}

func TestVerify_RejectsMalformedEncodings(t *testing.T) {
	t.Parallel()
	salt := []byte("0123456789abcdef")
	good := string(hashWith(t, "pw", 64*1024, 3, 1, salt))
	cases := map[string]string{
		"empty":                "",
		"random-text":          "this is not a hash",
		"missing-segments":     "$argon2id$",
		"wrong-algorithm":      strings.Replace(good, "$argon2id$", "$argon2i$", 1),
		"bad-version":          strings.Replace(good, "v=19", "v=99", 1),
		"unknown-param":        strings.Replace(good, "m=65536", "x=65536", 1),
		"non-numeric":          strings.Replace(good, "m=65536", "m=fast", 1),
		"missing-m":            strings.Replace(good, "m=65536,", "", 1),
		"bad-base64-salt":      good[:strings.Index(good, "$0")+1] + "!!!" + good[strings.Index(good, "$0")+4:],
		"missing-hash-segment": good[:strings.LastIndex(good, "$")],
		"giant-input":          "$argon2id$v=19$m=64,t=1,p=1$" + strings.Repeat("A", 4096) + "$AAAA",
	}
	for name, enc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := password.Verify([]byte(enc), "pw"); !errors.Is(err, password.ErrInvalidHash) {
				t.Fatalf("Verify(%s): expected ErrInvalidHash, got %v", name, err)
			}
		})
	}
}

func TestVerify_AcceptsAlternateParameters(t *testing.T) {
	t.Parallel()
	// The verifier is parameter-tolerant: it must accept any valid PHC
	// argon2id hash, not just the library's preferred tuning. This
	// matters when an embedder migrates from a different tool that
	// produced the existing hashes.
	salt := []byte("alternative-salt")
	enc := hashWith(t, "tuned-pw", 32*1024, 2, 2, salt)
	if err := password.Verify(enc, "tuned-pw"); err != nil {
		t.Fatalf("Verify with m=32MiB,t=2,p=2: %v", err)
	}
}

// TestVerify_RejectsBelowOWASPFloor pins the new behaviour the
// 2026-05-07 audit (S-02 / S-03) flagged: the password verifier
// MUST refuse a stored hash whose Argon2id parameters fall below
// the OWASP 2024 floor (m≥19MiB, t≥2). Pre-audit the password
// path admitted such hashes silently, while the client_secret path
// already rejected them — the migration to the shared
// internal/argon2id helper closes the gap.
func TestVerify_RejectsBelowOWASPFloor(t *testing.T) {
	t.Parallel()
	salt := []byte("0123456789abcdef")
	cases := map[string]struct {
		mem  uint32
		iter uint32
		par  uint8
	}{
		"memory-below-min":     {18 * 1024, 2, 1}, // < 19 MiB
		"iterations-below-min": {19 * 1024, 1, 1}, // < 2
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			enc := hashWith(t, "pw", tc.mem, tc.iter, tc.par, salt)
			if err := password.Verify(enc, "pw"); !errors.Is(err, password.ErrInvalidHash) {
				t.Fatalf("Verify(%s) err=%v want ErrInvalidHash", name, err)
			}
		})
	}
}

// TestVerify_RejectsOversizedSalt confirms the policy clamp catches
// a stored hash whose salt exceeds the [argon2id.DefaultPolicy] cap.
// Without the bound, a corrupted store could feed the verifier a
// kilobyte salt and burn unbounded memory inside [argon2.IDKey].
func TestVerify_RejectsOversizedSalt(t *testing.T) {
	t.Parallel()
	bigSalt := make([]byte, 256) // > MaxSaltLength=128
	for i := range bigSalt {
		bigSalt[i] = byte(i)
	}
	enc := hashWith(t, "pw", 19*1024, 2, 1, bigSalt)
	if err := password.Verify(enc, "pw"); !errors.Is(err, password.ErrInvalidHash) {
		t.Fatalf("Verify(oversized-salt) err=%v want ErrInvalidHash", err)
	}
}

// TestVerify_RejectsDuplicateParameter confirms the parser refuses a
// PHC that re-declares m / t / p with a different value (m=64,m=128).
// Pre-audit the parser's last-value-wins behaviour produced an
// ambiguous wire shape; the shared parser now returns
// [argon2id.ErrEncoding] (collapsed onto [password.ErrInvalidHash]).
func TestVerify_RejectsDuplicateParameter(t *testing.T) {
	t.Parallel()
	salt := []byte("0123456789abcdef")
	good := string(hashWith(t, "pw", 19*1024, 2, 1, salt))
	bogus := strings.Replace(good, "m=19456,t=2,p=1", "m=19456,m=20000,t=2,p=1", 1)
	if err := password.Verify([]byte(bogus), "pw"); !errors.Is(err, password.ErrInvalidHash) {
		t.Fatalf("Verify(duplicate-m) err=%v want ErrInvalidHash", err)
	}
}
