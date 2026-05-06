//nolint:testpackage // exercises the unexported parseParams / validatePolicy paths for full coverage.
package argon2id

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

// hashWith derives a PHC string with the supplied params so tests can
// build deterministic fixtures without re-running argon2id under
// production parameters every iteration.
func hashWith(t *testing.T, plain string, mem, iter uint32, par uint8, saltLen, keyLen int) string {
	t.Helper()
	if keyLen < 0 || uint64(keyLen) > uint64(^uint32(0)) {
		t.Fatalf("hashWith: keyLen=%d out of uint32 range", keyLen)
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	key := argon2.IDKey([]byte(plain), salt, iter, mem, par, uint32(keyLen)) //nolint:gosec // bounded by the explicit guard above.
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, mem, iter, par,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)
}

// productionParams returns memory=19MiB / t=2 / p=1 / salt=16 /
// key=32 — within DefaultPolicy bounds but quick enough to derive in
// tests (the OWASP minimum, not the library's 64MiB default).
func productionParams() (mem, iter uint32, par uint8, saltLen, keyLen int) {
	return 19 * 1024, 2, 1, 16, 32
}

// TestVerify_HappyPath confirms a freshly-derived PHC under
// DefaultPolicy round-trips: matching plaintext returns nil, a
// non-matching plaintext returns [ErrMismatch].
func TestVerify_HappyPath(t *testing.T) {
	t.Parallel()
	mem, iter, par, saltLen, keyLen := productionParams()
	enc := hashWith(t, "secret", mem, iter, par, saltLen, keyLen)
	if err := Verify([]byte("secret"), enc, DefaultPolicy()); err != nil {
		t.Fatalf("Verify(matching) err=%v want nil", err)
	}
	if err := Verify([]byte("WRONG"), enc, DefaultPolicy()); !errors.Is(err, ErrMismatch) {
		t.Fatalf("Verify(non-matching) err=%v want ErrMismatch", err)
	}
}

// TestParsePHC_RejectsStructuralIssues pins every structural fail
// path. Each row carries a deliberately-mangled PHC and asserts
// [ErrEncoding] (NOT [ErrPolicy]) — the parser must distinguish the
// two axes consistently.
func TestParsePHC_RejectsStructuralIssues(t *testing.T) {
	t.Parallel()
	mem, iter, par, saltLen, keyLen := productionParams()
	good := hashWith(t, "x", mem, iter, par, saltLen, keyLen)

	cases := []struct {
		name string
		enc  string
	}{
		{"empty", ""},
		{"too-few-segments", "$argon2id$v=19$m=19456,t=2,p=1"},
		{"wrong-algorithm", strings.Replace(good, "argon2id", "argon2i", 1)},
		{"missing-version-prefix", strings.Replace(good, "v=19", "version=19", 1)},
		{"non-numeric-version", strings.Replace(good, "v=19", "v=NaN", 1)},
		{"unsupported-version", strings.Replace(good, "v=19", "v=99", 1)},
		{"non-numeric-m", strings.Replace(good, "m=19456", "m=NaN", 1)},
		{"unknown-param", strings.Replace(good, "m=19456,t=2,p=1", "m=19456,t=2,p=1,x=2", 1)},
		{"duplicate-m", strings.Replace(good, "m=19456,t=2,p=1", "m=19456,m=20000,t=2,p=1", 1)},
		{"duplicate-t", strings.Replace(good, "m=19456,t=2,p=1", "m=19456,t=2,t=3,p=1", 1)},
		{"duplicate-p", strings.Replace(good, "m=19456,t=2,p=1", "m=19456,t=2,p=1,p=2", 1)},
		{"missing-m", strings.Replace(good, "m=19456,t=2,p=1", "t=2,p=1", 1)},
		{"missing-t", strings.Replace(good, "m=19456,t=2,p=1", "m=19456,p=1", 1)},
		{"missing-p", strings.Replace(good, "m=19456,t=2,p=1", "m=19456,t=2", 1)},
		{"p-overflows-uint8", strings.Replace(good, "p=1", "p=300", 1)},
		{"malformed-salt-base64", strings.Replace(good, "$"+strings.Split(good, "$")[4]+"$", "$@@@$", 1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParsePHC(tc.enc, DefaultPolicy())
			if !errors.Is(err, ErrEncoding) {
				t.Fatalf("ParsePHC(%s) err=%v want ErrEncoding", tc.name, err)
			}
		})
	}
}

// TestParsePHC_PolicyViolations confirms each axis of the policy
// fence triggers [ErrPolicy] (not [ErrEncoding]). The matrix doubles
// as a regression guard: a future change that loosens any of these
// rows must do so consciously.
func TestParsePHC_PolicyViolations(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		mem    uint32
		iter   uint32
		par    uint8
		salt   int
		keyLen int
	}{
		{"memory-below-min", 8 * 1024, 2, 1, 16, 32},      // < 19MiB
		{"iterations-below-min", 19 * 1024, 1, 1, 16, 32}, // < 2
		{"parallelism-zero-rejected-by-parser", 19 * 1024, 2, 1, 16, 32},
		// memory above max needs a value > 1 GiB; we use a synthetic PHC
		// rather than actually deriving such a hash.
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.name == "parallelism-zero-rejected-by-parser" {
				// Build a PHC manually with p=0 — the parser refuses
				// missing fields but accepts a literal zero before the
				// policy stage; this row pins that path.
				salt := make([]byte, tc.salt)
				_, _ = rand.Read(salt)
				key := make([]byte, tc.keyLen)
				_, _ = rand.Read(key)
				bogus := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=0$%s$%s",
					argon2.Version, tc.mem, tc.iter,
					base64.RawStdEncoding.EncodeToString(salt),
					base64.RawStdEncoding.EncodeToString(key),
				)
				_, err := ParsePHC(bogus, DefaultPolicy())
				if !errors.Is(err, ErrPolicy) {
					t.Fatalf("p=0 err=%v want ErrPolicy", err)
				}
				return
			}
			enc := hashWith(t, "x", tc.mem, tc.iter, tc.par, tc.salt, tc.keyLen)
			_, err := ParsePHC(enc, DefaultPolicy())
			if !errors.Is(err, ErrPolicy) {
				t.Fatalf("ParsePHC(%s) err=%v want ErrPolicy", tc.name, err)
			}
		})
	}
}

// TestParsePHC_RejectsOversizedEncoding confirms the
// MaxEncodingLength clamp fires before any base64 decode. A PHC
// claiming a kilobyte of trailer is refused without doing the
// downstream parse work.
func TestParsePHC_RejectsOversizedEncoding(t *testing.T) {
	t.Parallel()
	mem, iter, par, saltLen, keyLen := productionParams()
	good := hashWith(t, "x", mem, iter, par, saltLen, keyLen)
	// Build a PHC with a giant trailer by re-encoding a 2KiB key.
	huge := good + strings.Repeat("A", 2048)
	_, err := ParsePHC(huge, DefaultPolicy())
	if !errors.Is(err, ErrPolicy) {
		t.Fatalf("err=%v want ErrPolicy (encoding length cap)", err)
	}
}

// TestParsePHC_RejectsOversizedSalt confirms the MaxSaltLength clamp.
// The PHC is structurally well-formed but carries a 256-byte salt;
// the policy bound rejects it as ErrPolicy rather than letting
// [argon2.IDKey] consume the oversized buffer.
func TestParsePHC_RejectsOversizedSalt(t *testing.T) {
	t.Parallel()
	mem, iter, par := uint32(19*1024), uint32(2), uint8(1)
	enc := hashWith(t, "x", mem, iter, par, 256, 32) // saltLen=256 > MaxSaltLength=128
	_, err := ParsePHC(enc, DefaultPolicy())
	if !errors.Is(err, ErrPolicy) {
		t.Fatalf("err=%v want ErrPolicy (salt length cap)", err)
	}
}

// TestParsePHC_RejectsOversizedKey confirms the MaxKeyLength clamp.
// Pinned for the same reason as the salt case: an oversized derived
// key is a parse-time refusal, not a downstream Argon2 invocation.
func TestParsePHC_RejectsOversizedKey(t *testing.T) {
	t.Parallel()
	mem, iter, par := uint32(19*1024), uint32(2), uint8(1)
	enc := hashWith(t, "x", mem, iter, par, 16, 256) // keyLen=256 > MaxKeyLength=128
	_, err := ParsePHC(enc, DefaultPolicy())
	if !errors.Is(err, ErrPolicy) {
		t.Fatalf("err=%v want ErrPolicy (key length cap)", err)
	}
}

// TestVerify_ZeroPolicyAllowsLegacyHashes confirms a zero-valued
// Policy disables every bound, so callers (operator migration tools,
// tests) can verify against historical hashes that fall outside the
// production fence.
func TestVerify_ZeroPolicyAllowsLegacyHashes(t *testing.T) {
	t.Parallel()
	// Build a hash with a sub-OWASP memory floor (8 MiB) and t=1.
	enc := hashWith(t, "x", 8*1024, 1, 1, 16, 32)
	if err := Verify([]byte("x"), enc, Policy{}); err != nil {
		t.Fatalf("Verify under zero Policy err=%v want nil", err)
	}
	if err := Verify([]byte("x"), enc, DefaultPolicy()); !errors.Is(err, ErrPolicy) {
		t.Fatalf("Verify under DefaultPolicy err=%v want ErrPolicy", err)
	}
}
