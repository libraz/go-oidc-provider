package recovery

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// batchSize is the number of codes minted in a single batch. Ten is the
// industry default (GitHub, Google, Auth0, AWS) and is intentionally not
// configurable in v1.0 to keep the user-facing UX consistent across
// embedders.
const batchSize = 10

// maxBatchSize is the upper cap [Verifier.Verify] applies to
// [store.RecoveryBatch.Codes] before walking the slot list. The
// generator only ever emits [batchSize] entries; a stored batch
// claiming more is treated as store-integrity corruption rather than
// a legitimate state, because each unmatched slot triggers an
// argon2id derivation under [argon2id.DefaultPolicy] and an unbounded
// slot count would let one verify call burn unbounded CPU / memory.
//
// The cap is deliberately loose (1.6× the generator size) so a
// future revision that adjusts [batchSize] does not silently make
// every existing verifier reject pre-bump batches; tightening to
// exactly [batchSize] is a v1.x conversation, not a v1.0 invariant.
const maxBatchSize = 16

// codeChars is the number of alphabet characters in a single code,
// excluding the formatting hyphen. Ten characters of base32 entropy
// gives 50 bits per code; a successful guess against an unconsumed
// batch of ten therefore needs ~2^46 attempts in expectation, which is
// well above brute-force reach for any deployment that rate-limits the
// verifier.
const codeChars = 10

// crockfordAlphabet is Crockford's base32 alphabet. The deliberate
// omissions are I, L, O, and U: I/L/1 are visually ambiguous, O/0 are
// visually ambiguous, and U is reserved by the Crockford spec for a
// future "obscenity safeguard" — codes are presented to users on
// printed sheets and read back manually, so removing the ambiguous
// glyphs cuts transcription errors substantially. The alphabet still
// carries 32 symbols, preserving the full 5 bits of entropy per
// character that base32 encoding implies. crypto/rand.Int handles
// modular bias on its own through rejection sampling, so the alphabet
// length need not be a power of two for [generateOneCode] to remain
// uniform.
const crockfordAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// GenerateBatch returns ten freshly-minted plaintext recovery codes
// formatted as XXXXX-XXXXX. The caller is expected to hash each code
// through [hashCode] before persistence and to surface the plaintext
// list to the user exactly once: the package's display-once invariant
// (see the package godoc) lives at this boundary.
//
// The function reads from crypto/rand and returns an error if the
// system entropy source is unavailable; in that case no codes are
// returned (a partial batch would tempt callers into displaying it).
func GenerateBatch() ([]string, error) {
	out := make([]string, 0, batchSize)
	for range batchSize {
		c, err := generateOneCode()
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// generateOneCode returns a single XXXXX-XXXXX recovery code. Each
// character is drawn uniformly from [crockfordAlphabet] using
// crypto/rand.Int, which performs rejection sampling internally so the
// distribution is uniform regardless of the alphabet length. The
// returned string is the human-friendly form; the hash and verify
// paths normalise by stripping the hyphen.
func generateOneCode() (string, error) {
	raw := make([]byte, codeChars)
	limit := big.NewInt(int64(len(crockfordAlphabet)))
	for i := range codeChars {
		n, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return "", fmt.Errorf("recovery: read entropy: %w", err)
		}
		raw[i] = crockfordAlphabet[int(n.Int64())]
	}
	return crockfordEncode(raw), nil
}

// crockfordEncode formats the supplied codeChars-byte alphabet slice
// into the human-friendly XXXXX-XXXXX form. The hyphen is purely
// cosmetic — the hash and verify paths re-normalise by stripping it —
// but it sharply reduces transcription errors when users read codes
// off a printed sheet. The function is unexported because it has a
// single internal caller and the length precondition (len(raw) ==
// codeChars) is enforced by construction at that site.
func crockfordEncode(raw []byte) string {
	half := codeChars / 2
	return string(raw[:half]) + "-" + string(raw[half:])
}

// normalise strips whitespace and the formatting hyphen and uppercases
// the remainder. It is the canonical form fed into both [hashCode] and
// [verifyCode] so that a user typing "abcde-12345" matches the stored
// hash of "ABCDE12345". Characters outside [crockfordAlphabet] are not
// rewritten — Crockford's spec maps O->0, I/L->1 — because the
// generated codes never contain ambiguous glyphs, so any such input is
// already a typo and SHOULD fall through to ErrCodeInvalid rather than
// being silently corrected.
//
// The function operates on bytes rather than runes because every
// alphabet character is single-byte ASCII and the only legal
// non-alphabet characters (hyphen, space, tab) are also single-byte;
// a multi-byte rune in the input survives the loop unchanged and the
// hash comparison rejects it like any other typo.
func normalise(s string) string {
	out := make([]byte, 0, len(s))
	for i := range len(s) {
		c := s[i]
		switch {
		case c == '-' || c == ' ' || c == '\t':
			continue
		case c >= 'a' && c <= 'z':
			out = append(out, c-('a'-'A'))
		default:
			out = append(out, c)
		}
	}
	return string(out)
}
