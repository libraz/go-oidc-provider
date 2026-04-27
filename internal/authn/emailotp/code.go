package emailotp

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	// codeDigits is the length of the decimal OTP. Six is the
	// industry-standard length for email / SMS OTPs and the same
	// length the [auth.email_otp.verify] FieldSpec advertises.
	codeDigits = 6

	// saltLength is the per-record salt the package mixes into the
	// hash. Sixteen bytes (128 bits) is well above the spec
	// requirement and matches the entropy used elsewhere in the
	// library for record-binding salts.
	saltLength = 16
)

// generateCode draws codeDigits decimal digits from crypto/rand. The
// implementation reads a uint64, reduces modulo 10^codeDigits, and
// zero-pads. The 64-bit modulo bias for a 10^6 modulus is below
// 2^-43 — orders of magnitude smaller than a guess-the-code attack —
// so the straight reduction is acceptable for OTP purposes.
func generateCode() (string, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("emailotp: read random: %w", err)
	}
	modulus := uint64(1)
	for range codeDigits {
		modulus *= 10
	}
	val := binary.BigEndian.Uint64(buf[:]) % modulus
	return fmt.Sprintf("%0*d", codeDigits, val), nil
}

// generateSalt draws saltLength random bytes from crypto/rand for the
// per-record salt mixed into [hashCode].
func generateSalt() ([]byte, error) {
	buf := make([]byte, saltLength)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("emailotp: read salt: %w", err)
	}
	return buf, nil
}

// hashCode computes SHA-256(salt || subject || code). Subject is
// bound into the digest so a record copied from one user to another
// fails verify. SHA-256 is cheap by design — the brute-force defence
// is the FailedCount counter, not hash strength — so callers MUST
// gate verify behind the rate-limit machinery in [Verifier].
func hashCode(salt []byte, subject, code string) []byte {
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(subject))
	h.Write([]byte(code))
	return h.Sum(nil)
}

// constantTimeEqualHashes reports whether two SHA-256 digests are
// equal in constant time.
func constantTimeEqualHashes(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// constantTimeEqualEmails compares two addresses case-insensitively
// in constant time. Real-world email addresses are case-insensitive
// for the domain (RFC 5321) and, in practice, the local-part as well;
// folding both sides to lowercase before the compare keeps casing
// typos from rejecting an otherwise legitimate match.
func constantTimeEqualEmails(a, b string) bool {
	la, lb := strings.ToLower(a), strings.ToLower(b)
	if len(la) != len(lb) {
		// subtle.ConstantTimeCompare returns 0 on length mismatch
		// already; the explicit branch keeps the comparison cost
		// bounded by max(len(a),len(b)) without padding allocations.
		return false
	}
	return subtle.ConstantTimeCompare([]byte(la), []byte(lb)) == 1
}

// maskEmail returns the privacy-preserving rendering of addr for
// [interaction.EmailOTPVerifyPromptData.MaskedEmail]. The format is
// "x***@y***" — first rune of the local part, first rune of the
// domain. An invalid input (no @, empty side) collapses to "***" so
// the SPA always renders something non-empty.
func maskEmail(addr string) string {
	at := strings.IndexByte(addr, '@')
	if at < 1 || at >= len(addr)-1 {
		return "***"
	}
	return maskFirstRune(addr[:at]) + "@" + maskFirstRune(addr[at+1:])
}

func maskFirstRune(s string) string {
	if s == "" {
		return "***"
	}
	for _, r := range s {
		return string(r) + "***"
	}
	return "***"
}
