package totp

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238 mandates HMAC-SHA-1 for interop with every authenticator app.
	"encoding/binary"
	"fmt"
	"time"
)

// stepSeconds is the RFC 6238 §5.2 default time step. The library does
// not expose this as a configuration knob: every authenticator app on
// the market hard-codes 30 seconds, and changing it would silently
// break enrolled users.
const stepSeconds = 30

// digits is the RFC 6238 §5.3 truncation length. Six is the de-facto
// standard; eight digits is permitted by the spec but unsupported by
// many authenticator apps. The value is paired with [pow10]; changing
// it requires updating both constants together.
const digits = 6

// pow10 caches 10^digits so the dynamic-truncation modulus is a
// constant. With digits == 6 the value is 1_000_000; pre-computing it
// avoids recomputing on every Code call and keeps the truncation
// expression cleanly readable.
const pow10 = 1_000_000

// step converts wall-clock time t into the RFC 6238 counter T:
//
//	T = floor((Unix(t) - T0) / X)
//
// with T0 = 0 (Unix epoch) and X = stepSeconds. Times before the epoch
// are clamped to step 0; the spec is silent on negative T because it
// cannot occur in practice — RFC 6238 §4.1 defines T0 as the Unix epoch
// and assumes monotonic forward time.
func step(t time.Time) uint64 {
	s := t.Unix()
	if s < 0 {
		return 0
	}
	return uint64(s / stepSeconds)
}

// codeAtStep computes the 6-digit TOTP for an explicit counter value.
// It is the unit-tested core of [Code]; the wall-clock-driven entry
// point delegates to this function after computing T.
//
// The implementation follows RFC 4226 §5.3 dynamic truncation verbatim:
// HMAC-SHA-1(secret, counter) → take the low nibble of the last byte
// as an offset, read the four bytes at that offset as a big-endian
// uint32, mask the high bit, and reduce modulo 10^digits.
func codeAtStep(secret []byte, counter uint64) string {
	var ctr [8]byte
	binary.BigEndian.PutUint64(ctr[:], counter)
	mac := hmac.New(sha1.New, secret)
	// hash.Hash.Write is documented to never return an error; the
	// stdlib HMAC implementation honours that contract.
	_, _ = mac.Write(ctr[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	binCode := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", digits, binCode%pow10)
}

// Code returns the 6-digit zero-padded TOTP for the supplied secret at
// time t. The function is RFC 6238 with the interop defaults documented
// in the package godoc: SHA-1, 30-second step, 6 digits, T0 = epoch.
//
// The output is always exactly 6 ASCII characters; callers that compare
// it to user input MUST use [crypto/subtle.ConstantTimeCompare] to
// avoid leaking the prefix length through timing.
func Code(secret []byte, t time.Time) string {
	return codeAtStep(secret, step(t))
}
