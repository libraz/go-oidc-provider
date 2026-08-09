package devicecode

import (
	"crypto/rand"
	"errors"
	"strings"
)

// UserCodeLength is the canonical user_code length in characters. 8
// characters of Crockford Base32 yield 40 bits of entropy, which is
// the margin the user_code brute-force gate is sized against.
const UserCodeLength = 8

// crockfordAlphabet is the Crockford Base32 alphabet (RFC 4648 with
// 0/O and 1/I/L collapsed and the alphabet rotated so the visually
// ambiguous pairs canonicalise without a lookup table). Length 32.
const crockfordAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// ErrUserCodeLength is returned by [NormaliseUserCode] when the input
// produces a canonical form whose length does not match
// [UserCodeLength]. The verification page surfaces this as the
// generic "code not recognised" error so the caller cannot distinguish
// "wrong length" from "valid length but no record".
var ErrUserCodeLength = errors.New("devicecode: user_code has wrong length after normalisation")

// ErrUserCodeCharset is returned by [NormaliseUserCode] when the
// canonical form contains a character that is not in the Crockford
// Base32 alphabet. Same surfacing posture as [ErrUserCodeLength].
var ErrUserCodeCharset = errors.New("devicecode: user_code contains characters outside the Crockford Base32 alphabet")

// NewUserCode draws [UserCodeLength] characters from
// [crockfordAlphabet] using crypto/rand. The returned value is the
// canonical form: uppercase, no separators, every character drawn
// from the 32-symbol alphabet.
//
// The function uses unbiased rejection sampling: each byte from the
// CSPRNG is masked to 5 bits and reused only when the masked value
// indexes into the alphabet (always true at width 32, so no bias is
// possible). The function returns an error only when the CSPRNG
// itself fails — a condition the library treats as fatal at the
// caller.
func NewUserCode() (string, error) {
	out := make([]byte, UserCodeLength)
	buf := make([]byte, UserCodeLength)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	for i := range UserCodeLength {
		out[i] = crockfordAlphabet[buf[i]&0x1f]
	}
	return string(out), nil
}

// NormaliseUserCode canonicalises a user-typed user_code: uppercases
// the input, strips separators (' ', '-', '_'), folds the
// visually-ambiguous Crockford symbols (O→0, I→1, L→1) so a user
// who reads "OIL" and types "0IL" still hits the same record, and
// rejects any value whose canonical form is not exactly
// [UserCodeLength] characters of Crockford Base32. The returned
// string is comparable to records persisted via [NewUserCode] byte-
// for-byte.
func NormaliseUserCode(raw string) (string, error) {
	upper := strings.ToUpper(raw)
	var b strings.Builder
	b.Grow(len(upper))
	for _, r := range upper {
		switch r {
		case ' ', '-', '_', '\t':
			continue
		case 'O':
			b.WriteByte('0')
		case 'I', 'L':
			b.WriteByte('1')
		default:
			b.WriteRune(r)
		}
	}
	canonical := b.String()
	if len(canonical) != UserCodeLength {
		return "", ErrUserCodeLength
	}
	for i := range len(canonical) {
		if !strings.ContainsRune(crockfordAlphabet, rune(canonical[i])) {
			return "", ErrUserCodeCharset
		}
	}
	return canonical, nil
}

// MaxUserCodeStrikes is the brute-force ceiling per [DeviceCode]
// record. After [MaxUserCodeStrikes] mismatched submissions the
// verification page calls [store.DeviceCodeStore.Deny] with reason
// "user_code_lockout" and the device must restart the flow.
const MaxUserCodeStrikes uint8 = 5
