package password

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// ErrInvalidHash is returned when [Verify] is given a stored hash it
// cannot parse. The verifier collapses every structural issue (wrong
// number of segments, unknown algorithm, non-integer parameter,
// malformed base64) onto this single sentinel so a caller cannot
// distinguish "you tampered with the encoding" from "you tampered
// with the parameters" through the error type.
var ErrInvalidHash = errors.New("password: hash encoding is invalid")

// ErrPasswordMismatch is returned by [Verify] when the candidate
// password does not match the supplied stored hash. The caller MUST
// surface a generic invalid-credentials prompt: distinguishing
// mismatch from "username not found" leaks user enumeration.
var ErrPasswordMismatch = errors.New("password: candidate does not match")

// maxKeyLength is a defensive cap on the derived-key length the
// verifier accepts. A legitimate encoding emitted by a sane
// password-hashing library stays well under this; a malformed stored
// value claiming a giant key is rejected before invoking
// [argon2.IDKey].
const maxKeyLength = 1024

// maxStoredHashLength caps the encoded hash bytes the verifier will
// even attempt to parse. Real PHC encodings are <200 bytes; the cap
// prevents a misconfigured store from feeding the verifier a
// pathological input.
const maxStoredHashLength = 1024

// Verify reports whether candidate matches the supplied PHC argon2id
// encoding. Structural issues with the encoded value collapse onto
// [ErrInvalidHash]; a parsed-but-mismatched comparison returns
// [ErrPasswordMismatch] so the caller can branch on user-visible
// error messages without leaking which way the comparison failed.
//
// The comparison is constant-time: a partial match cannot leak the
// prefix length through timing.
//
// Unlike the recovery-code verifier, password input is NOT
// canonicalised: case, whitespace, and unicode-equivalence variants
// all hash distinctly. Embedders enforcing case-insensitive password
// matches must pre-process before storing the hash.
func Verify(encoded []byte, candidate string) error {
	if len(encoded) == 0 || len(encoded) > maxStoredHashLength {
		return ErrInvalidHash
	}
	parsed, err := parseArgon2idEncoding(string(encoded))
	if err != nil {
		return err
	}
	keyLen := len(parsed.hash)
	if keyLen <= 0 || keyLen > maxKeyLength {
		return ErrInvalidHash
	}
	derived := argon2.IDKey([]byte(candidate), parsed.salt, parsed.iterations, parsed.memory, parsed.parallelism, uint32(keyLen))
	if subtle.ConstantTimeCompare(derived, parsed.hash) != 1 {
		return ErrPasswordMismatch
	}
	return nil
}

// argon2idHash is the parsed view of a stored argon2id encoding.
type argon2idHash struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	salt        []byte
	hash        []byte
}

// parseArgon2idEncoding parses the modular-crypt argon2id format. It
// returns [ErrInvalidHash] on any structural issue so the verifier
// never leaks why a comparison failed.
func parseArgon2idEncoding(s string) (argon2idHash, error) {
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return argon2idHash{}, ErrInvalidHash
	}
	if !strings.HasPrefix(parts[2], "v=") {
		return argon2idHash{}, ErrInvalidHash
	}
	version, err := strconv.Atoi(parts[2][2:])
	if err != nil || version != argon2.Version {
		return argon2idHash{}, ErrInvalidHash
	}
	mem, iter, par, err := parseArgon2idParams(parts[3])
	if err != nil {
		return argon2idHash{}, err
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return argon2idHash{}, ErrInvalidHash
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return argon2idHash{}, ErrInvalidHash
	}
	return argon2idHash{
		memory:      mem,
		iterations:  iter,
		parallelism: par,
		salt:        salt,
		hash:        hash,
	}, nil
}

// parseArgon2idParams extracts the m/t/p triple from the parameter
// segment ("m=...,t=...,p=...") of an argon2id modular-crypt encoding.
// Errors collapse onto [ErrInvalidHash] so the caller cannot tell
// which sub-field tripped the parse.
func parseArgon2idParams(seg string) (mem, iter uint32, par uint8, err error) {
	for _, kv := range strings.Split(seg, ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return 0, 0, 0, ErrInvalidHash
		}
		n, parseErr := strconv.ParseUint(v, 10, 32)
		if parseErr != nil {
			return 0, 0, 0, ErrInvalidHash
		}
		switch k {
		case "m":
			mem = uint32(n)
		case "t":
			iter = uint32(n)
		case "p":
			if n > 255 {
				return 0, 0, 0, ErrInvalidHash
			}
			par = uint8(n)
		default:
			return 0, 0, 0, ErrInvalidHash
		}
	}
	if mem == 0 || iter == 0 || par == 0 {
		return 0, 0, 0, ErrInvalidHash
	}
	return mem, iter, par, nil
}
