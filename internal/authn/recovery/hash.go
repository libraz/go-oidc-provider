package recovery

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// argon2idParams carries the parameter set used for every recovery
// code hashed by this package. The values come from OWASP's 2024
// password-hashing guidance (m=64MiB, t=3, p=1, salt=16, key=32) and
// match the [github.com/libraz/go-oidc-provider/internal/authn].Argon2idDefaults
// reference impl used for client_secret hashing — but the recovery
// package keeps the constants private and intentionally NOT
// configurable in v1.0. Tunability is a future-version surface; for now
// every recovery batch hashes under the same parameters, which keeps
// the verifier path branch-free and avoids a footgun where embedders
// pick weaker parameters than they realise.
type argon2idParams struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

// argon2idDefaults is the immutable parameter set for [hashCode] and
// [verifyCode].
//
//nolint:gochecknoglobals // immutable config vector; no per-instance tuning.
var argon2idDefaults = argon2idParams{
	memory:      64 * 1024,
	iterations:  3,
	parallelism: 1,
	saltLength:  16,
	keyLength:   32,
}

// maxKeyLength is a defensive cap on the derived-key length the
// verifier accepts. A legitimate encoding emitted by [hashCode] stays
// well under this; a malformed stored value claiming a giant key is
// rejected before invoking [argon2.IDKey].
const maxKeyLength = 1024

// ErrInvalidHash is returned when [verifyCode] is given a stored hash
// it cannot parse. The verifier collapses every structural issue
// (wrong number of segments, unknown algorithm, non-integer parameter,
// malformed base64) onto this single sentinel so a caller cannot
// distinguish "you tampered with the encoding" from "you tampered with
// the parameters" through the error type.
var ErrInvalidHash = errors.New("recovery: hash encoding is invalid")

// hashCode derives an argon2id encoding of plain using the package's
// fixed parameter set. The salt is sourced from crypto/rand and the
// returned string is the modular-crypt encoding
// `$argon2id$v=...$m=...,t=...,p=...$salt$hash`. The plaintext is
// canonicalised through [normalise] first so that "abcde-12345" and
// "ABCDE12345" hash to the same value.
func hashCode(plain string) (string, error) {
	p := argon2idDefaults
	salt := make([]byte, p.saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("recovery: read salt: %w", err)
	}
	canonical := normalise(plain)
	key := argon2.IDKey([]byte(canonical), salt, p.iterations, p.memory, p.parallelism, p.keyLength)
	enc := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		p.memory, p.iterations, p.parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)
	return enc, nil
}

// verifyCode reports whether plain matches the supplied modular-crypt
// argon2id encoding. The plaintext is canonicalised through [normalise]
// first so user input formatting differences (case, hyphen, spaces)
// don't matter. Structural issues with the encoded value collapse onto
// [ErrInvalidHash]; a parsed-but-mismatched comparison returns
// [ErrCodeInvalid] so the caller can branch on user-visible error
// messages without leaking which way the comparison failed.
//
// The comparison is constant-time: a partial match cannot leak the
// prefix length through timing.
func verifyCode(plain, encoded string) error {
	parsed, err := parseArgon2idEncoding(encoded)
	if err != nil {
		return err
	}
	keyLen := len(parsed.hash)
	// argon2.IDKey accepts uint32 for the key length; the parser caps
	// the hash bytes at the maximum the encoder can emit (a few hundred
	// bytes), so the conversion below is safe. The bound check is
	// defensive: a malformed encoding could in theory carry a
	// pathological length.
	if keyLen <= 0 || keyLen > maxKeyLength {
		return ErrInvalidHash
	}
	canonical := normalise(plain)
	candidate := argon2.IDKey([]byte(canonical), parsed.salt, parsed.iterations, parsed.memory, parsed.parallelism, uint32(keyLen))
	if subtle.ConstantTimeCompare(candidate, parsed.hash) != 1 {
		return ErrCodeInvalid
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

// parseArgon2idEncoding parses the modular-crypt format produced by
// [hashCode]. It returns [ErrInvalidHash] on any structural issue so
// the verifier never leaks why a comparison failed.
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
