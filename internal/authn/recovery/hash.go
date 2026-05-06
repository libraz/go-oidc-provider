package recovery

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"

	"github.com/libraz/go-oidc-provider/internal/argon2id"
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

// ErrInvalidHash is returned when [verifyCode] is given a stored hash
// it cannot parse, or whose Argon2id parameters violate the
// [argon2id.DefaultPolicy] fence the verifier enforces. The verifier
// collapses every structural and policy issue onto this single sentinel
// so a caller cannot distinguish "you tampered with the encoding" from
// "you tampered with the parameters" through the error type.
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
// don't matter. Structural issues — and parameter values that violate
// [argon2id.DefaultPolicy] — collapse onto [ErrInvalidHash]; a
// parsed-but-mismatched comparison returns [ErrCodeInvalid] so the
// caller can branch on user-visible error messages without leaking
// which way the comparison failed.
//
// The comparison is constant-time: a partial match cannot leak the
// prefix length through timing.
//
// A corrupted store cannot drive one verify into an unbounded CPU /
// memory burst because [argon2id.DefaultPolicy] clamps the m / t /
// p / salt / key parameters before [argon2.IDKey] runs.
func verifyCode(plain, encoded string) error {
	canonical := normalise(plain)
	switch err := argon2id.Verify([]byte(canonical), encoded, argon2id.DefaultPolicy()); {
	case err == nil:
		return nil
	case errors.Is(err, argon2id.ErrMismatch):
		return ErrCodeInvalid
	case errors.Is(err, argon2id.ErrEncoding),
		errors.Is(err, argon2id.ErrPolicy):
		return ErrInvalidHash
	default:
		return ErrInvalidHash
	}
}
