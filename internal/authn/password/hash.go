package password

import (
	"errors"

	"github.com/libraz/go-oidc-provider/internal/argon2id"
)

// ErrInvalidHash is returned when [Verify] is given a stored hash it
// cannot parse, or whose Argon2id parameters violate the policy fence
// the verifier enforces (m / t / p / salt / key / encoding length out
// of bounds — see [argon2id.DefaultPolicy]). The verifier collapses
// every structural and policy issue onto this single sentinel so a
// caller cannot distinguish "you tampered with the encoding" from
// "you stored a hash with weak parameters" through the error type.
var ErrInvalidHash = errors.New("password: hash encoding is invalid")

// ErrPasswordMismatch is returned by [Verify] when the candidate
// password does not match the supplied stored hash. The caller MUST
// surface a generic invalid-credentials prompt: distinguishing
// mismatch from "username not found" leaks user enumeration.
var ErrPasswordMismatch = errors.New("password: candidate does not match")

// Verify reports whether candidate matches the supplied PHC argon2id
// encoding. Structural issues with the encoded value collapse onto
// [ErrInvalidHash]; a parsed-but-mismatched comparison returns
// [ErrPasswordMismatch] so the caller can branch on user-visible
// error messages without leaking which way the comparison failed.
//
// The comparison is constant-time: a partial match cannot leak the
// prefix length through timing.
//
// The verifier rejects stored hashes whose Argon2id parameters fall
// outside [argon2id.DefaultPolicy] — m / t below the OWASP 2024 floor,
// or m / t / p / salt / key above defensive caps. A corrupted store
// or a hostile import cannot drive one verify into an unbounded CPU
// or memory burst because the policy clamps every input axis before
// the derivation runs.
//
// Unlike the recovery-code verifier, password input is NOT
// canonicalised: case, whitespace, and unicode-equivalence variants
// all hash distinctly. Embedders enforcing case-insensitive password
// matches must pre-process before storing the hash.
func Verify(encoded []byte, candidate string) error {
	switch err := argon2id.Verify([]byte(candidate), string(encoded), argon2id.DefaultPolicy()); {
	case err == nil:
		return nil
	case errors.Is(err, argon2id.ErrMismatch):
		return ErrPasswordMismatch
	case errors.Is(err, argon2id.ErrEncoding),
		errors.Is(err, argon2id.ErrPolicy):
		return ErrInvalidHash
	default:
		return ErrInvalidHash
	}
}
