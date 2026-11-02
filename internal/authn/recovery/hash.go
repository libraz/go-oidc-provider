package recovery

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/libraz/go-oidc-provider/internal/argon2id"
)

// argon2idDefaults is the immutable parameter set [hashCodes] mints
// under and [verifyPolicy] accepts: the library-wide
// [argon2id.DefaultParams], intentionally NOT configurable. Every
// recovery batch hashes under the same parameters, which keeps the
// verifier path branch-free and avoids a footgun where embedders pick
// weaker parameters than they realise.
//
//nolint:gochecknoglobals // immutable config vector; no per-instance tuning.
var argon2idDefaults = argon2id.DefaultParams()

// ErrInvalidHash is returned when a stored slot carries an encoding the
// verifier cannot parse, or whose Argon2id parameters violate the
// [verifyPolicy] fence. The verifier collapses every structural and
// policy issue onto this single sentinel so a caller cannot distinguish
// "you tampered with the encoding" from "you tampered with the
// parameters" through the error type.
var ErrInvalidHash = errors.New("recovery: hash encoding is invalid")

// verifyPolicy bounds the Argon2id parameters the verifier is willing
// to derive under. It starts from the shared default and clamps the m /
// t / p ceilings down to the values this package mints, so the cost of
// one wrong guess is fixed by the generator rather than by whatever a
// corrupted store happens to claim: without the clamp a stored slot
// could declare m=1GiB, t=32 and turn a single guess into a
// multi-second, multi-gigabyte burst.
//
// Changing [argon2idDefaults] therefore also changes what the verifier
// accepts. A future parameter bump has to widen these ceilings to span
// both the old and the new value for as long as pre-bump batches are
// still expected to verify.
func verifyPolicy() argon2id.Policy {
	p := argon2id.DefaultPolicy()
	p.MaxMemory = argon2idDefaults.Memory
	p.MaxIterations = argon2idDefaults.Iterations
	p.MaxParallelism = argon2idDefaults.Parallelism
	return p
}

// hashCodes derives the stored encoding of every plaintext code in one
// batch. All slots share a single salt, and that is the property the
// verifier is built on: a guess can then be turned into ONE argon2id
// derivation and compared against every slot, instead of one 64 MiB
// derivation per slot. A per-slot salt would make the cost of a wrong
// guess scale with the batch size, which is a memory-amplification
// vector an attacker triggers with one short string.
//
// Sharing the salt inside a batch costs nothing that matters. A salt
// stops cross-record precomputation, and the salt is still unique per
// batch (and therefore per user); the only concession is that an
// attacker who steals the batch can attack its ten codes in one
// derivation pass rather than ten. Each code carries 50 bits of
// crypto/rand entropy, so that reduces an infeasible offline search by
// a factor of ten — and the online path already offers the same
// ten-target amortisation, which is what the ~2^46 figure in
// [codeChars] accounts for.
//
// The plaintext is canonicalised through [normalise] first so that
// "abcde-12345" and "ABCDE12345" hash to the same value.
func hashCodes(plain []string) ([]string, error) {
	salt, err := newSalt()
	if err != nil {
		return nil, err
	}
	p := argon2idDefaults
	out := make([]string, 0, len(plain))
	for _, code := range plain {
		out = append(out, argon2id.Hash([]byte(normalise(code)), salt, p))
	}
	return out, nil
}

// newSalt reads a fresh salt from crypto/rand.
func newSalt() ([]byte, error) {
	salt := make([]byte, argon2idDefaults.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("recovery: read salt: %w", err)
	}
	return salt, nil
}

// deriveKey runs the argon2id derivation for a canonicalised code. It is
// the only place in the package that spends the work factor, so the
// verifier's cost bound is exactly "how many times is this called".
func deriveKey(plain string, salt []byte, p argon2id.Params) []byte {
	return argon2id.Key([]byte(normalise(plain)), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
}

// parseStoredHash parses one stored slot encoding under [verifyPolicy].
// It runs no derivation: parsing is the cheap half, and the verifier
// parses every candidate slot before deciding whether it is willing to
// spend the single derivation the batch is worth.
//
// Structural issues and parameter-bound violations collapse onto
// [ErrInvalidHash] so a caller cannot tell which axis failed.
func parseStoredHash(encoded string) (argon2id.PHCParams, error) {
	parsed, err := argon2id.ParsePHC(encoded, verifyPolicy())
	if err != nil {
		return argon2id.PHCParams{}, ErrInvalidHash
	}
	return parsed, nil
}

// paramsOf projects a parsed slot onto the package's parameter struct so
// [deriveKey] can be driven from stored values. The narrowing
// conversions are safe because [verifyPolicy] has already clamped the
// salt and key lengths well inside the uint32 domain.
func paramsOf(parsed argon2id.PHCParams) argon2id.Params {
	return argon2id.Params{
		Memory:      parsed.Memory,
		Iterations:  parsed.Iterations,
		Parallelism: parsed.Parallelism,
		SaltLength:  uint32(len(parsed.Salt)), //nolint:gosec // verifyPolicy caps the salt at 128 bytes.
		KeyLength:   uint32(len(parsed.Hash)), //nolint:gosec // verifyPolicy caps the key at 128 bytes.
	}
}

// sameDerivation reports whether two parsed slots would derive under
// identical inputs — same work factor, same salt, same key length — and
// can therefore be answered by one shared derivation. The comparison
// reads only stored material, never the presented code, so it leaks
// nothing about a guess.
func sameDerivation(a, b argon2id.PHCParams) bool {
	return a.Memory == b.Memory &&
		a.Iterations == b.Iterations &&
		a.Parallelism == b.Parallelism &&
		len(a.Hash) == len(b.Hash) &&
		bytes.Equal(a.Salt, b.Salt)
}
