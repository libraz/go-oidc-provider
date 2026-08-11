// Package argon2id is the in-tree shared argon2id PHC verifier the
// library's three credential surfaces — client_secret
// (internal/clientauth), password (internal/authn/password), and
// recovery code (internal/authn/recovery) — funnel through.
//
// The package exists for two reasons:
//
//  1. Consolidate the three near-identical PHC parsers that drifted
//     before and accumulated a different bug catalogue per copy. A
//     single parser means a single place to fix a future security
//     issue (rejected duplicate parameter, rejected unknown key,
//     rejected oversized field, …) instead of three.
//  2. Refuse stored hashes whose Argon2id parameters fall outside a
//     bounded [Policy]. The legacy verifiers capped the derived-key
//     length but accepted arbitrary memory / iteration / parallelism
//     / salt sizes, which let a corrupted store or a hostile import
//     turn one verify into an unbounded CPU / memory burst.
//
// The package returns three sentinel errors, deliberately disjoint so
// callers can collapse the structural / policy axes onto their own
// "invalid hash" sentinel while routing [ErrMismatch] onto the
// user-visible "credentials invalid" sentinel. The wire shape is the
// caller's choice — this package never produces text that escapes the
// caller's error mapping.
package argon2id

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Sentinel errors returned by [Verify] and [ParsePHC]. Each caller
// MUST collapse [ErrEncoding] / [ErrPolicy] onto its own opaque
// "invalid hash" sentinel and [ErrMismatch] onto its "credentials
// invalid" sentinel; the wire response then leaks neither the
// structural cause nor the policy axis.
var (
	// ErrEncoding signals a structural issue with the PHC string —
	// wrong number of segments, unknown algorithm, version mismatch,
	// non-integer parameter, duplicate parameter key, unknown
	// parameter key, malformed base64.
	ErrEncoding = errors.New("argon2id: encoding invalid")

	// ErrPolicy signals a structurally valid PHC whose Argon2id
	// parameters violate the supplied [Policy] (m / t / p / salt
	// / key / encoding length out of bounds). The error is distinct
	// from [ErrEncoding] for audit purposes; on the wire callers
	// MUST collapse it onto the same sentinel.
	ErrPolicy = errors.New("argon2id: parameter violates policy")

	// ErrMismatch signals the candidate plaintext does not match the
	// PHC. Callers map this onto their user-visible "credentials
	// invalid" sentinel.
	ErrMismatch = errors.New("argon2id: mismatch")
)

// Policy bounds the Argon2id parameters [Verify] / [ParsePHC] accept
// on a stored PHC. Callers initialise via [DefaultPolicy] and
// override fields where the default is too strict (e.g. interop with
// an external hash database that uses non-standard work factors).
//
// A zero-valued field disables that particular bound. This is for
// tests and migration tools; production callers SHOULD start from
// [DefaultPolicy] and tune individual fields.
type Policy struct {
	// MinMemory / MaxMemory bound the m= field (Argon2id memory cost
	// in KiB). DefaultPolicy uses [OWASP 2024]'s 19 MiB minimum and a
	// 1 GiB upper cap so a corrupted store cannot drive a 16 GiB
	// allocation per verify.
	//
	// [OWASP 2024]: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id
	MinMemory uint32
	MaxMemory uint32

	// MinIterations / MaxIterations bound the t= field (Argon2id
	// time cost). DefaultPolicy uses OWASP 2024's t=2 floor and a
	// t=32 ceiling — plenty of headroom for high-security
	// deployments without admitting a runaway value that turns one
	// verify into a multi-minute CPU burn.
	MinIterations uint32
	MaxIterations uint32

	// MinParallelism / MaxParallelism bound the p= field. The
	// DefaultPolicy bounds [1, 16] cover every realistic deployment;
	// larger values do not improve security and cost goroutines.
	MinParallelism uint8
	MaxParallelism uint8

	// MinSaltLength / MaxSaltLength cap the salt byte length after
	// base64 decode. DefaultPolicy uses [8, 128]: the floor matches
	// Argon2's own 8-byte minimum, the ceiling rejects pathological
	// PHCs that pretend to carry a kilobyte salt.
	MinSaltLength int
	MaxSaltLength int

	// MinKeyLength / MaxKeyLength cap the derived-key (hash) byte
	// length after base64 decode. DefaultPolicy uses [16, 128].
	MinKeyLength int
	MaxKeyLength int

	// MaxEncodingLength caps the PHC string itself before parsing.
	// A real argon2id PHC is well under 200 bytes; the cap rejects a
	// pathological store value claiming gigantic salt+hash before
	// hitting the parser. DefaultPolicy: 1024.
	MaxEncodingLength int
}

// DefaultPolicy returns the OWASP 2024-aligned policy the library
// applies to its built-in client_secret / password / recovery
// verifiers. Callers SHOULD start from this value and tune
// individual fields rather than zero-initialising the struct.
func DefaultPolicy() Policy {
	return Policy{
		MinMemory:         19 * 1024,
		MaxMemory:         1024 * 1024,
		MinIterations:     2,
		MaxIterations:     32,
		MinParallelism:    1,
		MaxParallelism:    16,
		MinSaltLength:     8,
		MaxSaltLength:     128,
		MinKeyLength:      16,
		MaxKeyLength:      128,
		MaxEncodingLength: 1024,
	}
}

// PHCParams is the parsed view of a stored argon2id PHC string.
// Callers typically only see this when re-emitting a PHC (operator
// migration tools); [Verify] consumes it internally.
type PHCParams struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	Salt        []byte
	Hash        []byte
}

// ParsePHC parses an argon2id modular-crypt encoding and validates
// the result against policy. The two error axes never overlap: the
// function returns [ErrEncoding] for structural issues and
// [ErrPolicy] for parameter-bound violations, in that order.
//
// The parser refuses duplicate, unknown, and missing parameter keys
// in the m=...,t=...,p=... segment so a hostile import cannot
// smuggle in last-value-wins ambiguity that makes audit logs
// disagree with the actual derivation.
func ParsePHC(encoded string, policy Policy) (PHCParams, error) {
	if policy.MaxEncodingLength > 0 && len(encoded) > policy.MaxEncodingLength {
		return PHCParams{}, fmt.Errorf("%w: encoding length %d exceeds policy max %d",
			ErrPolicy, len(encoded), policy.MaxEncodingLength)
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return PHCParams{}, fmt.Errorf("%w: bad envelope", ErrEncoding)
	}
	if !strings.HasPrefix(parts[2], "v=") {
		return PHCParams{}, fmt.Errorf("%w: missing version", ErrEncoding)
	}
	version, err := strconv.Atoi(parts[2][2:])
	if err != nil || version != argon2.Version {
		return PHCParams{}, fmt.Errorf("%w: unsupported version %q", ErrEncoding, parts[2][2:])
	}
	mem, iter, par, err := parseParams(parts[3])
	if err != nil {
		return PHCParams{}, err
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return PHCParams{}, fmt.Errorf("%w: salt base64: %w", ErrEncoding, err)
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return PHCParams{}, fmt.Errorf("%w: hash base64: %w", ErrEncoding, err)
	}
	parsed := PHCParams{
		Memory:      mem,
		Iterations:  iter,
		Parallelism: par,
		Salt:        salt,
		Hash:        hash,
	}
	if err := validatePolicy(parsed, policy); err != nil {
		return PHCParams{}, err
	}
	return parsed, nil
}

// parseParams extracts the m / t / p triple from the parameter
// segment ("m=...,t=...,p=...") of an argon2id PHC. Duplicate keys
// (m=64,m=128), unknown keys (m=64,t=3,p=1,x=2), and missing keys
// all surface as [ErrEncoding]. Callers cannot tell which sub-field
// tripped the parse; the catalogue is intentionally opaque so an
// attacker probing with synthetic PHCs cannot fingerprint the
// parser.
func parseParams(seg string) (mem, iter uint32, par uint8, err error) {
	var seenM, seenT, seenP bool
	for _, kv := range strings.Split(seg, ",") {
		k, n, parseErr := splitParam(kv)
		if parseErr != nil {
			return 0, 0, 0, parseErr
		}
		switch k {
		case "m":
			mem, err = assignParamUint32(seenM, n, "m")
			seenM = true
		case "t":
			iter, err = assignParamUint32(seenT, n, "t")
			seenT = true
		case "p":
			par, err = assignParamUint8(seenP, n)
			seenP = true
		default:
			return 0, 0, 0, fmt.Errorf("%w: unknown param %q", ErrEncoding, k)
		}
		if err != nil {
			return 0, 0, 0, err
		}
	}
	if !seenM || !seenT || !seenP {
		return 0, 0, 0, fmt.Errorf("%w: missing one of m,t,p", ErrEncoding)
	}
	return mem, iter, par, nil
}

// splitParam parses one "k=v" token from the parameter segment. The
// helper exists so parseParams's per-key dispatch table can stay
// flat — the structural / numeric error paths are dealt with here.
func splitParam(kv string) (string, uint64, error) {
	k, v, ok := strings.Cut(kv, "=")
	if !ok {
		return "", 0, fmt.Errorf("%w: param %q has no '='", ErrEncoding, kv)
	}
	n, parseErr := strconv.ParseUint(v, 10, 32)
	if parseErr != nil {
		return "", 0, fmt.Errorf("%w: param %q: %w", ErrEncoding, kv, parseErr)
	}
	return k, n, nil
}

// assignParamUint32 stores n into the matching uint32 field after
// confirming the slot has not already been filled. The duplicate
// check is the security-critical half of the parser: pre-audit
// last-value-wins let an attacker smuggle in a different work
// factor than the audit log recorded.
//
// The uint64 → uint32 narrow is safe because [splitParam] already
// invoked strconv.ParseUint with bitSize=32, which returns
// strconv.ErrRange for any value outside the uint32 domain.
func assignParamUint32(seen bool, n uint64, key string) (uint32, error) {
	if seen {
		return 0, fmt.Errorf("%w: duplicate %s=", ErrEncoding, key)
	}
	return uint32(n), nil //nolint:gosec // splitParam capped n at uint32 via ParseUint(bitSize=32).
}

// assignParamUint8 is the p= counterpart to [assignParamUint32]. The
// extra range check rejects p > 255 because the wire field is a
// uint8; without the gate, a hostile PHC could declare p=256 and
// see it silently truncate to 0 inside [argon2.IDKey].
func assignParamUint8(seen bool, n uint64) (uint8, error) {
	if seen {
		return 0, fmt.Errorf("%w: duplicate p=", ErrEncoding)
	}
	if n > 255 {
		return 0, fmt.Errorf("%w: p=%d exceeds uint8", ErrEncoding, n)
	}
	return uint8(n), nil
}

// validatePolicy compares a parsed [PHCParams] to policy bounds. A
// zero-valued bound disables the check on that axis (see Policy
// godoc). Every violation surfaces as [ErrPolicy] so callers branch
// on a single sentinel.
func validatePolicy(p PHCParams, policy Policy) error {
	if err := validateUint32Bound("m", uint64(p.Memory), uint64(policy.MinMemory), uint64(policy.MaxMemory)); err != nil {
		return err
	}
	if err := validateUint32Bound("t", uint64(p.Iterations), uint64(policy.MinIterations), uint64(policy.MaxIterations)); err != nil {
		return err
	}
	if err := validateUint32Bound("p", uint64(p.Parallelism), uint64(policy.MinParallelism), uint64(policy.MaxParallelism)); err != nil {
		return err
	}
	if err := validateLengthBound("salt", len(p.Salt), policy.MinSaltLength, policy.MaxSaltLength); err != nil {
		return err
	}
	return validateLengthBound("key", len(p.Hash), policy.MinKeyLength, policy.MaxKeyLength)
}

// validateUint32Bound checks a single numeric axis (m / t / p)
// against its [Min, Max] window. A zero Min or Max disables the
// matching half of the gate.
func validateUint32Bound(label string, value, minVal, maxVal uint64) error {
	if minVal > 0 && value < minVal {
		return fmt.Errorf("%w: %s=%d below Min%s=%d", ErrPolicy, label, value, label, minVal)
	}
	if maxVal > 0 && value > maxVal {
		return fmt.Errorf("%w: %s=%d exceeds Max%s=%d", ErrPolicy, label, value, label, maxVal)
	}
	return nil
}

// validateLengthBound is the salt / key counterpart to
// [validateUint32Bound]. A separate helper keeps the int-vs-uint64
// type domains clean rather than over-converting at call sites.
func validateLengthBound(label string, length, minVal, maxVal int) error {
	if minVal > 0 && length < minVal {
		return fmt.Errorf("%w: %s length %d below Min%sLength=%d", ErrPolicy, label, length, label, minVal)
	}
	if maxVal > 0 && length > maxVal {
		return fmt.Errorf("%w: %s length %d exceeds Max%sLength=%d", ErrPolicy, label, length, label, maxVal)
	}
	return nil
}

// Verify derives the candidate plaintext against the parsed PHC
// parameters and reports whether it matches encoded under policy.
// The function returns nil on a successful match; otherwise one of
// [ErrEncoding] (structural), [ErrPolicy] (parameter bound), or
// [ErrMismatch] (parsed-but-mismatched). The latter is the only
// error a caller surfaces to the user; the first two are integrity
// faults the caller MUST collapse onto a generic "invalid hash"
// sentinel before crossing the wire.
//
// Argon2id derivation runs only after [ParsePHC] has accepted the
// stored value. A hostile or corrupted store cannot drive the
// derivation cost beyond the policy bounds because the m / t / p /
// salt / key fields are clamped before [Key] is invoked. Policy bounds
// what one derivation may cost; [Key]'s gate bounds how many may cost
// it at once.
func Verify(plain []byte, encoded string, policy Policy) error {
	parsed, err := ParsePHC(encoded, policy)
	if err != nil {
		return err
	}
	keyLen, err := keyLengthAsUint32(len(parsed.Hash))
	if err != nil {
		return err
	}
	candidate := Key(plain, parsed.Salt, parsed.Iterations, parsed.Memory, parsed.Parallelism, keyLen)
	if subtle.ConstantTimeCompare(candidate, parsed.Hash) != 1 {
		return ErrMismatch
	}
	return nil
}

// keyLengthAsUint32 narrows an int slice length onto the uint32 field
// [argon2.IDKey] consumes. The conversion is a no-op for any
// realistic key (≤ 128 bytes under [DefaultPolicy.MaxKeyLength]) but
// the explicit gate keeps gosec G115 honest and surfaces a structural
// error if a future caller hands the function a hash that survived
// policy validation yet still cannot fit a uint32.
func keyLengthAsUint32(n int) (uint32, error) {
	if n < 0 || uint64(n) > uint64(^uint32(0)) {
		return 0, fmt.Errorf("%w: key length %d does not fit uint32", ErrEncoding, n)
	}
	return uint32(n), nil
}
