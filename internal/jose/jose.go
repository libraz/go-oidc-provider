package jose

import (
	"errors"
	"fmt"

	josev4 "github.com/go-jose/go-jose/v4"
)

// ErrAlgorithmNotAllowed is returned when a JWS or JWT header advertises
// an algorithm outside this package's allow-list. The error wraps the
// rejected algorithm string for logging but never echoes attacker-supplied
// payload bytes.
var ErrAlgorithmNotAllowed = errors.New("jose: algorithm not allowed")

// ErrMalformed indicates that the input was not a syntactically valid
// compact-serialised JWS. The wrapped cause comes from the underlying
// implementation and is safe to log but not safe to return to clients.
var ErrMalformed = errors.New("jose: malformed token")

// ErrCriticalHeader is returned when a JWS protected header advertises
// a "crit" extension this package does not understand. RFC 7515 §4.1.11
// and RFC 8725 §3.5 require verifiers to reject any "crit" value that
// is not on a documented allow-list, otherwise an attacker can smuggle
// header semantics (e.g. "b64":false to suppress payload base64
// encoding) past a verifier that simply ignores unknown headers.
//
// The package's allow-list is intentionally empty: no JWS produced by
// the OP needs a "crit" header, so any presence of "crit" in input is
// treated as a hard rejection rather than an opportunity to extend the
// allow-list at parse time.
var ErrCriticalHeader = errors.New("jose: unsupported critical header")

// ParseSigned validates the compact-serialised JWS in raw, ensuring that
// its "alg" header is one of the algorithms enabled by this package and
// that it carries no unsupported "crit" extension. It returns the parsed
// object on success or an error wrapping [ErrAlgorithmNotAllowed],
// [ErrCriticalHeader], or [ErrMalformed] on failure.
//
// Only compact serialisation (header.payload.signature) is accepted.
// JSON-serialised and multi-signature JWS forms are rejected as
// malformed. RFC 8725 §3.6 recommends the compact form for token
// contexts, and accepting the multi-signature form would let an
// attacker attach an additional signature over the same payload using
// a key under their control, hoping the verifier picks the wrong one.
//
// "crit" handling: RFC 7515 §4.1.11 requires the verifier to reject any
// JWS whose protected header contains a "crit" value the verifier does
// not understand. This package understands no extensions, so the
// presence of any "crit" entry — including go-jose's internal "b64"
// recognition (which would otherwise let `{"b64":false}` smuggle an
// unencoded payload) — is treated as an immediate parse failure.
//
// ParseSigned does not verify the signature; that is the caller's
// responsibility once it has selected an appropriate verifier and key.
// Pre-parse validation here is what closes the "alg=none" and "alg
// downgrade" attack surfaces structurally — by the time a verifier is
// invoked, the algorithm is already known to be in the allow-list.
func ParseSigned(raw string) (*josev4.JSONWebSignature, Algorithm, error) {
	allowed := allowedV4Algorithms()

	jws, err := josev4.ParseSignedCompact(raw, allowed)
	if err != nil {
		return nil, AlgUnspecified, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if len(jws.Signatures) != 1 {
		return nil, AlgUnspecified, ErrMalformed
	}

	algStr := jws.Signatures[0].Header.Algorithm
	alg, ok := ParseAlgorithm(algStr)
	if !ok {
		return nil, AlgUnspecified, fmt.Errorf("%w: %q", ErrAlgorithmNotAllowed, algStr)
	}

	if err := assertNoCriticalHeader(jws.Signatures[0]); err != nil {
		return nil, AlgUnspecified, err
	}
	return jws, alg, nil
}

// assertNoCriticalHeader rejects any JWS whose protected header carries
// a "crit" entry. The allow-list is intentionally empty: the OP never
// emits a "crit" header on its own JWS output and accepts none on
// input.
//
// The check inspects the protected header only. RFC 7515 §4.1.11
// requires "crit" to live in the protected (integrity-protected)
// header; an unprotected "crit" is meaningless and we ignore it on
// purpose so that attackers cannot mount a denial-of-service by
// appending a stray unprotected member.
//
// The function tolerates the two shapes go-jose may use to surface the
// raw value — `[]any` after JSON unmarshalling and `[]string` if the
// caller built the JWS programmatically — and treats every other shape
// (including a non-empty string or a number) as a malformed header so
// that we never confuse "ignored" with "absent".
func assertNoCriticalHeader(sig josev4.Signature) error {
	v, ok := sig.Protected.ExtraHeaders[josev4.HeaderKey("crit")]
	if !ok {
		return nil
	}
	switch crit := v.(type) {
	case []any:
		if len(crit) == 0 {
			// An empty "crit" array is invalid per RFC 7515 §4.1.11
			// but harmless; reject it for symmetry with non-empty.
			return fmt.Errorf("%w: empty crit header", ErrCriticalHeader)
		}
		return fmt.Errorf("%w: %v", ErrCriticalHeader, crit)
	case []string:
		if len(crit) == 0 {
			return fmt.Errorf("%w: empty crit header", ErrCriticalHeader)
		}
		return fmt.Errorf("%w: %v", ErrCriticalHeader, crit)
	default:
		return fmt.Errorf("%w: unrecognised crit shape", ErrCriticalHeader)
	}
}

// allowedV4Algorithms returns the slice of go-jose v4 algorithm constants
// matching this package's [Algorithm] allow-list. Keeping the mapping in
// one place lets us audit it alongside [Algorithm.IsAllowed].
func allowedV4Algorithms() []josev4.SignatureAlgorithm {
	return []josev4.SignatureAlgorithm{
		josev4.RS256,
		josev4.PS256,
		josev4.ES256,
		josev4.EdDSA,
	}
}
