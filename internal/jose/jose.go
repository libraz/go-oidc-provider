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

// ParseSigned validates the compact-serialised JWS in raw, ensuring that
// its "alg" header is one of the algorithms enabled by this package. It
// returns the parsed object on success or an error wrapping
// [ErrAlgorithmNotAllowed] / [ErrMalformed] on failure.
//
// Only compact serialisation (header.payload.signature) is accepted.
// JSON-serialised and multi-signature JWS forms are rejected as
// malformed. RFC 8725 §3.6 recommends the compact form for token
// contexts, and accepting the multi-signature form would let an
// attacker attach an additional signature over the same payload using
// a key under their control, hoping the verifier picks the wrong one.
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
	return jws, alg, nil
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
