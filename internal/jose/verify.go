package jose

import (
	"crypto"
	"errors"
	"fmt"

	josev4 "github.com/go-jose/go-jose/v4"
)

// ErrUnknownKeyID is returned by [Verify] when the JWS protected header
// names a "kid" that is not present in the supplied [KeyResolver]. The
// caller MUST treat this as a hard rejection: the package never falls
// back to a trial-decode loop over every key in the set, because doing
// so would let an attacker bypass key rotation auditing by stripping
// the "kid" header.
var ErrUnknownKeyID = errors.New("jose: unknown kid")

// ErrMissingKeyID is returned when the JWS protected header omits the
// "kid" parameter entirely. RFC 7515 §4.1.4 makes "kid" optional at
// the spec level, but every JWS the OP cares about (id_token, JARM,
// logout_token, JAR request objects, DPoP-style proofs the OP itself
// signs) is produced with a "kid", so a missing value can only come
// from an attacker probing the verifier.
var ErrMissingKeyID = errors.New("jose: missing kid")

// ErrKeyAlgMismatch is returned when the algorithm declared in the JWS
// header is incompatible with the public key shape the resolved key
// holds. Examples: ES256 paired with a non-P-256 curve, RS256 with an
// RSA key shorter than 2048 bits.
//
// This guard is a defence-in-depth duplicate of go-jose's internal
// validation. We re-check it here so that future callers cannot
// accidentally feed the JWS into a non-go-jose verifier and skip the
// algorithm/key shape pairing requirement.
var ErrKeyAlgMismatch = errors.New("jose: alg/key shape mismatch")

// KeyResolver is the small abstraction [Verify] uses to look up the
// public key advertised by a JWS "kid" header. The interface keeps the
// jose package free of an inbound dependency on [internal/keys] so the
// canonical [KeyShape] matrix can live in this file without an import
// cycle. Concrete callers wrap their key store (e.g. [keys.Set.Find])
// in a one-line adapter.
//
// Resolve returns the public key on the matching entry and ok=true; a
// missing or retired kid returns ok=false. The implementation MUST
// treat a kid that is present but past its rotation deadline as
// not-found so [Verify] surfaces [ErrUnknownKeyID] uniformly.
type KeyResolver interface {
	Resolve(keyID string) (pub crypto.PublicKey, ok bool)
}

// KeyResolverFunc adapts a free function to [KeyResolver]. It exists
// for callers that already have a `Find(kid string) (Entry, bool)`-
// style method on their key store.
type KeyResolverFunc func(keyID string) (crypto.PublicKey, bool)

// Resolve calls f(keyID).
func (f KeyResolverFunc) Resolve(keyID string) (crypto.PublicKey, bool) {
	if f == nil {
		return nil, false
	}
	return f(keyID)
}

// Verify validates the signature on jws against the public key whose
// "kid" matches the JWS protected header, returning the verified
// payload. The function enforces:
//
//   - The "alg" header is on this package's allow-list. (Already
//     guaranteed by [ParseSigned], re-checked here so a caller that
//     constructed a [*josev4.JSONWebSignature] another way is still
//     subject to the policy.)
//   - The protected header carries a "kid". A missing "kid" is
//     [ErrMissingKeyID].
//   - That "kid" resolves through [KeyResolver.Resolve] to a registered
//     entry. An unknown "kid" is [ErrUnknownKeyID]; no trial-decode
//     fallback over the full set is performed.
//   - The declared algorithm matches the public-key shape on the
//     resolved entry (see [assertAlgKeyShape]).
//
// On success the returned []byte is the verified payload bytes; the
// caller is responsible for parsing claims and applying any further
// audience / expiry checks.
func Verify(jws *josev4.JSONWebSignature, resolver KeyResolver) ([]byte, error) {
	if jws == nil {
		return nil, fmt.Errorf("%w: nil JWS", ErrMalformed)
	}
	if resolver == nil {
		return nil, fmt.Errorf("%w: nil keyset", ErrMalformed)
	}
	if len(jws.Signatures) != 1 {
		return nil, ErrMalformed
	}

	sig := jws.Signatures[0]
	alg, ok := ParseAlgorithm(sig.Header.Algorithm)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrAlgorithmNotAllowed, sig.Header.Algorithm)
	}

	kid := sig.Header.KeyID
	if kid == "" {
		return nil, ErrMissingKeyID
	}
	pub, found := resolver.Resolve(kid)
	if !found {
		return nil, fmt.Errorf("%w: %q", ErrUnknownKeyID, kid)
	}

	if err := assertAlgKeyShape(alg, pub); err != nil {
		return nil, err
	}

	payload, err := jws.Verify(pub)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return payload, nil
}

// assertAlgKeyShape enforces that a JWS algorithm and the corresponding
// public key shape are compatible, defending against algorithm-confusion
// attacks where a verifier is tricked into treating an HMAC-style key
// as a public key (or vice versa) — see RFC 8725 §2.1.
//
// The function is a thin wrapper over [AssertAlgKeyShape] (which is the
// canonical alg/key matrix shared with [internal/jarm], [internal/dpop],
// and [internal/keys]); it exists so the [Verify] surface can keep
// returning [ErrKeyAlgMismatch] as the structural failure label even
// though the underlying mismatch sentinel is [ErrUnsupportedKeyShape].
// Any non-nil result from [AssertAlgKeyShape] is wrapped with
// [ErrKeyAlgMismatch] so callers branching via [errors.Is] continue to
// see the same identity they did before consolidation.
//
// AlgUnspecified is filtered upstream by [ParseAlgorithm], but we re-map
// it here onto [ErrAlgorithmNotAllowed] for callers that constructed
// the parsed JWS some other way.
func assertAlgKeyShape(alg Algorithm, pub any) error {
	if alg == AlgUnspecified {
		return fmt.Errorf("%w: algorithm unspecified", ErrAlgorithmNotAllowed)
	}
	if err := AssertAlgKeyShape(alg.String(), pub); err != nil {
		return fmt.Errorf("%w: %w", ErrKeyAlgMismatch, err)
	}
	return nil
}
