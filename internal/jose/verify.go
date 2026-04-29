package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/keys"
)

// ErrUnknownKeyID is returned by [Verify] when the JWS protected header
// names a "kid" that is not present in the supplied [keys.Set]. The
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
// header is incompatible with the public key shape the resolved [keys.Entry]
// holds. Examples: ES256 paired with a non-P-256 curve, RS256 with an
// RSA key shorter than 2048 bits.
//
// This guard is a defence-in-depth duplicate of go-jose's internal
// validation. We re-check it here so that future callers cannot
// accidentally feed the JWS into a non-go-jose verifier and skip the
// algorithm/key shape pairing requirement.
var ErrKeyAlgMismatch = errors.New("jose: alg/key shape mismatch")

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
//   - That "kid" resolves through [keys.Set.Find] to a registered
//     entry. An unknown "kid" is [ErrUnknownKeyID]; no trial-decode
//     fallback over the full set is performed.
//   - The declared algorithm matches the public-key shape on the
//     resolved entry (see [assertAlgKeyShape]).
//
// On success the returned []byte is the verified payload bytes; the
// caller is responsible for parsing claims and applying any further
// audience / expiry checks.
//
// Future contract: the function currently only enforces shape pairing
// for ECDSA P-256 keys because [keys.NewSet] only accepts that shape.
// When other key types are added to keys.NewSet (RSA / Ed25519), the
// pairings RS256 / PS256 ⇒ *rsa.PublicKey with N.BitLen() ≥ 2048 and
// EdDSA ⇒ ed25519.PublicKey MUST be added to [assertAlgKeyShape] in
// the same change, before the new key shape is wired through the
// public API.
func Verify(jws *josev4.JSONWebSignature, set *keys.Set) ([]byte, error) {
	if jws == nil {
		return nil, fmt.Errorf("%w: nil JWS", ErrMalformed)
	}
	if set == nil {
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
	entry, found := set.Find(kid)
	if !found {
		return nil, fmt.Errorf("%w: %q", ErrUnknownKeyID, kid)
	}

	pub := entry.Signer.Public()
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
// Today the only key shape [keys.NewSet] accepts is *ecdsa.PublicKey on
// the P-256 curve, so the function only meaningfully checks ES256.
// When [keys.NewSet] is extended:
//
//   - RS256 / PS256 MUST match a *rsa.PublicKey with at least a
//     2048-bit modulus (RFC 8725 §3.3).
//   - EdDSA MUST match an ed25519.PublicKey of the standard length.
//
// Add those branches before exposing the new key types via the public
// op.WithKeyset.
func assertAlgKeyShape(alg Algorithm, pub any) error {
	switch alg {
	case AlgES256:
		ec, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: ES256 requires *ecdsa.PublicKey", ErrKeyAlgMismatch)
		}
		if ec.Curve != elliptic.P256() {
			return fmt.Errorf("%w: ES256 requires P-256 curve", ErrKeyAlgMismatch)
		}
		return nil
	case AlgRS256, AlgPS256, AlgEdDSA:
		// Reachable only once keys.NewSet learns about new shapes.
		// Until then a non-ES256 alg paired with the keystore-allowed
		// shape (P-256) is a bona fide mismatch.
		return fmt.Errorf("%w: alg %q not paired with any registered key shape", ErrKeyAlgMismatch, alg)
	case AlgUnspecified:
		return fmt.Errorf("%w: algorithm unspecified", ErrAlgorithmNotAllowed)
	default:
		return fmt.Errorf("%w: alg %q has no shape policy", ErrKeyAlgMismatch, alg)
	}
}
