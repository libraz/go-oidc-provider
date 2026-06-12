package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"fmt"
)

// ErrUnsupportedKeyShape is returned by [KeyShape] / [AssertAlgKeyShape]
// when the supplied [crypto.PublicKey] is nil, of an unsupported Go type,
// or of a supported type with an unsupported curve / form (P-224 ECDSA,
// Ed448, sub-2048-bit RSA, etc.). Callers branch on this sentinel via
// [errors.Is]; layering a feature-specific cause on top is fine, but the
// sentinel must remain the structural identity of the failure so audit
// pipelines can collapse all four call sites onto a single counter.
var ErrUnsupportedKeyShape = errors.New("jose: unsupported key shape")

// MinRSAKeyBits is the floor [KeyShape] enforces for RSA public keys.
// RFC 7518 §3.3 mandates 2048 bits for RSA-family JWS algorithms; FAPI
// 1.0 Advanced §8.6 reiterates the floor. Callers that need a stricter
// minimum (e.g. FAPI 2.0 Message Signing 3072) layer their own check on
// top of [KeyShape] — relaxing it below 2048 is forbidden.
const MinRSAKeyBits = 2048

// JWS algorithm identifiers ([RFC 7518 §3.1], [RFC 8037 §3.1]). Stored as
// untyped strings so callers can paste them straight into JOSE headers
// or compare against the [Algorithm] enum via string conversion without
// importing additional packages.
const (
	jwsAlgRS256 = "RS256"
	jwsAlgPS256 = "PS256"
	jwsAlgES256 = "ES256"
	jwsAlgES384 = "ES384"
	jwsAlgES512 = "ES512"
	jwsAlgEdDSA = "EdDSA"
)

// JWK key-type and curve identifiers ([RFC 7518 §6.1], [RFC 8037 §2]).
const (
	jwkKtyRSA = "RSA"
	jwkKtyEC  = "EC"
	jwkKtyOKP = "OKP"

	jwkCrvP256    = "P-256"
	jwkCrvP384    = "P-384"
	jwkCrvP521    = "P-521"
	jwkCrvEd25519 = "Ed25519"
)

// KeyShape inspects pub and returns the canonical (alg, kty, crv) triple
// the OP supports for that key. ok=false when pub is nil, an unsupported
// Go type, or a supported type with an unsupported curve / size.
//
// The mapping pins one signature algorithm per key shape, which is the
// JOSE-standard pairing: an RSA key is reported as RS256 (callers that
// need PS256 substitute the alg label themselves; the key shape is the
// same), an ECDSA key reports the algorithm whose hash matches the curve
// per [RFC 7518 §3.4], and an Ed25519 key reports EdDSA per
// [RFC 8037 §3.1].
//
// kty / crv are returned alongside alg so callers can inject them into
// JWK / JWS headers without re-inspecting the key. The kty values are
// "RSA" / "EC" / "OKP" and the crv values are "P-256" / "P-384" /
// "P-521" / "Ed25519" — the empty string for kty="RSA" because RFC 7518
// does not define a curve member for the RSA family.
//
// The function intentionally reports RS256 (not PS256) for *rsa.PublicKey
// because the public key shape itself does not encode the padding
// scheme; callers that mean PS256 keep RS256 here and override at the
// signer-construction site.
//
// References:
//   - RFC 7518 §3.1 ("alg" parameter values for JWS)
//   - RFC 7518 §6.1 ("kty" parameter values for JWK)
//   - RFC 8037 §3.1 (EdDSA algorithm value)
func KeyShape(pub crypto.PublicKey) (alg, kty, crv string, ok bool) {
	if pub == nil {
		return "", "", "", false
	}
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return rsaShape(k)
	case *ecdsa.PublicKey:
		return ecdsaShape(k)
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return "", "", "", false
		}
		return jwsAlgEdDSA, jwkKtyOKP, jwkCrvEd25519, true
	default:
		return "", "", "", false
	}
}

// rsaShape returns the [KeyShape] triple for an RSA public key, or
// ok=false when the key is nil or under [MinRSAKeyBits].
func rsaShape(k *rsa.PublicKey) (alg, kty, crv string, ok bool) {
	if k == nil || k.N == nil {
		return "", "", "", false
	}
	if k.N.BitLen() < MinRSAKeyBits {
		return "", "", "", false
	}
	return jwsAlgRS256, jwkKtyRSA, "", true
}

// ecdsaShape returns the [KeyShape] triple for an ECDSA public key on
// the supported curves (P-256 / P-384 / P-521 per RFC 7518 §3.4), or
// ok=false otherwise (P-224 and any caller-provided curve).
func ecdsaShape(k *ecdsa.PublicKey) (alg, kty, crv string, ok bool) {
	if k == nil || k.Curve == nil {
		return "", "", "", false
	}
	switch k.Curve {
	case elliptic.P256():
		return jwsAlgES256, jwkKtyEC, jwkCrvP256, true
	case elliptic.P384():
		return jwsAlgES384, jwkKtyEC, jwkCrvP384, true
	case elliptic.P521():
		return jwsAlgES512, jwkKtyEC, jwkCrvP521, true
	default:
		return "", "", "", false
	}
}

// AssertAlgKeyShape returns nil iff [KeyShape] yields alg for pub. The
// helper is the defence-in-depth gate that pairs a JWS "alg" header with
// the public key shape it claims to identify, closing the
// algorithm-confusion attack surface enumerated in [RFC 8725 §2.1].
//
// PS256 is treated as alg-compatible with the RS256 key shape: both
// algorithms operate on the same *rsa.PublicKey, the difference is
// padding (PKCS#1 v1.5 vs PSS). Callers that want to forbid one or the
// other layer that policy on top of this check.
//
// On mismatch the returned error wraps [ErrUnsupportedKeyShape] so
// callers can branch via [errors.Is]; the wrapped message includes the
// rejected alg and the actual key type for log-side diagnosis but never
// echoes attacker-supplied bytes.
func AssertAlgKeyShape(alg string, pub crypto.PublicKey) error {
	got, _, _, ok := KeyShape(pub)
	if !ok {
		return fmt.Errorf("%w: key type %T is not in the OP allow-list", ErrUnsupportedKeyShape, pub)
	}
	switch alg {
	case jwsAlgRS256, jwsAlgPS256:
		if got != jwsAlgRS256 {
			return fmt.Errorf("%w: alg %q requires *rsa.PublicKey, got %s", ErrUnsupportedKeyShape, alg, describe(pub))
		}
		return nil
	case jwsAlgES256, jwsAlgES384, jwsAlgES512, jwsAlgEdDSA:
		if got != alg {
			return fmt.Errorf("%w: alg %q does not match key shape %s", ErrUnsupportedKeyShape, alg, describe(pub))
		}
		return nil
	case "":
		return fmt.Errorf("%w: empty alg", ErrUnsupportedKeyShape)
	default:
		return fmt.Errorf("%w: alg %q has no shape policy", ErrUnsupportedKeyShape, alg)
	}
}

// AssertJWEAlgKeyShape returns nil iff pub is an allowed recipient public
// key shape for the JWE key-management alg. The check applies the same
// RSA floor and EC curve allow-list as [KeyShape] before the encrypter is
// constructed, so outbound JWE cannot be minted to sub-floor RP keys.
func AssertJWEAlgKeyShape(alg JWEAlg, pub crypto.PublicKey) error {
	if _, _, _, ok := KeyShape(pub); !ok {
		return fmt.Errorf("%w: key type %T is not in the OP allow-list", ErrUnsupportedKeyShape, pub)
	}
	switch alg {
	case JWEAlgRSAOAEP256:
		if _, ok := pub.(*rsa.PublicKey); !ok {
			return fmt.Errorf("%w: alg %q requires *rsa.PublicKey, got %s", ErrUnsupportedKeyShape, alg, describe(pub))
		}
		return nil
	case JWEAlgECDHES, JWEAlgECDHESA128KW, JWEAlgECDHESA256KW:
		if _, ok := pub.(*ecdsa.PublicKey); !ok {
			return fmt.Errorf("%w: alg %q requires *ecdsa.PublicKey, got %s", ErrUnsupportedKeyShape, alg, describe(pub))
		}
		return nil
	case "":
		return fmt.Errorf("%w: empty alg", ErrUnsupportedKeyShape)
	default:
		return fmt.Errorf("%w: alg %q has no shape policy", ErrUnsupportedKeyShape, alg)
	}
}

// describe returns a short, log-safe label for pub. Used only inside
// error wrappings so operators can see "*ecdsa.PublicKey/P-384" instead
// of a raw Go type when an alg/key mismatch is logged.
func describe(pub crypto.PublicKey) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k == nil || k.N == nil {
			return "*rsa.PublicKey/nil"
		}
		return fmt.Sprintf("*rsa.PublicKey/%d-bit", k.N.BitLen())
	case *ecdsa.PublicKey:
		if k == nil || k.Curve == nil {
			return "*ecdsa.PublicKey/nil"
		}
		return "*ecdsa.PublicKey/" + k.Curve.Params().Name
	case ed25519.PublicKey:
		return fmt.Sprintf("ed25519.PublicKey/%d-byte", len(k))
	default:
		return fmt.Sprintf("%T", pub)
	}
}
