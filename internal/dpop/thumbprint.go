package dpop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"

	josev4 "github.com/go-jose/go-jose/v4"
)

// minRSAKeyBits is the minimum modulus size accepted on a DPoP proof's
// RSA JWK. RFC 7518 §3.3 already mandates 2048 for RSA-family JWS algs
// and FAPI 1.0 Advanced §8.6 reiterates the floor; 2048 matches both
// without forcing operators onto 3072+.
const minRSAKeyBits = 2048

// Thumbprint returns the RFC 7638 SHA-256 JWK thumbprint of jwk encoded
// as base64url without padding. The value is what the OP places in the
// access token's "cnf.jkt" claim (RFC 9449 §6) and what subsequent
// proofs are compared against.
//
// The function delegates to the go-jose implementation for correctness
// (it is the same canonical encoding the rest of the JOSE ecosystem
// uses) but layers the public-only / supported-shape gates the DPoP
// surface needs:
//
//   - Private keys are rejected. The thumbprint is derived from the
//     public coordinates only; passing a private key here would mean
//     the caller threaded its DPoP signing key through a verifier
//     entry point, which is a programmer bug.
//   - Only ECDSA P-256, Ed25519, and RSA (≥ [minRSAKeyBits] modulus)
//     are accepted, mirroring the algorithm allow-list ([proof.go]).
//     Other key types fail closed so a misconfigured client cannot
//     obtain a thumbprint that the verifier would later refuse to
//     match.
func Thumbprint(jwk *josev4.JSONWebKey) (string, error) {
	if jwk == nil {
		return "", errors.New("dpop: nil JWK")
	}
	if !jwk.IsPublic() {
		return "", errors.New("dpop: thumbprint requires a public JWK")
	}
	if err := assertSupportedKeyType(jwk); err != nil {
		return "", err
	}
	sum, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("dpop: compute thumbprint: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(sum), nil
}

// assertSupportedKeyType narrows go-jose's broader acceptance set to the
// shapes the DPoP path supports: ECDSA P-256, Ed25519, and RSA ≥
// [minRSAKeyBits]. The RSA branch tracks the PS256 entry in
// [allowedProofAlgs] — admitting an RSA key while the alg gate still
// allowed only EC/Ed would let a client bind a token to a key it could
// never prove possession of through this verifier.
func assertSupportedKeyType(jwk *josev4.JSONWebKey) error {
	switch pub := jwk.Key.(type) {
	case *ecdsa.PublicKey:
		if pub == nil || pub.Curve == nil {
			return errors.New("dpop: incomplete ECDSA public key")
		}
		if pub.Curve != elliptic.P256() {
			return fmt.Errorf("dpop: unsupported curve %s", pub.Curve.Params().Name)
		}
		return nil
	case ed25519.PublicKey:
		if len(pub) != ed25519.PublicKeySize {
			return fmt.Errorf("dpop: ed25519 public key has %d bytes", len(pub))
		}
		return nil
	case *rsa.PublicKey:
		if pub == nil || pub.N == nil {
			return errors.New("dpop: incomplete RSA public key")
		}
		if bits := pub.N.BitLen(); bits < minRSAKeyBits {
			return fmt.Errorf("dpop: RSA modulus is %d bits (minimum %d)", bits, minRSAKeyBits)
		}
		return nil
	default:
		return fmt.Errorf("dpop: unsupported JWK key type %T", jwk.Key)
	}
}
