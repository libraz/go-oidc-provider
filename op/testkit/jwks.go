package testkit

import (
	"crypto"
	"errors"
	"fmt"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// SignedJWT serialises an arbitrary claims value as an ES256 compact JWS
// using the testkit's active signing key. It is the testkit's recommended
// path for fabricating signed assertions (private_key_jwt, request objects,
// id_token fixtures) in tests.
//
// The "kid" header is set to the testkit's active key ID so verifiers can
// route the verification through the JWKS endpoint exactly as they would
// for a production token. The "alg" header is fixed to ES256 to match the
// library's v1.0 signing policy; passing a non-ECDSA Signer fails with
// [ErrSignerMismatch].
func (p *Provider) SignedJWT(claims any) (string, error) {
	return signWith(p.SigningKey.Signer, p.SigningKey.KeyID, claims)
}

// ErrSignerMismatch is returned by [Provider.SignedJWT] when the supplied
// claims could not be signed because the active key does not satisfy the
// ES256 contract (the constructor already enforces this; the error exists
// for defensive symmetry with verifier helpers).
var ErrSignerMismatch = errors.New("testkit: active signer is not ES256")

// signWith is the package-private workhorse: it builds a [jose.Signer]
// stamped with the supplied kid, hands the claims to the [jwt] builder,
// and returns the compact serialisation.
func signWith(signer crypto.Signer, kid string, claims any) (string, error) {
	if signer == nil {
		return "", ErrSignerMismatch
	}
	sk := josev4.SigningKey{
		Algorithm: josev4.ES256,
		Key: josev4.JSONWebKey{
			Key:       signer,
			KeyID:     kid,
			Algorithm: string(josev4.ES256),
			Use:       "sig",
		},
	}
	opts := (&josev4.SignerOptions{}).WithType("JWT")
	js, err := josev4.NewSigner(sk, opts)
	if err != nil {
		return "", fmt.Errorf("testkit: build signer: %w", err)
	}
	out, err := jwt.Signed(js).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("testkit: serialise jwt: %w", err)
	}
	return out, nil
}
