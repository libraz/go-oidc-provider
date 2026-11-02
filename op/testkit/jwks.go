package testkit

import (
	"crypto"
	"errors"
	"fmt"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/internal/jose"
	"github.com/libraz/go-oidc-provider/internal/nilcheck"
)

// SignedJWT serialises an arbitrary claims value as a compact JWS
// using the OP's own active signing key — the same key that signs the
// id_tokens this provider issues. It is therefore the path for fabricating
// artefacts the OP itself would have produced: id_token_hint values for
// /end_session, id_token fixtures a verifier resolves through this
// provider's JWKS endpoint.
//
// It is NOT a way to fabricate a client-side assertion. A private_key_jwt
// client_assertion or a JAR request object must be signed by the *client*
// and verified by the OP against the key the client registered, so signing
// one here produces a JWT the real verifier rejects unless the test also
// registers the OP's public key as the client's JWKS — a configuration
// that does not exist in production. For those, generate a keypair with
// crypto/ecdsa, sign with go-jose directly, and register the public JWK on
// the client fixture's [store.Client.JWKs].
//
// The "kid" header is set to the testkit's active key ID so verifiers can
// route the verification through the JWKS endpoint exactly as they would
// for a production token. The "alg" header is derived from the active key:
// ES256 for an ECDSA P-256 key, RS256 for an RSA key of at least 2048 bits.
// A [Provider.SigningKey] whose Signer is nil or any other shape fails with
// [ErrSignerMismatch].
func (p *Provider) SignedJWT(claims any) (string, error) {
	return signWith(p.SigningKey.Signer, p.SigningKey.KeyID, claims)
}

// ErrSignerMismatch is returned by [Provider.SignedJWT] when the supplied
// claims could not be signed because the active key is neither ES256 nor
// RS256 shaped. The constructor only enforces this for the key it
// generates; [Provider.SigningKey] is an exported mutable field, so a test
// that swaps in its own key reaches this error rather than an opaque
// go-jose failure.
var ErrSignerMismatch = errors.New("testkit: active signer is not a key the OP signs with (ES256 or RS256)")

// signWith is the package-private workhorse: it builds a [jose.Signer]
// stamped with the supplied kid, hands the claims to the [jwt] builder,
// and returns the compact serialisation.
func signWith(signer crypto.Signer, kid string, claims any) (string, error) {
	alg, err := signerAlg(signer)
	if err != nil {
		return "", err
	}
	sk := josev4.SigningKey{
		Algorithm: alg,
		Key: josev4.JSONWebKey{
			Key:       signer,
			KeyID:     kid,
			Algorithm: string(alg),
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

// signerAlg derives the JWS algorithm from the signer's public key and
// reports [ErrSignerMismatch] unless it is ES256 or RS256. It runs before
// go-jose so an unsupported key surfaces the documented sentinel instead
// of a wrapped ErrUnsupportedKeyType.
func signerAlg(signer crypto.Signer) (josev4.SignatureAlgorithm, error) {
	if nilcheck.IsNil(signer) {
		return "", ErrSignerMismatch
	}
	alg, _, _, ok := jose.KeyShape(signer.Public())
	if !ok {
		return "", ErrSignerMismatch
	}
	switch alg {
	case string(josev4.ES256):
		return josev4.ES256, nil
	case string(josev4.RS256):
		return josev4.RS256, nil
	}
	return "", ErrSignerMismatch
}
