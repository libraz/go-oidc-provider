package testkit

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"reflect"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// SignedJWT serialises an arbitrary claims value as an ES256 compact JWS
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
// for a production token. The "alg" header is fixed to ES256 to match the
// library's v1.0 signing policy; an active [Provider.SigningKey] whose
// Signer is nil, non-ECDSA, or on a curve other than P-256 fails with
// [ErrSignerMismatch].
func (p *Provider) SignedJWT(claims any) (string, error) {
	return signWith(p.SigningKey.Signer, p.SigningKey.KeyID, claims)
}

// ErrSignerMismatch is returned by [Provider.SignedJWT] when the supplied
// claims could not be signed because the active key does not satisfy the
// ES256 contract. The constructor only enforces this for the key it
// generates; [Provider.SigningKey] is an exported mutable field, so a test
// that swaps in its own key reaches this error rather than an opaque
// go-jose failure.
var ErrSignerMismatch = errors.New("testkit: active signer is not ES256")

// signWith is the package-private workhorse: it builds a [jose.Signer]
// stamped with the supplied kid, hands the claims to the [jwt] builder,
// and returns the compact serialisation.
func signWith(signer crypto.Signer, kid string, claims any) (string, error) {
	if err := requireES256Signer(signer); err != nil {
		return "", err
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

// requireES256Signer reports [ErrSignerMismatch] unless signer can produce
// an ES256 signature, i.e. it is non-nil and holds an ECDSA P-256 key. The
// shape check mirrors the keyset validation op.New performs at construction
// so the testkit rejects the same keys the OP would, and it runs before
// go-jose so an RSA or Ed25519 key surfaces the documented sentinel instead
// of a wrapped ErrUnsupportedKeyType.
func requireES256Signer(signer crypto.Signer) error {
	if isNilSigner(signer) {
		return ErrSignerMismatch
	}
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return ErrSignerMismatch
	}
	return nil
}

// isNilSigner reports whether signer is nil or a typed nil pointer. A
// typed nil would panic inside Public(), so the guard has to look past the
// interface header.
func isNilSigner(signer crypto.Signer) bool {
	if signer == nil {
		return true
	}
	rv := reflect.ValueOf(signer)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Chan, reflect.Func:
		return rv.IsNil()
	default:
		return false
	}
}
