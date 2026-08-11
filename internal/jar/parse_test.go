package jar_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/internal/jar"
	"github.com/libraz/go-oidc-provider/internal/jose"
)

// signedRequestObject is a tiny test helper: it generates a fresh ES256
// keypair and returns a compact JWS over claims plus the corresponding
// public JWK (so verifier tests can stand the keyset up by hand).
func signedRequestObject(t *testing.T, claims any, kid string) (string, *josev4.JSONWebKey, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signed := signClaims(t, priv, kid, claims, josev4.ES256)
	pub := &josev4.JSONWebKey{
		Key:       &priv.PublicKey,
		KeyID:     kid,
		Algorithm: string(josev4.ES256),
		Use:       "sig",
	}
	return signed, pub, priv
}

func signedRequestObjectWithType(t *testing.T, claims any, kid, typ string) (string, *josev4.JSONWebKey, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signed := signClaimsWithType(t, priv, kid, claims, josev4.ES256, typ)
	pub := &josev4.JSONWebKey{
		Key:       &priv.PublicKey,
		KeyID:     kid,
		Algorithm: string(josev4.ES256),
		Use:       "sig",
	}
	return signed, pub, priv
}

// signClaims serialises claims as a compact JWS using priv with the
// supplied alg / kid. It is the workhorse beneath
// [signedRequestObject] and is exposed to tests that need to vary the
// algorithm.
func signClaims(t *testing.T, priv any, kid string, claims any, alg josev4.SignatureAlgorithm) string {
	t.Helper()
	return signClaimsWithType(t, priv, kid, claims, alg, "oauth-authz-req+jwt")
}

func signClaimsWithType(t *testing.T, priv any, kid string, claims any, alg josev4.SignatureAlgorithm, typ string) string {
	t.Helper()
	sk := josev4.SigningKey{
		Algorithm: alg,
		Key: josev4.JSONWebKey{
			Key:       priv,
			KeyID:     kid,
			Algorithm: string(alg),
			Use:       "sig",
		},
	}
	opts := &josev4.SignerOptions{}
	// An empty typ means "emit no typ header at all" so tests can model
	// the request objects RFC 9101 permits (and the conformance suite
	// sends) without a media type.
	if typ != "" {
		opts = opts.WithType(josev4.ContentType(typ))
	}
	signer, err := josev4.NewSigner(sk, opts)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	out, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return out
}

func TestParse_RejectsEmpty(t *testing.T) {
	t.Parallel()

	_, err := jar.Parse("")
	if !errors.Is(err, jar.ErrParse) {
		t.Fatalf("err=%v want ErrParse", err)
	}
}

func TestParse_RejectsNonJWS(t *testing.T) {
	t.Parallel()

	_, err := jar.Parse("not-a-jws")
	if !errors.Is(err, jar.ErrParse) {
		t.Fatalf("err=%v want ErrParse", err)
	}
}

func TestParse_HappyPath(t *testing.T) {
	t.Parallel()

	raw, _, _ := signedRequestObject(t, map[string]any{"foo": "bar"}, "kid-1")
	obj, err := jar.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if obj.Algorithm != jose.AlgES256 {
		t.Errorf("Algorithm=%q want ES256", obj.Algorithm)
	}
	if obj.KeyID != "kid-1" {
		t.Errorf("KeyID=%q want kid-1", obj.KeyID)
	}
	if obj.Type != "oauth-authz-req+jwt" {
		t.Errorf("Type=%q want oauth-authz-req+jwt", obj.Type)
	}
	if obj.Claims["foo"] != "bar" {
		t.Errorf("Claims[foo]=%v want bar", obj.Claims["foo"])
	}
	if obj.Raw != raw {
		t.Errorf("Raw mismatch")
	}
}

func TestParse_RejectsAlgNone(t *testing.T) {
	t.Parallel()

	// "alg=none" is structurally rejected by [jose.ParseSigned]
	// before Parse even sees the bytes. We hand the parser a minimal
	// "none"-shaped JWS to confirm the path; the body is the value
	// jose.ParseSigned would emit on a "none"-shaped header.
	const noneJWS = "eyJhbGciOiJub25lIn0.e30."
	_, err := jar.Parse(noneJWS)
	if !errors.Is(err, jar.ErrParse) {
		t.Fatalf("err=%v want ErrParse", err)
	}
}

func TestParse_RejectsHMAC(t *testing.T) {
	t.Parallel()

	// HS256 is outside the project allow-list. ParseSigned will reject
	// it before Parse can inspect the payload.
	const hsJWS = "eyJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIifQ.bm90c2lnbmF0dXJl"
	_, err := jar.Parse(hsJWS)
	if !errors.Is(err, jar.ErrParse) {
		t.Fatalf("err=%v want ErrParse", err)
	}
}

func TestParse_HasSingleSignature(t *testing.T) {
	t.Parallel()

	raw, _, _ := signedRequestObject(t, map[string]any{}, "kid-x")
	obj, err := jar.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if obj.Algorithm.String() != "ES256" {
		t.Errorf("Algorithm.String()=%q", obj.Algorithm.String())
	}
}
