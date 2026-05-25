package clientauth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// signRSAAssertion mirrors signAssertion but signs with RS256 so the
// test can exercise the RSA key-shape floor. randReader is the package
// crypto/rand source reused from verify_test.go via the shared import.
func signRSAAssertion(tb testing.TB, priv *rsa.PrivateKey, keyID string, claims map[string]any) string {
	tb.Helper()
	sk := josev4.SigningKey{
		Algorithm: josev4.RS256,
		Key: josev4.JSONWebKey{
			Key:       priv,
			KeyID:     keyID,
			Algorithm: string(josev4.RS256),
			Use:       "sig",
		},
	}
	signer, err := josev4.NewSigner(sk, (&josev4.SignerOptions{}).WithType("JWT"))
	if err != nil {
		tb.Fatalf("NewSigner: %v", err)
	}
	out, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		tb.Fatalf("Serialize: %v", err)
	}
	return out
}

func rsaPrivateKeyJWTVerifier(tb testing.TB, priv *rsa.PrivateKey, now time.Time) (*clientauth.PrivateKeyJWTVerifier, string) {
	tb.Helper()
	const tokenAud = "https://op.test/oidc/token" //nolint:gosec // token endpoint URL, not a credential.
	pubKeys := &josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{{
		Key: &priv.PublicKey, KeyID: "rp-key-1", Algorithm: string(josev4.RS256), Use: "sig",
	}}}
	v := &clientauth.PrivateKeyJWTVerifier{
		Resolver: staticResolver{keys: pubKeys},
		JTIStore: inmem.New(inmem.WithClock(fixedClock{now: now})).ConsumedJTIs(),
		Audience: tokenAud,
		Clock:    fixedClock{now: now}.Now,
	}
	return v, tokenAud
}

// TestPrivateKeyJWTVerifier_RejectsSubFloorRSAKey verifies that a client
// registering a sub-2048-bit RSA verification key cannot have its
// private_key_jwt assertion accepted. The OP applies the RFC 7518 §3.3 /
// RFC 8725 §3.2 key-shape floor to its own keys; a client key must not
// receive a laxer check.
func TestPrivateKeyJWTVerifier_RejectsSubFloorRSAKey(t *testing.T) {
	t.Parallel()

	priv, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // deliberately sub-floor to assert rejection.
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	v, aud := rsaPrivateKeyJWTVerifier(t, priv, now)
	assertion := signRSAAssertion(t, priv, "rp-key-1", map[string]any{
		"iss": "client-1", "sub": "client-1", "aud": aud, "jti": "j-rsa-weak",
		"iat": now.Add(-30 * time.Second).Unix(), "exp": now.Add(2 * time.Minute).Unix(),
	})
	if err := v.Verify(context.Background(), "client-1", assertion); !errors.Is(err, clientauth.ErrCredentialsInvalid) {
		t.Fatalf("err=%v want ErrCredentialsInvalid", err)
	}
}

// TestPrivateKeyJWTVerifier_AcceptsFloorRSAKey is the positive control:
// a compliant 2048-bit RSA key still authenticates, proving the
// key-shape gate does not change behaviour for conforming clients.
func TestPrivateKeyJWTVerifier_AcceptsFloorRSAKey(t *testing.T) {
	t.Parallel()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	v, aud := rsaPrivateKeyJWTVerifier(t, priv, now)
	assertion := signRSAAssertion(t, priv, "rp-key-1", map[string]any{
		"iss": "client-1", "sub": "client-1", "aud": aud, "jti": "j-rsa-ok",
		"iat": now.Add(-30 * time.Second).Unix(), "exp": now.Add(2 * time.Minute).Unix(),
	})
	if err := v.Verify(context.Background(), "client-1", assertion); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}
