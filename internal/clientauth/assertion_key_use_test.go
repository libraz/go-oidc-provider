package clientauth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestPrivateKeyJWTVerifier_RejectsAssertionSignedWithEncryptionKey pins
// RFC 7517 §4.2 on the client-assertion surface: a JWK the client
// published with use=enc is its encryption key, never a verification key.
// Client registration already refuses to count such a key as a signing
// key, so a client that registered both a sig key and an enc key must not
// be able to authenticate with the latter — while the former keeps
// working, which is what separates a purpose gate from an outage.
func TestPrivateKeyJWTVerifier_RejectsAssertionSignedWithEncryptionKey(t *testing.T) {
	t.Parallel()

	const (
		clientID = "client-dual-use"
		sigKID   = "dual-sig-1"
		encKID   = "dual-enc-1"
		tokenAud = "https://op.test/oidc/token" //nolint:gosec // not a credential.
	)

	sigKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(sig): %v", err)
	}
	encKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(enc): %v", err)
	}

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	st := inmem.New(inmem.WithClock(fixedClock{now: now}))
	jwks, err := json.Marshal(josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{
		{Key: &sigKey.PublicKey, KeyID: sigKID, Algorithm: string(josev4.ES256), Use: "sig"},
		{Key: &encKey.PublicKey, KeyID: encKID, Algorithm: string(josev4.ES256), Use: "enc"},
	}})
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}
	if err := st.RegisterClient(context.Background(), &store.Client{
		ID:                      clientID,
		TokenEndpointAuthMethod: string(clientauth.MethodPrivateKeyJWT),
		JWKs:                    jwks,
	}); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}

	resolver, err := clientauth.NewStoreJWKSResolver(st.Clients())
	if err != nil {
		t.Fatalf("NewStoreJWKSResolver: %v", err)
	}
	newVerifier := func() *clientauth.PrivateKeyJWTVerifier {
		return &clientauth.PrivateKeyJWTVerifier{
			Resolver: resolver,
			JTIStore: st.ConsumedJTIs(),
			Audience: tokenAud,
			Clock:    fixedClock{now: now}.Now,
		}
	}
	claimsFor := func(jti string) map[string]any {
		return map[string]any{
			"iss": clientID,
			"sub": clientID,
			"aud": tokenAud,
			"jti": jti,
			"iat": now.Unix(),
			"exp": now.Add(time.Minute).Unix(),
		}
	}

	t.Run("the registered signing key authenticates the client", func(t *testing.T) {
		t.Parallel()
		assertion := signAssertion(t, sigKey, sigKID, claimsFor("j-use-control"))
		if err := newVerifier().Verify(context.Background(), clientID, assertion); err != nil {
			t.Fatalf("assertion signed with the sig key rejected: %v", err)
		}
	})

	t.Run("the registered encryption key does not", func(t *testing.T) {
		t.Parallel()
		assertion := signAssertion(t, encKey, encKID, claimsFor("j-use-enc"))
		err := newVerifier().Verify(context.Background(), clientID, assertion)
		if !errors.Is(err, clientauth.ErrCredentialsInvalid) {
			t.Fatalf("assertion signed with the use=enc key: err=%v, want ErrCredentialsInvalid", err)
		}
	})
}
