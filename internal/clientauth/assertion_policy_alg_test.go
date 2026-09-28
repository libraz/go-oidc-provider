package clientauth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/jose"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestPrivateKeyJWTVerifier_AllowedAlgsNarrowsTheProjectAllowList pins
// that [clientauth.PrivateKeyJWTVerifier.AllowedAlgs] refuses an
// assertion whose alg the project allow-list admits but the configured
// set does not, while the same key still authenticates under an alg
// inside the set. The RSA key signs both RS256 and PS256, so the only
// difference between the two assertions is the alg itself.
func TestPrivateKeyJWTVerifier_AllowedAlgsNarrowsTheProjectAllowList(t *testing.T) {
	t.Parallel()

	const (
		clientID = "client-alg-narrowing"
		keyID    = "rp-rsa-1"
		tokenAud = "https://op.test/oidc/token" //nolint:gosec // not a credential.
	)
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	jwks, err := json.Marshal(josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{{
		Key: &priv.PublicKey, KeyID: keyID, Use: "sig",
	}}})
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	st := inmem.New(inmem.WithClock(fixedClock{now: now}))
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
	sign := func(alg josev4.SignatureAlgorithm, jti string) string {
		signer, err := josev4.NewSigner(
			josev4.SigningKey{Algorithm: alg, Key: priv},
			(&josev4.SignerOptions{}).WithType("JWT").WithHeader("kid", keyID),
		)
		if err != nil {
			t.Fatalf("NewSigner: %v", err)
		}
		out, err := jwt.Signed(signer).Claims(map[string]any{
			"iss": clientID, "sub": clientID, "aud": tokenAud, "jti": jti,
			"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
		}).Serialize()
		if err != nil {
			t.Fatalf("Serialize: %v", err)
		}
		return out
	}
	verifier := func(allowed []jose.Algorithm) *clientauth.PrivateKeyJWTVerifier {
		return &clientauth.PrivateKeyJWTVerifier{
			Resolver:    resolver,
			JTIStore:    st.ConsumedJTIs(),
			Audience:    tokenAud,
			Clock:       fixedClock{now: now}.Now,
			AllowedAlgs: allowed,
		}
	}
	narrowed := []jose.Algorithm{jose.AlgPS256, jose.AlgES256, jose.AlgEdDSA}

	if err := verifier(narrowed).Verify(context.Background(), clientID, sign(josev4.RS256, "j-rs256-narrowed")); !errors.Is(err, clientauth.ErrCredentialsInvalid) {
		t.Errorf("RS256 assertion under a set without RS256: err=%v, want ErrCredentialsInvalid", err)
	}
	if err := verifier(narrowed).Verify(context.Background(), clientID, sign(josev4.PS256, "j-ps256-narrowed")); err != nil {
		t.Errorf("PS256 assertion under a set with PS256: %v", err)
	}
	if err := verifier(nil).Verify(context.Background(), clientID, sign(josev4.RS256, "j-rs256-default")); err != nil {
		t.Errorf("RS256 assertion with no narrowing: %v", err)
	}
}
