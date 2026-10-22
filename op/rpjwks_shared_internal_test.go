package op

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/clientencjwks"
	"github.com/libraz/go-oidc-provider/internal/jar"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// sharedJWKSFixture is one RP publishing a signing and an encryption key at
// one jwks_uri, with the request count the server observed.
type sharedJWKSFixture struct {
	cfg     *config
	client  *store.Client
	sigKey  *ecdsa.PrivateKey
	hits    *atomic.Int32
	jwksURI string
}

func newSharedJWKSFixture(t *testing.T) sharedJWKSFixture {
	t.Helper()
	sigKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	encKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	body, err := json.Marshal(josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{
		{Key: &sigKey.PublicKey, KeyID: "rp-sig", Use: "sig", Algorithm: "ES256"},
		{Key: &encKey.PublicKey, KeyID: "rp-enc", Use: "enc", Algorithm: "RSA-OAEP-256"},
	}})
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	hits := &atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	st := inmem.New(inmem.WithClock(builderTestClock{now: now}))
	client := &store.Client{ //nolint:gosec // G101 false positive: "private_key_jwt" is the OIDC auth-method name, not a credential.
		ID:                      "rp",
		JWKsURI:                 srv.URL,
		TokenEndpointAuthMethod: "private_key_jwt",
	}
	if err := st.RegisterClient(context.Background(), client); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	cfg := &config{
		issuer:                  "https://op.example.com",
		store:                   st,
		clock:                   builderTestClock{now: now},
		features:                []feature.Flag{feature.JAR},
		allowPrivateNetworkJWKS: true,
	}
	cfg.applyDefaults()
	return sharedJWKSFixture{cfg: cfg, client: client, sigKey: sigKey, hits: hits, jwksURI: srv.URL}
}

// TestRelyingPartyJWKS_OneFetchAcrossSurfaces pins that request-object
// verification, private_key_jwt and response encryption read one cache: a
// jwks_uri all three consult is fetched once per TTL, not once per surface.
func TestRelyingPartyJWKS_OneFetchAcrossSurfaces(t *testing.T) {
	t.Parallel()

	fx := newSharedJWKSFixture(t)
	ctx := context.Background()

	if _, err := buildClientEncryptionResolver(fx.cfg).ResolveRecipient(ctx, fx.client, "RSA-OAEP-256", "A256GCM"); err != nil {
		t.Fatalf("ResolveRecipient: %v", err)
	}
	assertions, err := buildAssertionVerifiers(fx.cfg)
	if err != nil {
		t.Fatalf("buildAssertionVerifiers: %v", err)
	}
	if _, err := assertions.Token.Resolver.JWKS(ctx, fx.client.ID); err != nil {
		t.Fatalf("assertion JWKS: %v", err)
	}
	jv, err := buildJARVerifiers(fx.cfg, nil)
	if err != nil {
		t.Fatalf("buildJARVerifiers: %v", err)
	}
	signer, err := josev4.NewSigner(josev4.SigningKey{Algorithm: josev4.ES256, Key: fx.sigKey},
		(&josev4.SignerOptions{}).WithHeader("kid", "rp-sig"))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	jws, err := signer.Sign([]byte(`{"iss":"rp","aud":"https://op.example.com","client_id":"rp"}`))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	raw, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize: %v", err)
	}
	// The claims are incomplete; only the key resolution before them matters.
	_, _ = jv.Authorize.Verify(ctx, raw, fx.client.ID, fx.client)

	if got := fx.hits.Load(); got != 1 {
		t.Fatalf("jwks_uri hits = %d, want 1 across the three surfaces", got)
	}
}

// TestRelyingPartyJWKS_RefusesBothSourcesEverywhere pins one jwks-vs-jwks_uri
// rule: a client carrying both is refused by request-object verification,
// private_key_jwt and response encryption alike, instead of verifying inbound
// from the inline set while encryption fails.
func TestRelyingPartyJWKS_RefusesBothSourcesEverywhere(t *testing.T) {
	t.Parallel()

	fx := newSharedJWKSFixture(t)
	ctx := context.Background()
	inline, err := json.Marshal(josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{
		{Key: &fx.sigKey.PublicKey, KeyID: "rp-sig", Use: "sig", Algorithm: "ES256"},
	}})
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	both := *fx.client
	both.ID = "rp-both"
	both.JWKs = inline
	if err := fx.cfg.store.(*inmem.Store).RegisterClient(ctx, &both); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}

	if _, err := buildClientEncryptionResolver(fx.cfg).ResolveRecipient(ctx, &both, "RSA-OAEP-256", "A256GCM"); !errors.Is(err, clientencjwks.ErrJWKSConfigured) {
		t.Errorf("encryption: err = %v, want ErrJWKSConfigured", err)
	}
	assertions, err := buildAssertionVerifiers(fx.cfg)
	if err != nil {
		t.Fatalf("buildAssertionVerifiers: %v", err)
	}
	if _, err := assertions.Token.Resolver.JWKS(ctx, both.ID); err == nil {
		t.Error("private_key_jwt resolved keys for a client with both jwks and jwks_uri")
	}
	jv, err := buildJARVerifiers(fx.cfg, nil)
	if err != nil {
		t.Fatalf("buildJARVerifiers: %v", err)
	}
	signer, err := josev4.NewSigner(josev4.SigningKey{Algorithm: josev4.ES256, Key: fx.sigKey},
		(&josev4.SignerOptions{}).WithHeader("kid", "rp-sig"))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	jws, err := signer.Sign([]byte(`{"iss":"rp-both"}`))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	raw, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize: %v", err)
	}
	if _, err := jv.Authorize.Verify(ctx, raw, both.ID, &both); !errors.Is(err, jar.ErrJWKSConfigured) {
		t.Errorf("JAR: err = %v, want ErrJWKSConfigured", err)
	}
	if got := fx.hits.Load(); got != 0 {
		t.Errorf("jwks_uri hits = %d, want 0: a refused pair must not reach the network", got)
	}
}
