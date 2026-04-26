package authn_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/url"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func newConfidentialClient(tb testing.TB, secret string) *store.Client {
	tb.Helper()
	v := &authn.Argon2id{Params: authn.Argon2idParams{
		Memory:      16 * 1024,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  8,
		KeyLength:   16,
	}}
	hash, err := v.Hash(secret)
	if err != nil {
		tb.Fatalf("Hash: %v", err)
	}
	return &store.Client{
		ID:                      "client-1",
		SecretHash:              hash,
		TokenEndpointAuthMethod: string(authn.MethodSecretBasic),
	}
}

func smallArgon2id() *authn.Argon2id {
	return &authn.Argon2id{Params: authn.Argon2idParams{
		Memory:      16 * 1024,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  8,
		KeyLength:   16,
	}}
}

func TestVerifyClient_BasicAuth_Success(t *testing.T) {
	t.Parallel()

	client := newConfidentialClient(t, "topsecret")
	form := url.Values{}
	req := newPostRequest(t, form, "client-1", "topsecret")
	creds, err := authn.Parse(req)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	method, err := authn.VerifyClient(context.Background(), creds, client, authn.VerifyOpts{
		SecretVerifier: smallArgon2id(),
	})
	if err != nil {
		t.Fatalf("VerifyClient: %v", err)
	}
	if method != authn.MethodSecretBasic {
		t.Errorf("method=%v", method)
	}
}

func TestVerifyClient_WrongSecretYieldsCredentialsInvalid(t *testing.T) {
	t.Parallel()

	client := newConfidentialClient(t, "topsecret")
	req := newPostRequest(t, url.Values{}, "client-1", "wrong-secret")
	creds, err := authn.Parse(req)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	_, err = authn.VerifyClient(context.Background(), creds, client, authn.VerifyOpts{
		SecretVerifier: smallArgon2id(),
	})
	if !errors.Is(err, authn.ErrCredentialsInvalid) {
		t.Errorf("err=%v want ErrCredentialsInvalid", err)
	}
}

func TestVerifyClient_PublicClientCannotUseBasic(t *testing.T) {
	t.Parallel()

	public := &store.Client{
		ID:                      "spa",
		PublicClient:            true,
		TokenEndpointAuthMethod: string(authn.MethodNone),
	}
	req := newPostRequest(t, url.Values{}, "spa", "anything")
	creds, err := authn.Parse(req)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	_, err = authn.VerifyClient(context.Background(), creds, public, authn.VerifyOpts{
		SecretVerifier: smallArgon2id(),
	})
	if !errors.Is(err, authn.ErrCredentialsInvalid) {
		t.Errorf("err=%v want ErrCredentialsInvalid", err)
	}
}

func TestVerifyClient_PublicClientNonePath(t *testing.T) {
	t.Parallel()

	public := &store.Client{
		ID:                      "spa",
		PublicClient:            true,
		TokenEndpointAuthMethod: string(authn.MethodNone),
	}
	form := url.Values{}
	form.Set("client_id", "spa")
	req := newPostRequest(t, form, "", "")
	creds, err := authn.Parse(req)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	method, err := authn.VerifyClient(context.Background(), creds, public, authn.VerifyOpts{})
	if err != nil {
		t.Fatalf("VerifyClient: %v", err)
	}
	if method != authn.MethodNone {
		t.Errorf("method=%v", method)
	}
}

func TestVerifyClient_NilClientReturnsCredentialsInvalid(t *testing.T) {
	t.Parallel()

	req := newPostRequest(t, url.Values{}, "client-1", "x")
	creds, _ := authn.Parse(req)
	_, err := authn.VerifyClient(context.Background(), creds, nil, authn.VerifyOpts{
		SecretVerifier: smallArgon2id(),
	})
	if !errors.Is(err, authn.ErrCredentialsInvalid) {
		t.Errorf("err=%v want ErrCredentialsInvalid", err)
	}
}

func TestVerifyClient_ClientIDMismatch(t *testing.T) {
	t.Parallel()

	client := newConfidentialClient(t, "x")
	creds := &authn.Credentials{
		ClientID:    "other-id",
		Method:      authn.MethodSecretBasic,
		SecretBasic: "x",
	}
	_, err := authn.VerifyClient(context.Background(), creds, client, authn.VerifyOpts{
		SecretVerifier: smallArgon2id(),
	})
	if !errors.Is(err, authn.ErrClientMismatch) {
		t.Errorf("err=%v want ErrClientMismatch", err)
	}
}

// --- private_key_jwt --------------------------------------------------------

type staticResolver struct{ keys *josev4.JSONWebKeySet }

func (r staticResolver) JWKS(_ context.Context, _ string) (*josev4.JSONWebKeySet, error) {
	return r.keys, nil
}

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

func TestPrivateKeyJWTVerifier_HappyPath(t *testing.T) {
	t.Parallel()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubKeys := &josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{{
		Key:       &priv.PublicKey,
		KeyID:     "rp-key-1",
		Algorithm: string(josev4.ES256),
		Use:       "sig",
	}}}
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	const tokenAud = "https://op.test/oidc/token" //nolint:gosec // not a credential, the token endpoint URL.
	assertion := signAssertion(t, priv, "rp-key-1", map[string]any{
		"iss": "client-1",
		"sub": "client-1",
		"aud": tokenAud,
		"jti": "j-1",
		"iat": now.Add(-30 * time.Second).Unix(),
		"exp": now.Add(2 * time.Minute).Unix(),
	})

	jtiStore := inmem.New().ConsumedJTIs()
	v := &authn.PrivateKeyJWTVerifier{
		Resolver: staticResolver{keys: pubKeys},
		JTIStore: jtiStore,
		Audience: tokenAud,
		Clock:    fixedClock{now: now}.Now,
	}
	if err := v.Verify(context.Background(), "client-1", assertion); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	// Replay must be rejected.
	if err := v.Verify(context.Background(), "client-1", assertion); !errors.Is(err, authn.ErrAssertionReplayed) {
		t.Fatalf("replay err=%v want ErrAssertionReplayed", err)
	}
}

func TestPrivateKeyJWTVerifier_RejectsBadAudience(t *testing.T) {
	t.Parallel()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubKeys := &josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{{
		Key: &priv.PublicKey, KeyID: "rp-key-1", Algorithm: string(josev4.ES256), Use: "sig",
	}}}
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	assertion := signAssertion(t, priv, "rp-key-1", map[string]any{
		"iss": "client-1", "sub": "client-1",
		"aud": "https://op.test/wrong",
		"jti": "j-2",
		"iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(),
	})
	v := &authn.PrivateKeyJWTVerifier{
		Resolver: staticResolver{keys: pubKeys},
		JTIStore: inmem.New().ConsumedJTIs(),
		Audience: "https://op.test/oidc/token",
		Clock:    fixedClock{now: now}.Now,
	}
	if err := v.Verify(context.Background(), "client-1", assertion); !errors.Is(err, authn.ErrAssertionMalformed) {
		t.Errorf("err=%v want ErrAssertionMalformed", err)
	}
}

func TestPrivateKeyJWTVerifier_RejectsExpired(t *testing.T) {
	t.Parallel()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubKeys := &josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{{
		Key: &priv.PublicKey, KeyID: "rp-key-1", Algorithm: string(josev4.ES256), Use: "sig",
	}}}
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	assertion := signAssertion(t, priv, "rp-key-1", map[string]any{
		"iss": "client-1", "sub": "client-1",
		"aud": "https://op.test/oidc/token",
		"jti": "j-3",
		"iat": now.Add(-10 * time.Minute).Unix(),
		"exp": now.Add(-5 * time.Minute).Unix(),
	})
	v := &authn.PrivateKeyJWTVerifier{
		Resolver: staticResolver{keys: pubKeys},
		JTIStore: inmem.New().ConsumedJTIs(),
		Audience: "https://op.test/oidc/token",
		Clock:    fixedClock{now: now}.Now,
	}
	if err := v.Verify(context.Background(), "client-1", assertion); !errors.Is(err, authn.ErrAssertionMalformed) {
		t.Errorf("err=%v want ErrAssertionMalformed", err)
	}
}

func TestPrivateKeyJWTVerifier_UnknownClient_RejectsCredentials(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	assertion := signAssertion(t, priv, "rp-key-1", map[string]any{
		"iss": "client-1", "sub": "client-1",
		"aud": "https://op.test/oidc/token",
		"jti": "j-4",
		"iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(),
	})
	v := &authn.PrivateKeyJWTVerifier{
		Resolver: staticResolver{keys: &josev4.JSONWebKeySet{}}, // empty
		JTIStore: inmem.New().ConsumedJTIs(),
		Audience: "https://op.test/oidc/token",
		Clock:    fixedClock{now: now}.Now,
	}
	if err := v.Verify(context.Background(), "client-1", assertion); !errors.Is(err, authn.ErrCredentialsInvalid) {
		t.Errorf("err=%v want ErrCredentialsInvalid", err)
	}
}

// signAssertion builds a compact-serialised ES256 JWT signed with priv
// and the kid header set to keyID. Used by every private_key_jwt test in
// this file so each case can mutate just the claim payload.
func signAssertion(tb testing.TB, priv *ecdsa.PrivateKey, keyID string, claims map[string]any) string {
	tb.Helper()
	sk := josev4.SigningKey{
		Algorithm: josev4.ES256,
		Key: josev4.JSONWebKey{
			Key:       priv,
			KeyID:     keyID,
			Algorithm: string(josev4.ES256),
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
