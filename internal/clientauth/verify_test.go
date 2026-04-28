package clientauth_test

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

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func newConfidentialClient(tb testing.TB, secret string) *store.Client {
	tb.Helper()
	v := &clientauth.Argon2id{Params: clientauth.Argon2idParams{
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
		TokenEndpointAuthMethod: string(clientauth.MethodSecretBasic),
	}
}

func smallArgon2id() *clientauth.Argon2id {
	return &clientauth.Argon2id{Params: clientauth.Argon2idParams{
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
	creds, err := clientauth.Parse(req)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	method, err := clientauth.VerifyClient(context.Background(), creds, client, clientauth.VerifyOpts{
		SecretVerifier: smallArgon2id(),
	})
	if err != nil {
		t.Fatalf("VerifyClient: %v", err)
	}
	if method != clientauth.MethodSecretBasic {
		t.Errorf("method=%v", method)
	}
}

func TestVerifyClient_WrongSecretYieldsCredentialsInvalid(t *testing.T) {
	t.Parallel()

	client := newConfidentialClient(t, "topsecret")
	req := newPostRequest(t, url.Values{}, "client-1", "wrong-secret")
	creds, err := clientauth.Parse(req)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	_, err = clientauth.VerifyClient(context.Background(), creds, client, clientauth.VerifyOpts{
		SecretVerifier: smallArgon2id(),
	})
	if !errors.Is(err, clientauth.ErrCredentialsInvalid) {
		t.Errorf("err=%v want ErrCredentialsInvalid", err)
	}
}

func TestVerifyClient_PublicClientCannotUseBasic(t *testing.T) {
	t.Parallel()

	public := &store.Client{
		ID:                      "spa",
		PublicClient:            true,
		TokenEndpointAuthMethod: string(clientauth.MethodNone),
	}
	req := newPostRequest(t, url.Values{}, "spa", "anything")
	creds, err := clientauth.Parse(req)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	_, err = clientauth.VerifyClient(context.Background(), creds, public, clientauth.VerifyOpts{
		SecretVerifier: smallArgon2id(),
	})
	if !errors.Is(err, clientauth.ErrCredentialsInvalid) {
		t.Errorf("err=%v want ErrCredentialsInvalid", err)
	}
}

func TestVerifyClient_PublicClientNonePath(t *testing.T) {
	t.Parallel()

	public := &store.Client{
		ID:                      "spa",
		PublicClient:            true,
		TokenEndpointAuthMethod: string(clientauth.MethodNone),
	}
	form := url.Values{}
	form.Set("client_id", "spa")
	req := newPostRequest(t, form, "", "")
	creds, err := clientauth.Parse(req)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	method, err := clientauth.VerifyClient(context.Background(), creds, public, clientauth.VerifyOpts{})
	if err != nil {
		t.Fatalf("VerifyClient: %v", err)
	}
	if method != clientauth.MethodNone {
		t.Errorf("method=%v", method)
	}
}

func TestVerifyClient_AllowedMethodsRejectsOutOfPolicy(t *testing.T) {
	t.Parallel()

	client := newConfidentialClient(t, "topsecret")
	req := newPostRequest(t, url.Values{}, "client-1", "topsecret")
	creds, err := clientauth.Parse(req)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	_, err = clientauth.VerifyClient(context.Background(), creds, client, clientauth.VerifyOpts{
		SecretVerifier: smallArgon2id(),
		// FAPI 2.0 §3.1.3: only private_key_jwt / tls_client_auth /
		// self_signed_tls_client_auth are accepted. The presented
		// client_secret_basic credential MUST be rejected even though
		// the client is registered for it.
		AllowedMethods: []clientauth.Method{clientauth.MethodPrivateKeyJWT},
	})
	if !errors.Is(err, clientauth.ErrCredentialsInvalid) {
		t.Errorf("err=%v want ErrCredentialsInvalid", err)
	}
}

func TestVerifyClient_AllowedMethodsAcceptsListed(t *testing.T) {
	t.Parallel()

	client := newConfidentialClient(t, "topsecret")
	req := newPostRequest(t, url.Values{}, "client-1", "topsecret")
	creds, err := clientauth.Parse(req)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	method, err := clientauth.VerifyClient(context.Background(), creds, client, clientauth.VerifyOpts{
		SecretVerifier: smallArgon2id(),
		AllowedMethods: []clientauth.Method{
			clientauth.MethodSecretBasic,
			clientauth.MethodPrivateKeyJWT,
		},
	})
	if err != nil {
		t.Fatalf("VerifyClient: %v", err)
	}
	if method != clientauth.MethodSecretBasic {
		t.Errorf("method=%v", method)
	}
}

func TestVerifyClient_AllowedMethodsEmptyMeansNoOverride(t *testing.T) {
	t.Parallel()

	// Empty AllowedMethods is the default no-policy state and MUST
	// behave identically to the pre-Wave-G2 path: the registered
	// client's TokenEndpointAuthMethod is the only gate.
	client := newConfidentialClient(t, "topsecret")
	req := newPostRequest(t, url.Values{}, "client-1", "topsecret")
	creds, err := clientauth.Parse(req)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	method, err := clientauth.VerifyClient(context.Background(), creds, client, clientauth.VerifyOpts{
		SecretVerifier: smallArgon2id(),
	})
	if err != nil {
		t.Fatalf("VerifyClient: %v", err)
	}
	if method != clientauth.MethodSecretBasic {
		t.Errorf("method=%v", method)
	}
}

func TestVerifyClient_NilClientReturnsCredentialsInvalid(t *testing.T) {
	t.Parallel()

	req := newPostRequest(t, url.Values{}, "client-1", "x")
	creds, _ := clientauth.Parse(req)
	_, err := clientauth.VerifyClient(context.Background(), creds, nil, clientauth.VerifyOpts{
		SecretVerifier: smallArgon2id(),
	})
	if !errors.Is(err, clientauth.ErrCredentialsInvalid) {
		t.Errorf("err=%v want ErrCredentialsInvalid", err)
	}
}

func TestVerifyClient_ClientIDMismatch(t *testing.T) {
	t.Parallel()

	client := newConfidentialClient(t, "x")
	creds := &clientauth.Credentials{
		ClientID:    "other-id",
		Method:      clientauth.MethodSecretBasic,
		SecretBasic: "x",
	}
	_, err := clientauth.VerifyClient(context.Background(), creds, client, clientauth.VerifyOpts{
		SecretVerifier: smallArgon2id(),
	})
	if !errors.Is(err, clientauth.ErrClientMismatch) {
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

	jtiStore := inmem.New(inmem.WithClock(fixedClock{now: now})).ConsumedJTIs()
	v := &clientauth.PrivateKeyJWTVerifier{
		Resolver: staticResolver{keys: pubKeys},
		JTIStore: jtiStore,
		Audience: tokenAud,
		Clock:    fixedClock{now: now}.Now,
	}
	if err := v.Verify(context.Background(), "client-1", assertion); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	// Replay must be rejected.
	if err := v.Verify(context.Background(), "client-1", assertion); !errors.Is(err, clientauth.ErrAssertionReplayed) {
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
	v := &clientauth.PrivateKeyJWTVerifier{
		Resolver: staticResolver{keys: pubKeys},
		JTIStore: inmem.New(inmem.WithClock(fixedClock{now: now})).ConsumedJTIs(),
		Audience: "https://op.test/oidc/token",
		Clock:    fixedClock{now: now}.Now,
	}
	if err := v.Verify(context.Background(), "client-1", assertion); !errors.Is(err, clientauth.ErrAssertionMalformed) {
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
	v := &clientauth.PrivateKeyJWTVerifier{
		Resolver: staticResolver{keys: pubKeys},
		JTIStore: inmem.New(inmem.WithClock(fixedClock{now: now})).ConsumedJTIs(),
		Audience: "https://op.test/oidc/token",
		Clock:    fixedClock{now: now}.Now,
	}
	if err := v.Verify(context.Background(), "client-1", assertion); !errors.Is(err, clientauth.ErrAssertionMalformed) {
		t.Errorf("err=%v want ErrAssertionMalformed", err)
	}
}

// TestPrivateKeyJWTVerifier_AudIssuer_AcceptedViaAuxAudiences pins the
// FAPI 2.0 §5.2.2 dialect of private_key_jwt: aud == AS issuer (not
// token endpoint URL). The verifier accepts it via AuxAudiences.
//
// Tracks: OIDF/IETF coordinated disclosure CVE-2025-27370 (OIDC) and
// CVE-2025-27371 (OAuth 2.0 / RFC 7523bis) — "private_key_jwt aud
// confusion": clients reusing one keypair across multiple ASs could be
// impersonated by a malicious AS that advertised the honest AS's token
// endpoint as its own. Spec fix promotes "aud SHOULD be issuer" to MUST,
// so OPs MUST accept aud == issuer. Stored under FAPI 2.0 lineage.
func TestPrivateKeyJWTVerifier_AudIssuer_AcceptedViaAuxAudiences(t *testing.T) {
	t.Parallel()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubKeys := &josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{{
		Key: &priv.PublicKey, KeyID: "rp-key-1", Algorithm: string(josev4.ES256), Use: "sig",
	}}}
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	const issuer = "https://op.test/oidc"
	const tokenAud = "https://op.test/oidc/token" //nolint:gosec // not a credential.
	assertion := signAssertion(t, priv, "rp-key-1", map[string]any{
		"iss": "client-1",
		"sub": "client-1",
		"aud": issuer, // FAPI 2.0 form.
		"jti": "j-aud-iss",
		"iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(),
	})
	v := &clientauth.PrivateKeyJWTVerifier{
		Resolver:     staticResolver{keys: pubKeys},
		JTIStore:     inmem.New(inmem.WithClock(fixedClock{now: now})).ConsumedJTIs(),
		Audience:     tokenAud,
		AuxAudiences: []string{issuer},
		Clock:        fixedClock{now: now}.Now,
	}
	if err := v.Verify(context.Background(), "client-1", assertion); err != nil {
		t.Fatalf("Verify aud=issuer: %v", err)
	}
}

// TestPrivateKeyJWTVerifier_AudOtherAS_Rejected confirms a client_assertion
// whose aud names a *different* authorization server is rejected, even
// when the keypair is otherwise valid. This is the negative half of the
// CVE-2025-27370 / CVE-2025-27371 fix: a malicious AS_att cannot relay
// an assertion forged "aud=AS_hon/token" to AS_hon, because AS_hon's
// expected aud set must not contain AS_att's identifier.
func TestPrivateKeyJWTVerifier_AudOtherAS_Rejected(t *testing.T) {
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
		"iss": "client-1",
		"sub": "client-1",
		"aud": "https://attacker.example/as", // unrelated AS.
		"jti": "j-aud-foreign",
		"iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(),
	})
	v := &clientauth.PrivateKeyJWTVerifier{
		Resolver:     staticResolver{keys: pubKeys},
		JTIStore:     inmem.New(inmem.WithClock(fixedClock{now: now})).ConsumedJTIs(),
		Audience:     "https://op.test/oidc/token",
		AuxAudiences: []string{"https://op.test/oidc"},
		Clock:        fixedClock{now: now}.Now,
	}
	if err := v.Verify(context.Background(), "client-1", assertion); !errors.Is(err, clientauth.ErrAssertionMalformed) {
		t.Fatalf("foreign-aud err=%v want ErrAssertionMalformed", err)
	}
}

// TestPrivateKeyJWTVerifier_AudArrayWithExtraneous_StillAccepted confirms
// that an "aud" array containing the expected value plus extras is
// accepted (RFC 7519 §4.1.3 allows an array). This guards against
// over-aggressive aud handling that would break legitimate clients
// while fixing CVE-2025-27370/27371.
func TestPrivateKeyJWTVerifier_AudArrayWithExtraneous_StillAccepted(t *testing.T) {
	t.Parallel()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubKeys := &josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{{
		Key: &priv.PublicKey, KeyID: "rp-key-1", Algorithm: string(josev4.ES256), Use: "sig",
	}}}
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	const tokenAud = "https://op.test/oidc/token" //nolint:gosec // not a credential.
	assertion := signAssertion(t, priv, "rp-key-1", map[string]any{
		"iss": "client-1",
		"sub": "client-1",
		"aud": []string{"https://other.example/as", tokenAud},
		"jti": "j-aud-array",
		"iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(),
	})
	v := &clientauth.PrivateKeyJWTVerifier{
		Resolver: staticResolver{keys: pubKeys},
		JTIStore: inmem.New(inmem.WithClock(fixedClock{now: now})).ConsumedJTIs(),
		Audience: tokenAud,
		Clock:    fixedClock{now: now}.Now,
	}
	if err := v.Verify(context.Background(), "client-1", assertion); err != nil {
		t.Fatalf("aud array: %v", err)
	}
}

// TestPrivateKeyJWTVerifier_JTIReplay_Rejected pins the RFC 7523 §3
// requirement that a private_key_jwt assertion's jti MUST NOT be
// replayed within its lifetime.
//
// Tracks: CVE-2020-15222 (ory/fosite < 0.31.0, GHSA-mh3m-8c74-74xh) —
// jti uniqueness was not enforced for private_key_jwt, so an
// intercepted assertion could be replayed to authenticate the client
// repeatedly. Equivalent to CWE-345 "Insufficient Verification of Data
// Authenticity". This test exercises both halves: first call succeeds,
// second call with the same assertion fails with ErrAssertionReplayed.
func TestPrivateKeyJWTVerifier_JTIReplay_Rejected(t *testing.T) {
	t.Parallel()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubKeys := &josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{{
		Key: &priv.PublicKey, KeyID: "rp-key-1", Algorithm: string(josev4.ES256), Use: "sig",
	}}}
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	const tokenAud = "https://op.test/oidc/token" //nolint:gosec // not a credential.
	assertion := signAssertion(t, priv, "rp-key-1", map[string]any{
		"iss": "client-1",
		"sub": "client-1",
		"aud": tokenAud,
		"jti": "j-replay",
		"iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(),
	})
	v := &clientauth.PrivateKeyJWTVerifier{
		Resolver: staticResolver{keys: pubKeys},
		JTIStore: inmem.New(inmem.WithClock(fixedClock{now: now})).ConsumedJTIs(),
		Audience: tokenAud,
		Clock:    fixedClock{now: now}.Now,
	}
	if err := v.Verify(context.Background(), "client-1", assertion); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	if err := v.Verify(context.Background(), "client-1", assertion); !errors.Is(err, clientauth.ErrAssertionReplayed) {
		t.Fatalf("replay err=%v want ErrAssertionReplayed", err)
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
	v := &clientauth.PrivateKeyJWTVerifier{
		Resolver: staticResolver{keys: &josev4.JSONWebKeySet{}}, // empty
		JTIStore: inmem.New(inmem.WithClock(fixedClock{now: now})).ConsumedJTIs(),
		Audience: "https://op.test/oidc/token",
		Clock:    fixedClock{now: now}.Now,
	}
	if err := v.Verify(context.Background(), "client-1", assertion); !errors.Is(err, clientauth.ErrCredentialsInvalid) {
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
