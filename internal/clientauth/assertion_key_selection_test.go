package clientauth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestPrivateKeyJWTVerifier_KeySelectionIgnoresTheAssertionsOwnHeader
// pins that the key an assertion is verified against is chosen by the
// OP from the keyset registered to the client being authenticated, and
// by nothing the assertion carries.
//
// The threat this addresses is not an outsider. It is the other tenants
// of the same OP: an attacker who registers a client legitimately holds
// a private key the OP has on file and will accept for *some* client.
// The only thing standing between that and impersonating any other
// client is that key selection is driven by "who is this request
// claiming to authenticate as", resolved from storage. Every JOSE
// header field is a lever for moving that decision somewhere else —
// naming another client's kid, embedding a key, pointing at a keyset
// the attacker hosts — and each must be inert.
//
// Tracks: CVE-2026-11800 (Keycloak) — an attacker holding any valid
// client credential in the realm forged a JWT authorization-grant
// assertion by manipulating the algorithm field, and signature
// verification was satisfied without the registered key (CWE-347).
//
// Tracks: CVE-2026-27962 (Authlib) — the verification key was taken
// from the token's own "jwk" header, so a token signed by an attacker
// key that published its public half inline verified successfully.
// Pinned here on the client-assertion surface, where an embedded key
// must not displace the registered keyset; the generic parse-time
// refusal is pinned by TestParseSigned_HeaderInjection_NeverFetches.
func TestPrivateKeyJWTVerifier_KeySelectionIgnoresTheAssertionsOwnHeader(t *testing.T) {
	t.Parallel()

	const (
		victim      = "client-victim"
		attacker    = "client-attacker"
		victimKID   = "victim-key-1"
		attackerKID = "attacker-key-1"
		tokenAud    = "https://op.test/oidc/token" //nolint:gosec // not a credential.
	)

	victimKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(victim): %v", err)
	}
	attackerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(attacker): %v", err)
	}

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	st := inmem.New(inmem.WithClock(fixedClock{now: now}))
	registerAssertionClient(t, st, victim, victimKID, &victimKey.PublicKey)
	registerAssertionClient(t, st, attacker, attackerKID, &attackerKey.PublicKey)

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
	// claimsFor builds an assertion body that is entirely well-formed
	// for the victim: the only thing wrong with the forgeries below is
	// which key signed them. That keeps each subtest a test of key
	// selection rather than of claim validation.
	claimsFor := func(jti string) map[string]any {
		return map[string]any{
			"iss": victim,
			"sub": victim,
			"aud": tokenAud,
			"jti": jti,
			"iat": now.Unix(),
			"exp": now.Add(time.Minute).Unix(),
		}
	}

	// The control. Without it a verifier that rejected everything would
	// pass every forgery subtest below.
	t.Run("the victim's own key authenticates the victim", func(t *testing.T) {
		t.Parallel()
		assertion := signAssertion(t, victimKey, victimKID, claimsFor("j-control"))
		if err := newVerifier().Verify(context.Background(), victim, assertion); err != nil {
			t.Fatalf("victim's own assertion rejected: %v", err)
		}
	})

	forgeries := []struct {
		name string
		// header is merged into the JOSE header of an assertion signed
		// with the attacker's key while claiming to be the victim.
		header map[string]any
		kid    string
	}{
		{
			// The baseline forgery: a key the OP knows and accepts,
			// used to authenticate as somebody else.
			name: "attacker's registered key, attacker's kid",
			kid:  attackerKID,
		},
		{
			// Naming the victim's kid does not conjure the victim's
			// key; it selects a key the attacker cannot sign with.
			name: "attacker's key signing under the victim's kid",
			kid:  victimKID,
		},
		{
			// With no kid the verifier trials the client's keys. It
			// must trial the victim's, never the presenter's.
			name: "attacker's key with no kid to steer selection",
			kid:  "",
		},
		{
			// A key inline in the header is supplied by whoever wrote
			// the token, so trusting it would make every assertion
			// self-authenticating (RFC 7515 §4.1.3 — the verification
			// key comes from application context).
			name:   "attacker's public key embedded in a jwk header",
			kid:    attackerKID,
			header: map[string]any{"jwk": mustPublicJWK(t, &attackerKey.PublicKey, attackerKID)},
		},
		{
			// Same defect one indirection out: a URL the attacker
			// controls, which must not be fetched at all.
			name:   "jku header pointing at a keyset the attacker hosts",
			kid:    attackerKID,
			header: map[string]any{"jku": "https://attacker.test.invalid/jwks.json"},
		},
		{
			// x5u is the certificate-shaped variant of the same lever.
			name:   "x5u header pointing at a chain the attacker hosts",
			kid:    attackerKID,
			header: map[string]any{"x5u": "https://attacker.test.invalid/chain.pem"},
		},
	}

	for i, f := range forgeries {
		t.Run(f.name, func(t *testing.T) {
			t.Parallel()
			assertion := signAssertionWithHeader(t, attackerKey, f.kid, f.header, claimsFor("j-forge-"+strconv.Itoa(i)))
			err := newVerifier().Verify(context.Background(), victim, assertion)
			if !errors.Is(err, clientauth.ErrCredentialsInvalid) {
				t.Fatalf("assertion authenticated %q while signed by %q's key: err=%v, want ErrCredentialsInvalid",
					victim, attacker, err)
			}
		})
	}
}

// registerAssertionClient seeds a private_key_jwt client whose only
// registered credential is the supplied public key.
func registerAssertionClient(t *testing.T, st *inmem.Store, clientID, keyID string, pub *ecdsa.PublicKey) {
	t.Helper()

	jwks, err := json.Marshal(josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{{
		Key: pub, KeyID: keyID, Algorithm: string(josev4.ES256), Use: "sig",
	}}})
	if err != nil {
		t.Fatalf("marshal JWKS for %s: %v", clientID, err)
	}
	if err := st.RegisterClient(context.Background(), &store.Client{
		ID:                      clientID,
		TokenEndpointAuthMethod: string(clientauth.MethodPrivateKeyJWT),
		JWKs:                    jwks,
	}); err != nil {
		t.Fatalf("RegisterClient(%s): %v", clientID, err)
	}
}

// signAssertionWithHeader is signAssertion with arbitrary extra JOSE
// header members, so a test can drive the header fields that a naive
// verifier would let steer key resolution. An empty keyID omits "kid"
// entirely rather than emitting an empty one.
func signAssertionWithHeader(
	tb testing.TB,
	priv *ecdsa.PrivateKey,
	keyID string,
	header map[string]any,
	claims map[string]any,
) string {
	tb.Helper()

	sk := josev4.SigningKey{Algorithm: josev4.ES256, Key: priv}
	if keyID != "" {
		sk.Key = josev4.JSONWebKey{
			Key:       priv,
			KeyID:     keyID,
			Algorithm: string(josev4.ES256),
			Use:       "sig",
		}
	}
	opts := (&josev4.SignerOptions{}).WithType("JWT")
	for k, v := range header {
		opts = opts.WithHeader(josev4.HeaderKey(k), v)
	}
	signer, err := josev4.NewSigner(sk, opts)
	if err != nil {
		tb.Fatalf("NewSigner: %v", err)
	}
	out, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		tb.Fatalf("Serialize: %v", err)
	}
	return out
}

// mustPublicJWK renders a public key as the JSON object shape a "jwk"
// header member carries.
func mustPublicJWK(tb testing.TB, pub *ecdsa.PublicKey, keyID string) map[string]any {
	tb.Helper()

	raw, err := (&josev4.JSONWebKey{
		Key: pub, KeyID: keyID, Algorithm: string(josev4.ES256), Use: "sig",
	}).MarshalJSON()
	if err != nil {
		tb.Fatalf("marshal JWK: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		tb.Fatalf("unmarshal JWK: %v", err)
	}
	return out
}
