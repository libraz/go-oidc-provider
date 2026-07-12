package clientauth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/jose"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// keyselectAud is the token-endpoint audience the key-selection tests
// mint assertions for.
const keyselectAud = "https://op.test/oidc/token"

func rsaSigJWK(pub *rsa.PublicKey, kid string) josev4.JSONWebKey {
	return josev4.JSONWebKey{Key: pub, KeyID: kid, Algorithm: string(josev4.RS256), Use: "sig"}
}

func keyselectVerifier(tb testing.TB, keys *josev4.JSONWebKeySet, now time.Time) *clientauth.PrivateKeyJWTVerifier {
	tb.Helper()
	return &clientauth.PrivateKeyJWTVerifier{
		Resolver: staticResolver{keys: keys},
		JTIStore: inmem.New(inmem.WithClock(fixedClock{now: now})).ConsumedJTIs(),
		Audience: keyselectAud,
		Clock:    fixedClock{now: now}.Now,
	}
}

func keyselectClaims(now time.Time, jti string) map[string]any {
	return map[string]any{
		"iss": "client-1", "sub": "client-1", "aud": keyselectAud, "jti": jti,
		"iat": now.Add(-30 * time.Second).Unix(), "exp": now.Add(2 * time.Minute).Unix(),
	}
}

func newRSAKey(tb testing.TB) *rsa.PrivateKey {
	tb.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatalf("GenerateKey: %v", err)
	}
	return k
}

// TestPrivateKeyJWTVerifier_KidPinsSigningKey pins that a `kid` header
// selects exactly the named key: an assertion whose header names key A
// but is actually signed by key B MUST be rejected rather than accepted
// by sweeping the rest of the keyset. Pinning both closes the
// amplification channel (one garbage assertion no longer forces a verify
// per registered key) and enforces that a client signs with the key it
// names (RFC 7515 §4.1.4).
func TestPrivateKeyJWTVerifier_KidPinsSigningKey(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	k1, k2 := newRSAKey(t), newRSAKey(t)
	keys := &josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{
		rsaSigJWK(&k1.PublicKey, "k1"),
		rsaSigJWK(&k2.PublicKey, "k2"),
	}}

	// Signed with k2 but header names k1: only k1 is trialled, so the
	// signature must not verify.
	mismatched := signRSAAssertion(t, k2, "k1", keyselectClaims(now, "j-kid-mismatch"))
	if err := keyselectVerifier(t, keys, now).Verify(context.Background(), "client-1", mismatched); !errors.Is(err, clientauth.ErrCredentialsInvalid) {
		t.Fatalf("kid-mismatched assertion accepted: err=%v want ErrCredentialsInvalid", err)
	}

	// Signed with k2 and header names k2: the kid selects the right key
	// among many and the assertion authenticates.
	matched := signRSAAssertion(t, k2, "k2", keyselectClaims(now, "j-kid-match"))
	if err := keyselectVerifier(t, keys, now).Verify(context.Background(), "client-1", matched); err != nil {
		t.Fatalf("kid-matched assertion rejected: %v", err)
	}
}

// TestPrivateKeyJWTVerifier_KidlessTrialCapBoundsSweep pins the kid-less
// trial cap: a client with a large JWKS cannot force one RSA verify per
// key with a kid-less assertion. Exactly jose.MaxKidlessTrialKeys
// shape-passing keys are trialled; a legitimate signer positioned beyond
// that bound is unreachable (rejected), while a signer within the bound
// authenticates.
func TestPrivateKeyJWTVerifier_KidlessTrialCapBoundsSweep(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	signer := newRSAKey(t)

	trialCap := jose.MaxKidlessTrialKeys
	decoys := make([]josev4.JSONWebKey, 0, trialCap)
	for range trialCap {
		decoys = append(decoys, rsaSigJWK(&newRSAKey(t).PublicKey, ""))
	}

	// Signer sits one past the cap behind trialCap shape-passing decoys:
	// the sweep breaks after trialCap failed verifies, before reaching it.
	beyondCap := &josev4.JSONWebKeySet{Keys: append(append([]josev4.JSONWebKey{}, decoys...), rsaSigJWK(&signer.PublicKey, ""))}
	beyond := signRSAAssertion(t, signer, "", keyselectClaims(now, "j-kidless-beyond"))
	if err := keyselectVerifier(t, beyondCap, now).Verify(context.Background(), "client-1", beyond); !errors.Is(err, clientauth.ErrCredentialsInvalid) {
		t.Fatalf("signer beyond kid-less trial cap was reached: err=%v want ErrCredentialsInvalid", err)
	}

	// Positive control: signer within the bound (cap-1 decoys before it)
	// still authenticates.
	withinCap := &josev4.JSONWebKeySet{Keys: append(append([]josev4.JSONWebKey{}, decoys[:trialCap-1]...), rsaSigJWK(&signer.PublicKey, ""))}
	within := signRSAAssertion(t, signer, "", keyselectClaims(now, "j-kidless-within"))
	if err := keyselectVerifier(t, withinCap, now).Verify(context.Background(), "client-1", within); err != nil {
		t.Fatalf("signer within kid-less trial cap rejected: %v", err)
	}
}
