package jar_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/jar"
)

// encAndSigKeyset stands up the keyset a client that both signs request
// objects and receives encrypted responses publishes: one "sig" key and
// one "enc" key, each with its own kid. It returns the set plus a
// request object signed by whichever member the caller names, so a test
// can drive the same fixture through both key selections.
func encAndSigKeyset(t *testing.T, now time.Time) (*josev4.JSONWebKeySet, map[string]string) {
	t.Helper()
	set := &josev4.JSONWebKeySet{}
	signed := map[string]string{}
	for kid, use := range map[string]string{"kid-sig": "sig", "kid-enc": "enc"} {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		signed[kid] = signClaims(t, priv, kid, happyClaims(now), josev4.ES256)
		set.Keys = append(set.Keys, josev4.JSONWebKey{
			Key:       &priv.PublicKey,
			KeyID:     kid,
			Algorithm: string(josev4.ES256),
			Use:       use,
		})
	}
	return set, signed
}

// TestVerify_RejectsRequestObjectSignedWithEncryptionKey pins RFC 7517
// §4.2: a JWK the client published with use=enc is its response-
// encryption key, never a verification key. Client registration already
// refuses to count such a key as a signing key, so the verifier must not
// be laxer — a request object whose kid names the enc key does not
// verify even though its signature is mathematically valid.
func TestVerify_RejectsRequestObjectSignedWithEncryptionKey(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	keys, signed := encAndSigKeyset(t, now)
	v := newTestVerifier(t, now, keys)
	_, err := v.Verify(context.Background(), signed["kid-enc"], testClientID, newClient())
	if !errors.Is(err, jar.ErrNoMatchingJWK) {
		t.Fatalf("err=%v want ErrNoMatchingJWK", err)
	}
}

// TestVerify_AcceptsRequestObjectSignedWithSigningKey is the positive
// control for the use gate: the same client's use=sig key still verifies,
// so the gate rejects by declared purpose rather than by the presence of
// a second key in the set.
func TestVerify_AcceptsRequestObjectSignedWithSigningKey(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	keys, signed := encAndSigKeyset(t, now)
	v := newTestVerifier(t, now, keys)
	if _, err := v.Verify(context.Background(), signed["kid-sig"], testClientID, newClient()); err != nil {
		t.Fatalf("Verify with the signing key: %v", err)
	}
}

// TestVerify_RejectsKIDLessObjectAgainstLoneEncryptionKey covers the
// branch that selects a key without a kid header: a keyset whose single
// member is an encryption key offers no verification key at all, so the
// selection must miss rather than fall back to the only member present.
func TestVerify_RejectsKIDLessObjectAgainstLoneEncryptionKey(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	raw := signClaims(t, priv, "", happyClaims(now), josev4.ES256)
	keys := &josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{{
		Key: &priv.PublicKey, Algorithm: string(josev4.ES256), Use: "enc",
	}}}
	v := newTestVerifier(t, now, keys)
	if _, err := v.Verify(context.Background(), raw, testClientID, newClient()); !errors.Is(err, jar.ErrNoMatchingJWK) {
		t.Fatalf("err=%v want ErrNoMatchingJWK", err)
	}
}
