package jar_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/jar"
)

// TestVerify_RejectsSubFloorRSAKey pins the RFC 7518 §3.3 / RFC 8725 §3.2
// key-shape floor on client-supplied request-object keys: a client that
// registers a sub-2048-bit RSA key must not have its JAR verified, even
// though the signature itself is mathematically valid. The OP holds its
// own keys to the same floor, so a client key must not get a laxer check.
func TestVerify_RejectsSubFloorRSAKey(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	priv, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // deliberately sub-floor to assert rejection.
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	raw := signClaims(t, priv, testKID, happyClaims(now), josev4.RS256)
	keys := &josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{{
		Key: &priv.PublicKey, KeyID: testKID, Algorithm: string(josev4.RS256), Use: "sig",
	}}}
	v := newTestVerifier(t, now, keys)
	if _, err := v.Verify(context.Background(), raw, testClientID, newClient()); !errors.Is(err, jar.ErrSigInvalid) {
		t.Fatalf("err=%v want ErrSigInvalid", err)
	}
}

// TestVerify_AcceptsFloorRSAKey is the positive control: a compliant
// 2048-bit RSA request-object key still verifies, proving the key-shape
// gate leaves conforming clients unchanged.
func TestVerify_AcceptsFloorRSAKey(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	raw := signClaims(t, priv, testKID, happyClaims(now), josev4.RS256)
	keys := &josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{{
		Key: &priv.PublicKey, KeyID: testKID, Algorithm: string(josev4.RS256), Use: "sig",
	}}}
	v := newTestVerifier(t, now, keys)
	if _, err := v.Verify(context.Background(), raw, testClientID, newClient()); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}
