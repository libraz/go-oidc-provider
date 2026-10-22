package clientauth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

const advisoryAud = "https://op.test/oidc/token"

func advisoryVerifier(t *testing.T, priv *ecdsa.PrivateKey, now time.Time) *clientauth.PrivateKeyJWTVerifier {
	t.Helper()
	keys := &josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{{
		Key: &priv.PublicKey, KeyID: "rp-key-1", Algorithm: string(josev4.ES256), Use: "sig",
	}}}
	return &clientauth.PrivateKeyJWTVerifier{
		Resolver: staticResolver{keys: keys},
		JTIStore: inmem.New(inmem.WithClock(fixedClock{now: now})).ConsumedJTIs(),
		Audience: advisoryAud,
		Clock:    fixedClock{now: now}.Now,
	}
}

func advisoryKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return priv
}

// TestPrivateKeyJWTVerifier_RejectsNonObjectPayloads pins that a correctly
// signed assertion whose payload is not a JSON object is rejected as
// malformed, never returned as a successful authentication.
//
// Tracks: CVE-2026-107723 (fast-jwt — claim validation silently skipped when
// the payload was a JSON array)
func TestPrivateKeyJWTVerifier_RejectsNonObjectPayloads(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	priv := advisoryKey(t)
	signer, err := josev4.NewSigner(
		josev4.SigningKey{Algorithm: josev4.ES256, Key: josev4.JSONWebKey{
			Key: priv, KeyID: "rp-key-1", Algorithm: string(josev4.ES256), Use: "sig",
		}},
		(&josev4.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	for name, payload := range map[string]string{
		"array": `[]`, "null": `null`, "string": `"s"`, "number": `1`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			obj, err := signer.Sign([]byte(payload))
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			raw, err := obj.CompactSerialize()
			if err != nil {
				t.Fatalf("CompactSerialize: %v", err)
			}
			err = advisoryVerifier(t, priv, now).Verify(context.Background(), "client-1", raw)
			if !errors.Is(err, clientauth.ErrAssertionMalformed) {
				t.Fatalf("err=%v want ErrAssertionMalformed", err)
			}
		})
	}
}

// TestPrivateKeyJWTVerifier_ExpLeewayIsBoundedConstant pins the exp
// tolerance at exactly DefaultAssertionLeeway: one second inside it is
// accepted, one second beyond it is rejected.
//
// Tracks: CVE-2026-107721 (fast-jwt — clockTolerance: Infinity disabled the
// exp/nbf checks)
func TestPrivateKeyJWTVerifier_ExpLeewayIsBoundedConstant(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	priv := advisoryKey(t)

	for name, tc := range map[string]struct {
		expAge  time.Duration
		wantErr error
	}{
		"beyond leeway": {clientauth.DefaultAssertionLeeway + time.Second, clientauth.ErrAssertionMalformed},
		"within leeway": {clientauth.DefaultAssertionLeeway - time.Second, nil},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			raw := signAssertion(t, priv, "rp-key-1", map[string]any{
				"iss": "client-1", "sub": "client-1", "aud": advisoryAud, "jti": "j-leeway",
				"iat": now.Add(-time.Hour).Unix(), "exp": now.Add(-tc.expAge).Unix(),
			})
			err := advisoryVerifier(t, priv, now).Verify(context.Background(), "client-1", raw)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err=%v want %v", err, tc.wantErr)
			}
		})
	}
}

// TestPrivateKeyJWTVerifier_ReplayKeysOnJTINotRawAssertion pins that replay
// detection follows the parsed jti: the same claims signed twice yield
// distinct serialisations, and the second is still a replay.
//
// Tracks: CVE-2026-102269 (PyJWT — non-canonical signature segments gave one
// token several string forms, bypassing a raw-token revocation list)
func TestPrivateKeyJWTVerifier_ReplayKeysOnJTINotRawAssertion(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	priv := advisoryKey(t)
	claims := map[string]any{
		"iss": "client-1", "sub": "client-1", "aud": advisoryAud, "jti": "j-same",
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
	}
	first := signAssertion(t, priv, "rp-key-1", claims)
	second := signAssertion(t, priv, "rp-key-1", claims)
	if first == second {
		t.Fatal("expected distinct serialisations for the same claims")
	}

	v := advisoryVerifier(t, priv, now)
	if err := v.Verify(context.Background(), "client-1", first); err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	if err := v.Verify(context.Background(), "client-1", second); !errors.Is(err, clientauth.ErrAssertionReplayed) {
		t.Fatalf("re-signed assertion err=%v want ErrAssertionReplayed", err)
	}
}
