package tokens_test

import (
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/tokens"
)

// TestSignAccessToken_CnfJktEmitted verifies that a non-empty
// Confirmation map is encoded onto the wire as the "cnf" claim with
// the same key ordering the input carried.
func TestSignAccessToken_CnfJktEmitted(t *testing.T) {
	t.Parallel()

	key := newTestSigner(t)
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	claims := tokens.AccessTokenClaims{
		Issuer:    "https://op.example.com",
		Subject:   "user-1",
		Audience:  []string{"https://op.example.com"},
		ClientID:  "client-1",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(5 * time.Minute).Unix(),
		JTI:       "jti-1",
		Scope:     []string{"openid", "email"},
		Confirmation: map[string]string{
			"jkt": "thumbprint-value",
		},
	}
	jws, err := tokens.SignAccessToken(key, claims)
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}
	payload := decodePayload(t, jws)
	cnfRaw, ok := payload["cnf"]
	if !ok {
		t.Fatalf("cnf claim missing: %v", payload)
	}
	cnf, ok := cnfRaw.(map[string]any)
	if !ok {
		t.Fatalf("cnf=%T want map", cnfRaw)
	}
	if cnf["jkt"] != "thumbprint-value" {
		t.Errorf("cnf.jkt=%v want thumbprint-value", cnf["jkt"])
	}
}

// TestSignAccessToken_CnfOmittedWhenEmpty verifies that the "cnf"
// claim is absent when [tokens.AccessTokenClaims.Confirmation] is
// nil or empty. Bearer tokens MUST NOT carry an empty confirmation
// object on the wire.
func TestSignAccessToken_CnfOmittedWhenEmpty(t *testing.T) {
	t.Parallel()

	key := newTestSigner(t)
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	claims := tokens.AccessTokenClaims{
		Issuer:    "https://op.example.com",
		Subject:   "user-1",
		Audience:  []string{"https://op.example.com"},
		ClientID:  "client-1",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(5 * time.Minute).Unix(),
		JTI:       "jti-1",
		Scope:     []string{"openid"},
	}
	jws, err := tokens.SignAccessToken(key, claims)
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}
	if _, ok := decodePayload(t, jws)["cnf"]; ok {
		t.Errorf("cnf claim must be absent on bearer access tokens")
	}

	// Empty (non-nil) map is also a "bearer" signal.
	claims.Confirmation = map[string]string{}
	jws, err = tokens.SignAccessToken(key, claims)
	if err != nil {
		t.Fatalf("SignAccessToken empty cnf: %v", err)
	}
	if _, ok := decodePayload(t, jws)["cnf"]; ok {
		t.Errorf("empty Confirmation must not produce a cnf claim")
	}
}

// TestVerify_CnfRoundTrip threads the cnf claim through SignAccessToken
// and AccessTokenVerifier. The library treats the claim as opaque;
// downstream resource-server code is the consumer.
func TestVerify_CnfRoundTrip(t *testing.T) {
	t.Parallel()

	key := newTestSigner(t)
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	claims := tokens.AccessTokenClaims{
		Issuer:       "https://op.example.com",
		Subject:      "user-1",
		Audience:     []string{"https://op.example.com"},
		ClientID:     "client-1",
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(5 * time.Minute).Unix(),
		JTI:          "jti-1",
		Scope:        []string{"openid"},
		Confirmation: map[string]string{"jkt": "abc"},
	}
	jws, err := tokens.SignAccessToken(key, claims)
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}
	keySet, err := keys.NewSet([]keys.Entry{{KeyID: key.KeyID, Signer: key.Signer}})
	if err != nil {
		t.Fatalf("keys.NewSet: %v", err)
	}
	v := &tokens.AccessTokenVerifier{
		Keys:   keySet,
		Issuer: claims.Issuer,
		Clock:  fixedClock{now: now},
	}
	parsed, _, err := v.Verify(jws)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got := parsed.Confirmation["jkt"]; got != "abc" {
		t.Errorf("cnf.jkt=%q want abc", got)
	}
}

type fixedClock struct{ now time.Time }

func (f fixedClock) Now() time.Time { return f.now }
