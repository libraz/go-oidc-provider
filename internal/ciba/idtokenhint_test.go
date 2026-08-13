package ciba_test

import (
	"context"
	"errors"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/internal/ciba"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/tokens"
)

const (
	hintIssuer   = "https://op.example"
	hintClientID = "client-hint"
	hintSubject  = "user-hint"
	hintKID      = "hint-kid"
)

// hintKeys returns a fresh single-entry OP keyset plus the signing key
// that matches it, so the tests below sign with the same machinery the
// OP uses in production rather than assembling a JWS by hand.
func hintKeys(t *testing.T) (*keys.Set, tokens.SigningKey) {
	t.Helper()
	entry, err := keys.GenerateES256(hintKID)
	if err != nil {
		t.Fatalf("keys.GenerateES256: %v", err)
	}
	set, err := keys.NewSet([]keys.Entry{entry})
	if err != nil {
		t.Fatalf("keys.NewSet: %v", err)
	}
	return set, tokens.FromInternalEntry(entry)
}

// signHint serialises an id_token with the supplied claims.
func signHint(t *testing.T, key tokens.SigningKey, claims tokens.IDTokenClaims) string {
	t.Helper()
	raw, err := tokens.SignIDToken(key, claims)
	if err != nil {
		t.Fatalf("tokens.SignIDToken: %v", err)
	}
	return raw
}

// signRawHint serialises an arbitrary claim map as an id_token-shaped
// JWS. It exists for the claim sets [tokens.SignIDToken] refuses to
// produce, which a hint verifier still has to reject on its own.
func signRawHint(t *testing.T, key tokens.SigningKey, claims map[string]any) string {
	t.Helper()
	signer, err := josev4.NewSigner(
		josev4.SigningKey{Algorithm: josev4.ES256, Key: key.Signer},
		(&josev4.SignerOptions{}).WithHeader("kid", key.KeyID).WithType("JWT"),
	)
	if err != nil {
		t.Fatalf("josev4.NewSigner: %v", err)
	}
	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("jwt.Serialize: %v", err)
	}
	return raw
}

// baseHintClaims is the canonical id_token claim set the rows mutate.
func baseHintClaims(now time.Time) tokens.IDTokenClaims {
	return tokens.IDTokenClaims{
		Issuer:    hintIssuer,
		Subject:   hintSubject,
		Audience:  []string{hintClientID},
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(10 * time.Minute).Unix(),
	}
}

func TestVerifyIDTokenHint_AcceptsTokenIssuedToTheClient(t *testing.T) {
	t.Parallel()
	set, key := hintKeys(t)
	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	raw := signHint(t, key, baseHintClaims(now))

	got, err := ciba.VerifyIDTokenHint(context.Background(), set, hintIssuer, hintClientID, raw)
	if err != nil {
		t.Fatalf("VerifyIDTokenHint: %v", err)
	}
	if got != hintSubject {
		t.Errorf("subject=%q want %q", got, hintSubject)
	}
}

// TestVerifyIDTokenHint_AcceptsMultiValuedAudience covers RFC 7519
// §4.1.3's array form: the client need only appear among the entries.
func TestVerifyIDTokenHint_AcceptsMultiValuedAudience(t *testing.T) {
	t.Parallel()
	set, key := hintKeys(t)
	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	claims := baseHintClaims(now)
	claims.Audience = []string{"someone-else", hintClientID}
	claims.AZP = hintClientID
	raw := signHint(t, key, claims)

	got, err := ciba.VerifyIDTokenHint(context.Background(), set, hintIssuer, hintClientID, raw)
	if err != nil {
		t.Fatalf("VerifyIDTokenHint: %v", err)
	}
	if got != hintSubject {
		t.Errorf("subject=%q want %q", got, hintSubject)
	}
}

// TestVerifyIDTokenHint_AcceptsExpiredToken pins the deliberate choice
// that freshness is not a gate: a CIBA consumption device holds an ID
// Token from a session that ended long ago.
func TestVerifyIDTokenHint_AcceptsExpiredToken(t *testing.T) {
	t.Parallel()
	set, key := hintKeys(t)
	past := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	raw := signHint(t, key, baseHintClaims(past))

	got, err := ciba.VerifyIDTokenHint(context.Background(), set, hintIssuer, hintClientID, raw)
	if err != nil {
		t.Fatalf("VerifyIDTokenHint: %v", err)
	}
	if got != hintSubject {
		t.Errorf("subject=%q want %q", got, hintSubject)
	}
}

func TestVerifyIDTokenHint_Rejections(t *testing.T) {
	t.Parallel()
	set, key := hintKeys(t)
	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)

	otherAudience := baseHintClaims(now)
	otherAudience.Audience = []string{"some-other-client"}

	azpElsewhere := baseHintClaims(now)
	azpElsewhere.AZP = "some-other-client"

	foreignIssuer := baseHintClaims(now)
	foreignIssuer.Issuer = "https://other-op.example"

	// A subject-less hint cannot come from this OP's signer, which
	// refuses to emit one; it is assembled by hand because the hint is
	// attacker-supplied input that any producer could have minted.
	noSubject := signRawHint(t, key, map[string]any{
		"iss": hintIssuer,
		"aud": hintClientID,
		"iat": now.Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
	})

	cases := []struct {
		name     string
		set      *keys.Set
		clientID string
		raw      string
		want     error
	}{
		{
			name:     "nil keyset",
			set:      nil,
			clientID: hintClientID,
			raw:      signHint(t, key, baseHintClaims(now)),
			want:     ciba.ErrIDTokenHintUnverifiable,
		},
		{
			name:     "empty client id",
			set:      set,
			clientID: "",
			raw:      signHint(t, key, baseHintClaims(now)),
			want:     ciba.ErrIDTokenHintAudience,
		},
		{
			name:     "not a jws",
			set:      set,
			clientID: hintClientID,
			raw:      "this.is.not-a-valid-jwt",
			want:     ciba.ErrIDTokenHintMalformed,
		},
		{
			name:     "audience names another client",
			set:      set,
			clientID: hintClientID,
			raw:      signHint(t, key, otherAudience),
			want:     ciba.ErrIDTokenHintAudience,
		},
		{
			name:     "azp names another client",
			set:      set,
			clientID: hintClientID,
			raw:      signHint(t, key, azpElsewhere),
			want:     ciba.ErrIDTokenHintAudience,
		},
		{
			name:     "foreign issuer",
			set:      set,
			clientID: hintClientID,
			raw:      signHint(t, key, foreignIssuer),
			want:     ciba.ErrIDTokenHintIssuer,
		},
		{
			name:     "no subject",
			set:      set,
			clientID: hintClientID,
			raw:      noSubject,
			want:     ciba.ErrIDTokenHintSubject,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ciba.VerifyIDTokenHint(context.Background(), tc.set, hintIssuer, tc.clientID, tc.raw)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err=%v want %v", err, tc.want)
			}
			if got != "" {
				t.Errorf("subject=%q want empty on rejection", got)
			}
		})
	}
}

// TestVerifyIDTokenHint_RejectsSignatureFromAnotherKey pins the
// keyset binding: the token's kid resolves to an entry in the verifying
// set, but the bytes were produced by a different private key. A
// verifier that trusted the kid header alone would admit it.
func TestVerifyIDTokenHint_RejectsSignatureFromAnotherKey(t *testing.T) {
	t.Parallel()
	_, key := hintKeys(t)
	otherSet, _ := hintKeys(t)
	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	raw := signHint(t, key, baseHintClaims(now))

	if _, err := ciba.VerifyIDTokenHint(context.Background(), otherSet, hintIssuer, hintClientID, raw); !errors.Is(
		err, ciba.ErrIDTokenHintSignature,
	) {
		t.Fatalf("err=%v want %v", err, ciba.ErrIDTokenHintSignature)
	}
}
