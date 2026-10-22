package endsession

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/backchannel"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/tokens"
)

// TestVerifyIDTokenHint_RejectsOtherOPTypedTokens pins that a logout token
// or a JWT access token signed by the OP, for the same client and subject,
// does not pass as an id_token_hint at /end_session, while an ID Token does.
func TestVerifyIDTokenHint_RejectsOtherOPTypedTokens(t *testing.T) {
	t.Parallel()

	const (
		issuer   = "https://op.example.com"
		clientID = "rp-1"
		subject  = "alice"
	)
	entry, err := keys.GenerateES256("typ-kid")
	if err != nil {
		t.Fatalf("keys.GenerateES256: %v", err)
	}
	set, err := keys.NewSet([]keys.Entry{entry})
	if err != nil {
		t.Fatalf("keys.NewSet: %v", err)
	}
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	key := tokens.FromInternalEntry(entry)

	idToken, err := tokens.SignIDToken(key, tokens.IDTokenClaims{
		Issuer: issuer, Subject: subject, Audience: []string{clientID},
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("SignIDToken: %v", err)
	}
	logout, err := backchannel.SignLogoutToken(
		backchannel.SigningKey{KeyID: entry.KeyID, Signer: entry.Signer},
		backchannel.LogoutClaims{
			Issuer: issuer, Audience: clientID, Subject: subject,
			IssuedAt: now.Unix(), ExpiresAt: now.Add(2 * time.Minute).Unix(),
		},
	)
	if err != nil {
		t.Fatalf("SignLogoutToken: %v", err)
	}
	access, err := tokens.SignAccessToken(key, tokens.AccessTokenClaims{
		Issuer: issuer, Subject: subject, Audience: []string{clientID}, ClientID: clientID,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(), JTI: "at-jti",
	})
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}

	got, err := verifyIDTokenHint(context.Background(), set, issuer, idToken, now)
	if err != nil || got.clientID != clientID || got.subject != subject {
		t.Fatalf("ID Token hint: claims=%+v err=%v", got, err)
	}
	for name, raw := range map[string]string{"logout+jwt": logout, "at+jwt": access} {
		if _, err := verifyIDTokenHint(context.Background(), set, issuer, raw, now); !errors.Is(err, errIDTokenMalformed) {
			t.Errorf("%s: err=%v want %v", name, err, errIDTokenMalformed)
		}
	}
}
