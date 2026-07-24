//nolint:testpackage // exercises the unexported ID-token lookup boundary
package tokenexchange

import (
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/customgrant"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

func TestLookupIDToken_RejectsCrossTokenConfusionAndInvalidLifetime(t *testing.T) {
	t.Parallel()

	entry, err := keys.GenerateES256("tx-id-token-validation-kid")
	if err != nil {
		t.Fatalf("GenerateES256: %v", err)
	}
	keySet, err := keys.NewSet([]keys.Entry{entry})
	if err != nil {
		t.Fatalf("keys.NewSet: %v", err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	h := &Handler{
		issuer: "https://op.example",
		keys:   keySet,
		clock:  fixedClock{now: now},
	}
	signer := tokens.FromInternalEntry(entry)

	signIDToken := func(t *testing.T, claims tokens.IDTokenClaims) string {
		t.Helper()
		raw, signErr := tokens.SignIDToken(signer, claims)
		if signErr != nil {
			t.Fatalf("SignIDToken: %v", signErr)
		}
		return raw
	}
	validClaims := tokens.IDTokenClaims{
		Issuer:    "https://op.example",
		Subject:   "user-123",
		Audience:  []string{"caller-client"},
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		Extra:     map[string]any{"scope": "openid profile"},
	}
	valid := signIDToken(t, validClaims)
	missingExpClaims := validClaims
	missingExpClaims.ExpiresAt = 0
	expiredClaims := validClaims
	expiredClaims.IssuedAt = now.Add(-time.Hour).Unix()
	expiredClaims.ExpiresAt = now.Add(-time.Second).Unix()

	accessToken, err := tokens.SignAccessToken(signer, tokens.AccessTokenClaims{
		Issuer:    validClaims.Issuer,
		Subject:   validClaims.Subject,
		Audience:  validClaims.Audience,
		ClientID:  "caller-client",
		IssuedAt:  validClaims.IssuedAt,
		ExpiresAt: validClaims.ExpiresAt,
		JTI:       "access-token-jti",
		Scope:     []string{"openid", "profile"},
	})
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}

	noneHeader := base64.RawURLEncoding.EncodeToString([]byte(
		`{"alg":"none","typ":"JWT","kid":"tx-id-token-validation-kid"}`,
	))
	nonePayload := base64.RawURLEncoding.EncodeToString([]byte(
		`{"iss":"https://op.example","sub":"user-123","aud":"caller-client","iat":1700000000,"exp":1700003600}`,
	))

	tests := []struct {
		name       string
		raw        string
		wantReason string
		wantErr    bool
	}{
		{
			name:    "valid ID token",
			raw:     valid,
			wantErr: false,
		},
		{
			name:       "OP access token relabelled as ID token",
			raw:        accessToken,
			wantReason: "typ_mismatch",
			wantErr:    true,
		},
		{
			name:       "alg none",
			raw:        noneHeader + "." + nonePayload + ".",
			wantReason: "malformed",
			wantErr:    true,
		},
		{
			name:       "missing exp",
			raw:        signIDToken(t, missingExpClaims),
			wantReason: "missing_claim",
			wantErr:    true,
		},
		{
			name:       "expired exp",
			raw:        signIDToken(t, expiredClaims),
			wantReason: "expired",
			wantErr:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			result, lookupErr := h.lookupIDToken(tc.raw)
			if !tc.wantErr {
				if lookupErr != nil {
					t.Fatalf("lookupIDToken: %v", lookupErr)
				}
				if result.view.Subject != validClaims.Subject {
					t.Errorf("Subject=%q want %q", result.view.Subject, validClaims.Subject)
				}
				if result.view.ExpiresAt.Unix() != validClaims.ExpiresAt {
					t.Errorf("ExpiresAt=%v want Unix(%d)", result.view.ExpiresAt, validClaims.ExpiresAt)
				}
				return
			}
			if !errors.Is(lookupErr, errTokenInvalid) {
				t.Fatalf("lookupIDToken err=%v want errTokenInvalid", lookupErr)
			}
			if result.reason != tc.wantReason {
				t.Errorf("reason=%q want %q", result.reason, tc.wantReason)
			}
		})
	}
}

func TestBuildResponse_RejectsSourceWithoutPositiveRemainingTTL(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0).UTC()
	tests := []struct {
		name      string
		expiresAt time.Time
	}{
		{name: "unknown expiry"},
		{name: "expired", expiresAt: now.Add(-time.Second)},
		{name: "expires now", expiresAt: now},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := &Handler{
				clock:        fixedClock{now: now},
				maxAccessTTL: time.Hour,
			}
			_, buildErr := h.buildResponse(
				t.Context(),
				customgrant.Request{Client: &store.Client{ID: "caller-client"}},
				TokenView{
					Subject:   "user-123",
					ExpiresAt: tc.expiresAt,
				},
				nil,
				[]string{"read"},
				[]string{"https://api.example"},
				nil,
			)
			if code := oauthCodeOf(t, buildErr); code != "invalid_grant" {
				t.Errorf("error code=%q want invalid_grant", code)
			}
		})
	}
}

func TestLookupOpaqueAccessToken_RejectsUnknownExpiry(t *testing.T) {
	t.Parallel()

	h := &Handler{
		clock: fixedClock{now: time.Unix(1_700_000_000, 0).UTC()},
		opaqueAccessTokens: staticOpaqueStore{rec: &store.OpaqueAccessToken{
			ClientID: "subject-client",
			Subject:  "user-123",
			Scope:    []string{"read"},
		}},
	}
	result, lookupErr := h.lookupOpaqueAccessToken(t.Context(), "opaque-without-expiry")
	if !errors.Is(lookupErr, errTokenInvalid) {
		t.Fatalf("lookupOpaqueAccessToken err=%v want errTokenInvalid", lookupErr)
	}
	if result.reason != "missing_claim" {
		t.Errorf("reason=%q want missing_claim", result.reason)
	}
}
