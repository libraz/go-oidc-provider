package revokeendpoint_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/revokeendpoint"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestHandler_JWTAccessToken_RevokedAuditFollowsPersistence pins that
// token.revoked for a JWT access token is recorded only when a revocation row
// was written. Under the None strategy, or with no substore behind the active
// one, the token keeps verifying until exp and the audit stream must not say
// otherwise; the wire answer is 200 either way.
func TestHandler_JWTAccessToken_RevokedAuditFollowsPersistence(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		strategy    store.AccessTokenRevocationStrategy
		wireRegs    bool
		wantRevoked bool
	}{
		{name: "none strategy", strategy: store.RevocationStrategyNone, wireRegs: true},
		{name: "grant tombstone without substores", strategy: store.RevocationStrategyGrantTombstone},
		{name: "jti registry", strategy: store.RevocationStrategyJTIRegistry, wireRegs: true, wantRevoked: true},
		{name: "grant tombstone", strategy: store.RevocationStrategyGrantTombstone, wireRegs: true, wantRevoked: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
			priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("ecdsa key: %v", err)
			}
			keyset, err := keys.NewSet([]keys.Entry{{KeyID: "outcome-jwt-1", Signer: priv}})
			if err != nil {
				t.Fatalf("keys.NewSet: %v", err)
			}
			mem := inmem.New(inmem.WithClock(clock))

			const clientID = "client-revoke-jwt-outcome"
			const secret = "revoke-jwt-outcome-secret" //nolint:gosec // not a credential — opaque test fixture secret.
			hash, err := (&clientauth.Argon2id{}).Hash(secret)
			if err != nil {
				t.Fatalf("Argon2id.Hash: %v", err)
			}
			if err := mem.RegisterClient(context.Background(), &store.Client{
				ID:                      clientID,
				SecretHash:              hash,
				TokenEndpointAuthMethod: "client_secret_basic",
			}); err != nil {
				t.Fatalf("RegisterClient: %v", err)
			}
			const jti = "jwt-outcome-jti-1"
			if err := mem.AccessTokens().Register(context.Background(), store.AccessTokenRecord{
				JTI:       jti,
				GrantID:   "jwt-outcome-grant-1",
				Subject:   "user-1",
				ClientID:  clientID,
				Scopes:    []string{"openid"},
				IssuedAt:  clock.now,
				ExpiresAt: clock.now.Add(time.Hour),
			}); err != nil {
				t.Fatalf("AccessTokens.Register: %v", err)
			}
			raw, err := tokens.SignAccessToken(tokens.SigningKey{KeyID: "outcome-jwt-1", Signer: priv}, tokens.AccessTokenClaims{
				Issuer:    "https://op.example",
				Subject:   "user-1",
				Audience:  []string{"https://op.example"},
				ClientID:  clientID,
				IssuedAt:  clock.now.Unix(),
				ExpiresAt: clock.now.Add(time.Hour).Unix(),
				JTI:       jti,
				GrantID:   "jwt-outcome-grant-1",
				Scope:     []string{"openid"},
			})
			if err != nil {
				t.Fatalf("SignAccessToken: %v", err)
			}

			capture := newRevokeAuditCapture()
			deps := revokeendpoint.Deps{
				Issuer:             "https://op.example",
				Clients:            mem.Clients(),
				Keys:               keyset,
				Clock:              clock,
				RevocationStrategy: tc.strategy,
				Audit:              capture.emitter(),
			}
			if tc.wireRegs {
				deps.AccessTokens = mem.AccessTokens()
				deps.GrantRevocations = mem.GrantRevocations()
			}

			form := url.Values{"token": {raw}, "token_type_hint": {"access_token"}}
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://op.example/revoke", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.SetBasicAuth(clientID, secret)
			rec := httptest.NewRecorder()
			revokeendpoint.Handler(deps).ServeHTTP(rec, req)
			resp := rec.Result()
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("StatusCode=%d want 200", resp.StatusCode)
			}
			if got := capture.findEvent("token.revoked") != nil; got != tc.wantRevoked {
				t.Fatalf("token.revoked emitted=%v want %v; captured=%s", got, tc.wantRevoked, capture.dump())
			}
		})
	}
}
