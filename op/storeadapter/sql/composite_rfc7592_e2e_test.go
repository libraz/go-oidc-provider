//go:build compositee2e

package oidcsql_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/registrationendpoint"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/composite"
)

// TestCompositeRFC7592Delete_CascadesSQLAccessTokens exercises the actual
// management-endpoint HTTP path with a SQL backend routed through composite.
// It is deliberately build-tagged: the SQL submodule normally tests as an
// independently consumable module, while importing the root internal endpoint
// requires the temporary workspace created by scripts/test_contracts.sh.
func TestCompositeRFC7592Delete_CascadesSQLAccessTokens(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b := newSQLiteFactory(t)(t)
	routed, err := composite.New(composite.WithDefault(b.Store))
	if err != nil {
		t.Fatalf("composite.New: %v", err)
	}
	clients, ok := routed.ClientRegistry()
	if !ok {
		t.Fatal("composite store does not expose ClientRegistry")
	}
	const clientID = "dynamic-composite-client"
	if err := clients.RegisterClient(ctx, &store.Client{ID: clientID, Source: store.ClientSourceDynamic}); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	const rat = "rfc7592-rat"
	if err := routed.RegistrationAccessTokens().Put(ctx, &store.RegistrationAccessToken{
		ClientID: clientID, HashedValue: sha256Hex(rat), CreatedAt: b.Now(),
	}); err != nil {
		t.Fatalf("RegistrationAccessTokens.Put: %v", err)
	}
	if err := routed.AccessTokens().Register(ctx, store.AccessTokenRecord{
		JTI: "composite-jti", ClientID: clientID, GrantID: "grant", ExpiresAt: b.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("AccessTokens.Register: %v", err)
	}
	if err := routed.OpaqueAccessTokens().Save(ctx, &store.OpaqueAccessToken{
		ID: "composite-opaque", ClientID: clientID, GrantID: "grant", ExpiresAt: b.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("OpaqueAccessTokens.Save: %v", err)
	}

	h := registrationendpoint.Handler(registrationendpoint.Deps{
		Issuer:                   "https://issuer.example.test",
		RegisterPath:             "/register",
		Clients:                  clients,
		RegistrationAccessTokens: routed.RegistrationAccessTokens(),
		RefreshTokens:            routed.RefreshTokens(),
		Grants:                   routed.Grants(),
		AccessTokens:             routed.AccessTokens(),
		OpaqueAccessTokens:       routed.OpaqueAccessTokens(),
	})
	req := httptest.NewRequest(http.MethodDelete, "/register/"+clientID, nil)
	req.Header.Set("Authorization", "Bearer "+rat)
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	if resp.Code != http.StatusNoContent {
		t.Fatalf("DELETE status=%d want 204; body=%s", resp.Code, resp.Body.String())
	}
	if got, err := routed.AccessTokens().Find(ctx, "composite-jti"); err != nil || got == nil || !got.Revoked {
		t.Fatalf("JWT access token was not revoked: rec=%+v err=%v", got, err)
	}
	if got, err := routed.OpaqueAccessTokens().Find(ctx, "composite-opaque"); err != nil || got == nil || !got.Revoked {
		t.Fatalf("opaque access token was not revoked: rec=%+v err=%v", got, err)
	}
}

func sha256Hex(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}
