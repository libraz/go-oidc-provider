package oidcsql_test

import (
	"context"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
)

// TestRevokeByClient_AccessTokensAndOpaqueTokens pins the optional dynamic
// registration cascade capability for the SQL adapter. The in-memory adapter
// already provides it; SQL must not silently skip live bearer credentials.
func TestRevokeByClient_AccessTokensAndOpaqueTokens(t *testing.T) {
	t.Parallel()

	testRevokeByClient(t, newSQLiteFactory(t)(t))
}

// testRevokeByClient is shared with the real MySQL/PostgreSQL testcontainers
// gate so dialect-specific UPDATE predicates cannot silently drift from the
// SQLite development path.
func testRevokeByClient(t *testing.T, b contract.Backend) {
	t.Helper()
	ctx := context.Background()
	now := b.Now()

	registry := b.Store.AccessTokens()
	registryByClient, ok := registry.(store.RevokeByClient)
	if !ok {
		t.Fatal("SQL AccessTokenRegistry does not implement store.RevokeByClient")
	}
	for _, rec := range []store.AccessTokenRecord{
		{JTI: "jti-client-a-1", GrantID: "grant-a", Subject: "user-1", ClientID: "client-a", IssuedAt: now, ExpiresAt: now.Add(time.Hour)},
		{JTI: "jti-client-a-2", GrantID: "grant-b", Subject: "user-1", ClientID: "client-a", IssuedAt: now, ExpiresAt: now.Add(time.Hour)},
		{JTI: "jti-client-b", GrantID: "grant-c", Subject: "user-1", ClientID: "client-b", IssuedAt: now, ExpiresAt: now.Add(time.Hour)},
	} {
		if err := registry.Register(ctx, rec); err != nil {
			t.Fatalf("AccessTokens.Register(%s): %v", rec.JTI, err)
		}
	}
	if err := registryByClient.RevokeByClient(ctx, "client-a"); err != nil {
		t.Fatalf("AccessTokens.RevokeByClient: %v", err)
	}
	for _, tc := range []struct {
		jti     string
		revoked bool
	}{{"jti-client-a-1", true}, {"jti-client-a-2", true}, {"jti-client-b", false}} {
		rec, err := registry.Find(ctx, tc.jti)
		if err != nil || rec == nil {
			t.Fatalf("AccessTokens.Find(%s): rec=%v err=%v", tc.jti, rec, err)
		}
		if rec.Revoked != tc.revoked {
			t.Errorf("AccessTokens.Find(%s).Revoked=%v want %v", tc.jti, rec.Revoked, tc.revoked)
		}
	}

	opaque := b.Store.OpaqueAccessTokens()
	opaqueByClient, ok := opaque.(store.RevokeByClient)
	if !ok {
		t.Fatal("SQL OpaqueAccessTokenStore does not implement store.RevokeByClient")
	}
	for _, tok := range []*store.OpaqueAccessToken{
		{ID: "opaque-client-a-1", GrantID: "grant-a", Subject: "user-1", ClientID: "client-a", Audience: "https://rs.example", IssuedAt: now, ExpiresAt: now.Add(time.Hour)},
		{ID: "opaque-client-a-2", GrantID: "grant-b", Subject: "user-1", ClientID: "client-a", Audience: "https://rs.example", IssuedAt: now, ExpiresAt: now.Add(time.Hour)},
		{ID: "opaque-client-b", GrantID: "grant-c", Subject: "user-1", ClientID: "client-b", Audience: "https://rs.example", IssuedAt: now, ExpiresAt: now.Add(time.Hour)},
	} {
		if err := opaque.Save(ctx, tok); err != nil {
			t.Fatalf("OpaqueAccessTokens.Save(%s): %v", tok.ID, err)
		}
	}
	if err := opaqueByClient.RevokeByClient(ctx, "client-a"); err != nil {
		t.Fatalf("OpaqueAccessTokens.RevokeByClient: %v", err)
	}
	for _, tc := range []struct {
		id      string
		revoked bool
	}{{"opaque-client-a-1", true}, {"opaque-client-a-2", true}, {"opaque-client-b", false}} {
		tok, err := opaque.Find(ctx, tc.id)
		if err != nil {
			t.Fatalf("OpaqueAccessTokens.Find(%s): %v", tc.id, err)
		}
		if tok.Revoked != tc.revoked {
			t.Errorf("OpaqueAccessTokens.Find(%s).Revoked=%v want %v", tc.id, tok.Revoked, tc.revoked)
		}
	}
}
