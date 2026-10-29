package oidcsql_test

import (
	"context"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

// TestStoreGC_SweepsEverySubstore writes one row into each of the nine
// swept systems, runs GC at a cutoff past their expiry, and requires the
// row to be gone, every counter to be reported, and an unexpired row to
// survive.
func TestStoreGC_SweepsEverySubstore(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	base := contract.Reference
	s, err := oidcsql.New(openSQLite(t), oidcsql.SQLite(), oidcsql.WithClock(&fixedClock{now: base}))
	if err != nil {
		t.Fatalf("oidcsql.New: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	expiry := base.Add(time.Hour)
	cutoff := base.Add(2 * time.Hour)
	live := base.Add(3 * time.Hour)
	must := func(what string, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	}

	must("auth code", s.AuthorizationCodes().Save(ctx, &store.AuthorizationCode{
		ID: "code-1", ClientID: "c", Subject: "u", GrantID: "g-code", RedirectURI: "https://rp/cb",
		Scope: []string{"openid"}, ExpiresAt: expiry, CreatedAt: base,
	}))
	must("par", s.PushedAuthRequests().Save(ctx, &store.PushedAuthRequest{
		URI: "urn:par:expired", ClientID: "c", RawParams: []byte("a=b"), ExpiresAt: expiry, CreatedAt: base,
	}))
	must("par live", s.PushedAuthRequests().Save(ctx, &store.PushedAuthRequest{
		URI: "urn:par:live", ClientID: "c", RawParams: []byte("a=b"), ExpiresAt: live, CreatedAt: base,
	}))
	must("interaction", s.Interactions().Save(ctx, &store.Interaction{
		ID: "ix-1", ClientID: "c", Step: "login", RawState: []byte("{}"),
		ExpiresAt: expiry, CreatedAt: base, UpdatedAt: base,
	}))
	must("session", s.Sessions().Save(ctx, &store.Session{
		ID: "sess-1", Subject: "u", AuthTime: base, ChooserGroupID: "grp",
		ExpiresAt: expiry, CreatedAt: base, UpdatedAt: base,
	}))
	must("refresh", s.RefreshTokens().Save(ctx, &store.RefreshToken{
		ID: "rt-1", ClientID: "c", Subject: "u", GrantID: "g-refresh", Scope: []string{"openid"},
		ExpiresAt: expiry, CreatedAt: base,
	}))
	must("access token", s.AccessTokens().Register(ctx, store.AccessTokenRecord{
		JTI: "at-1", GrantID: "g-at", Subject: "u", ClientID: "c", Scopes: []string{"read"},
		IssuedAt: base, ExpiresAt: expiry,
	}))
	must("opaque token", s.OpaqueAccessTokens().Save(ctx, &store.OpaqueAccessToken{
		ID: "opaque-1", GrantID: "g-op", Subject: "u", ClientID: "c", Scope: []string{"read"},
		Audience: "https://api.example.com", IssuedAt: base, ExpiresAt: expiry,
	}))
	must("tombstone", s.GrantRevocations().RevokeGrant(ctx, store.GrantTombstone{
		GrantID: "g-tomb", RevokedAt: base, ExpiresAt: expiry,
	}))
	must("revoked jti", s.GrantRevocations().RevokeJTI(ctx, store.RevokedJTI{
		JTI: "rj-1", GrantID: "g-rj", ExpiresAt: expiry,
	}))
	must("consumed jti", s.ConsumedJTIs().Mark(ctx, "jti-1", expiry))

	stats, err := s.GC(ctx, cutoff)
	if err != nil {
		t.Fatalf("GC: %v", err)
	}

	counts := map[string]int64{
		"AuthorizationCodes": stats.AuthorizationCodes,
		"PushedAuthRequests": stats.PushedAuthRequests,
		"Interactions":       stats.Interactions,
		"Sessions":           stats.Sessions,
		"RefreshTokens":      stats.RefreshTokens,
		"AccessTokens":       stats.AccessTokens,
		"OpaqueAccessTokens": stats.OpaqueAccessTokens,
		"GrantRevocations":   stats.GrantRevocations,
		"ConsumedJTIs":       stats.ConsumedJTIs,
	}
	var sum int64
	for name, n := range counts {
		if n < 1 {
			t.Errorf("GCStats.%s = %d, want >= 1", name, n)
		}
		sum += n
	}
	if stats.Total() != sum {
		t.Errorf("Total() = %d, want %d", stats.Total(), sum)
	}
	if stats.GrantRevocations != 2 {
		t.Errorf("GrantRevocations = %d, want 2 (tombstone + denylist row)", stats.GrantRevocations)
	}

	if _, err := s.AuthorizationCodes().Find(ctx, "code-1"); err == nil {
		t.Error("expired authorization code survived GC")
	}
	if _, err := s.RefreshTokens().Find(ctx, "rt-1"); err == nil {
		t.Error("expired refresh token survived GC")
	}
	if got, err := s.AccessTokens().Find(ctx, "at-1"); err != nil || got != nil {
		t.Errorf("expired access token survived GC: got=%+v err=%v", got, err)
	}
	// A second sweep finds nothing left in any system.
	again, err := s.GC(ctx, cutoff)
	if err != nil {
		t.Fatalf("second GC: %v", err)
	}
	if again.Total() != 0 {
		t.Errorf("second GC deleted %+v, want nothing left", again)
	}
	if _, err := s.PushedAuthRequests().Find(ctx, "urn:par:live"); err != nil {
		t.Errorf("unexpired PAR record did not survive GC: %v", err)
	}
}
