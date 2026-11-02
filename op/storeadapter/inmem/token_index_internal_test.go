package inmem

import (
	"context"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

func TestAccessTokenRevocationFollowsIndexesThroughGCAndCommit(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	s := New()
	at := s.accessTokens
	register := func(r store.AccessTokenRecord) {
		t.Helper()
		if err := at.Register(ctx, r); err != nil {
			t.Fatalf("Register %s: %v", r.JTI, err)
		}
	}
	register(store.AccessTokenRecord{JTI: "dead", GrantID: "g1", ClientID: "c1", ExpiresAt: now.Add(-time.Hour)})
	register(store.AccessTokenRecord{JTI: "live", GrantID: "g1", ClientID: "c1", ExpiresAt: now.Add(time.Hour)})
	register(store.AccessTokenRecord{JTI: "bystander", GrantID: "g2", ClientID: "c2", ExpiresAt: now.Add(time.Hour)})

	if n, err := at.GC(ctx, now); err != nil || n != 1 {
		t.Fatalf("GC = %d, %v; want 1, nil", n, err)
	}
	if got := at.idx.byGrant["g1"]; len(got) != 1 {
		t.Fatalf("grant index after GC = %v, want only the live row", got)
	}

	tx, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if err := tx.AccessTokens().Register(ctx, store.AccessTokenRecord{
		JTI: "staged", GrantID: "g1", ClientID: "c3", ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("tx Register: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	if n, err := at.RevokeByGrant(ctx, "g1"); err != nil || n != 2 {
		t.Fatalf("RevokeByGrant = %d, %v; want 2 (live + committed staged), nil", n, err)
	}
	if err := at.RevokeByClient(ctx, "c2"); err != nil {
		t.Fatalf("RevokeByClient: %v", err)
	}
	for jti, want := range map[string]bool{"live": true, "staged": true, "bystander": true} {
		if got := at.m[jti].Revoked; got != want {
			t.Errorf("%s Revoked=%v, want %v", jti, got, want)
		}
	}
	if _, ok := at.m["dead"]; ok {
		t.Error("GC'd row still present")
	}

	// A transaction sees rows staged earlier in itself as well as committed ones.
	tx, err = s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx 2: %v", err)
	}
	if err := tx.AccessTokens().Register(ctx, store.AccessTokenRecord{
		JTI: "staged-2", GrantID: "g3", ClientID: "c3", ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("tx Register 2: %v", err)
	}
	if n, err := tx.AccessTokens().RevokeByGrant(ctx, "g3"); err != nil || n != 1 {
		t.Fatalf("tx RevokeByGrant = %d, %v; want 1, nil", n, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit 2: %v", err)
	}
	if !at.m["staged-2"].Revoked {
		t.Error("staged-2 not revoked after commit")
	}
}

func TestOpaqueAccessTokenRevocationFollowsIndexesThroughGCAndCommit(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	s := New()
	oat := s.opaqueAccessTokens
	save := func(id, grant, client, chain string, expires time.Time) {
		t.Helper()
		if err := oat.Save(ctx, &store.OpaqueAccessToken{
			ID: id, GrantID: grant, ClientID: client, ChainID: chain, ExpiresAt: expires,
		}); err != nil {
			t.Fatalf("Save %s: %v", id, err)
		}
	}
	save("dead", "g1", "c1", "ch1", now.Add(-time.Hour))
	save("live", "g1", "c1", "ch1", now.Add(time.Hour))
	save("other-chain", "g1", "c1", "ch2", now.Add(time.Hour))
	save("bystander", "g2", "c2", "ch3", now.Add(time.Hour))

	if n, err := oat.GC(ctx, now); err != nil || n != 1 {
		t.Fatalf("GC = %d, %v; want 1, nil", n, err)
	}
	if got := oat.idx.byClient["c1"]; len(got) != 2 {
		t.Fatalf("client index after GC = %v, want two live rows", got)
	}

	tx, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if err := tx.OpaqueAccessTokens().Save(ctx, &store.OpaqueAccessToken{
		ID: "staged", GrantID: "g1", ClientID: "c1", ChainID: "ch1", ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("tx Save: %v", err)
	}
	// Within the transaction: a committed row and the staged row share chain ch1.
	chains := tx.OpaqueAccessTokens().(store.OpaqueAccessTokenChainRevoker)
	if n, err := chains.RevokeByChain(ctx, "g1", "ch1"); err != nil || n != 2 {
		t.Fatalf("tx RevokeByChain = %d, %v; want 2, nil", n, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	for id, want := range map[string]bool{"live": true, "staged": true, "other-chain": false, "bystander": false} {
		if got := oat.m[hashKey(id)].Revoked; got != want {
			t.Errorf("%s Revoked=%v, want %v", id, got, want)
		}
	}
	if n, err := oat.RevokeByGrant(ctx, "g1"); err != nil || n != 1 {
		t.Fatalf("RevokeByGrant = %d, %v; want 1 (other-chain), nil", n, err)
	}
	if err := oat.RevokeByClient(ctx, "c2"); err != nil {
		t.Fatalf("RevokeByClient: %v", err)
	}
	if !oat.m[hashKey("bystander")].Revoked {
		t.Error("bystander not revoked by client")
	}
}
