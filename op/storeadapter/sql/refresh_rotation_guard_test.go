package oidcsql_test

import (
	"context"
	"errors"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/libraz/go-oidc-provider/op/store"
)

// guardRefresh builds a refresh-token record with a far-future expiry so
// the expiry gate never masks the rotation-guard behaviour under test.
func guardRefresh(now time.Time, id string, parent *string) *store.RefreshToken {
	return &store.RefreshToken{
		ID:        id,
		ClientID:  "c",
		Subject:   "s",
		GrantID:   "g",
		Scope:     []string{"openid", "offline_access"},
		ParentID:  parent,
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
	}
}

func strPtrSQL(s string) *string { return &s }

// TestSQLite_RefreshRotation_HappyPath pins the single-threaded rotation
// contract the OFCS suite depends on against the SQL adapter: rotate
// R -> R', R is consumed, R' is a live, consumable token. The
// guarded-write hardening must not perturb this path.
func TestSQLite_RefreshRotation_HappyPath(t *testing.T) {
	t.Parallel()
	b := newSQLiteFactory(t)(t)
	ctx := context.Background()
	now := b.Now()
	rt := b.Store.RefreshTokens()

	if err := rt.Save(ctx, guardRefresh(now, "R", nil)); err != nil {
		t.Fatalf("Save R: %v", err)
	}
	if _, err := rt.Consume(ctx, "R"); err != nil {
		t.Fatalf("Consume R: %v", err)
	}
	if err := rt.Save(ctx, guardRefresh(now, "R2", strPtrSQL("R"))); err != nil {
		t.Fatalf("Save rotated R2: %v", err)
	}
	got, err := rt.Find(ctx, "R2")
	if err != nil {
		t.Fatalf("Find R2: %v", err)
	}
	if got.ConsumedAt != nil || got.Revoked {
		t.Fatalf("rotated R2 must be live after happy-path rotation: %+v", got)
	}
	if _, err := rt.Consume(ctx, "R2"); err != nil {
		t.Fatalf("Consume rotated R2: %v", err)
	}
}

// TestSQLite_RefreshRotation_GuardRejectsSaveUnderRevokedParent pins the
// guarded-write predicate: when a chain revocation tombstones the parent
// before the racing rotation's Save lands, the Save is treated as a
// replay — it returns [store.ErrAlreadyConsumed] and rolls the descendant
// back so it never becomes redeemable (RFC 9700 §2.2.2).
func TestSQLite_RefreshRotation_GuardRejectsSaveUnderRevokedParent(t *testing.T) {
	t.Parallel()
	b := newSQLiteFactory(t)(t)
	ctx := context.Background()
	now := b.Now()
	rt := b.Store.RefreshTokens()

	if err := rt.Save(ctx, guardRefresh(now, "R", nil)); err != nil {
		t.Fatalf("Save R: %v", err)
	}
	if _, err := rt.Consume(ctx, "R"); err != nil {
		t.Fatalf("Consume R: %v", err)
	}
	// Replay cascade revokes the chain before the rotation persists R'.
	if err := rt.RevokeChain(ctx, "R"); err != nil {
		t.Fatalf("RevokeChain R: %v", err)
	}
	if err := rt.Save(ctx, guardRefresh(now, "R2", strPtrSQL("R"))); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("Save under revoked parent err=%v, want ErrAlreadyConsumed", err)
	}
	// The descendant must have been rolled back, not persisted.
	if _, err := rt.Find(ctx, "R2"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find R2 after guarded rollback err=%v, want ErrNotFound", err)
	}
}

// TestSQLite_RefreshRotation_GuardKeepsSaveUnderLiveParent is the
// negative control for the predicate: a parent consumed by legitimate
// rotation (Revoked == false) must NOT trip the guard, so the rotated
// descendant persists and stays live.
func TestSQLite_RefreshRotation_GuardKeepsSaveUnderLiveParent(t *testing.T) {
	t.Parallel()
	b := newSQLiteFactory(t)(t)
	ctx := context.Background()
	now := b.Now()
	rt := b.Store.RefreshTokens()

	if err := rt.Save(ctx, guardRefresh(now, "R", nil)); err != nil {
		t.Fatalf("Save R: %v", err)
	}
	if _, err := rt.Consume(ctx, "R"); err != nil {
		t.Fatalf("Consume R: %v", err)
	}
	if err := rt.Save(ctx, guardRefresh(now, "R2", strPtrSQL("R"))); err != nil {
		t.Fatalf("Save rotated R2 under live parent: %v", err)
	}
	got, err := rt.Find(ctx, "R2")
	if err != nil {
		t.Fatalf("Find R2: %v", err)
	}
	if got.Revoked || got.ConsumedAt != nil {
		t.Fatalf("R2 under a live (consumed-not-revoked) parent must stay live: %+v", got)
	}
}
