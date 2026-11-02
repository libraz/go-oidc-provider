package inmem

import (
	"context"
	"testing"
	"time"
)

// TestTxRevokeChainCoversCommittedAndStagedGenerations pins which rows a
// transactional RevokeChain stamps when the chain spans committed and
// staged generations, and that the committed rows stay untouched until
// Commit.
func TestTxRevokeChainCoversCommittedAndStagedGenerations(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	s := New(WithClock(refreshIndexClock{now: now}))
	ctx := context.Background()

	save := func(id, parent string) {
		t.Helper()
		var p *string
		if parent != "" {
			p = &parent
		}
		if err := s.refreshes.Save(ctx, newRefreshIndexToken(now, id, "client", "grant", p)); err != nil {
			t.Fatalf("Save %s: %v", id, err)
		}
	}
	save("g0", "")
	save("g1", "g0")
	save("g1-sibling", "g0")
	save("other-root", "")
	save("other-child", "other-root")

	tx, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	rt := tx.RefreshTokens()
	for _, tok := range []struct{ id, parent string }{{"g2", "g1"}, {"g3", "g2"}, {"g2-sibling", "g1"}} {
		parent := tok.parent
		if err := rt.Save(ctx, newRefreshIndexToken(now, tok.id, "client", "grant", &parent)); err != nil {
			t.Fatalf("tx Save %s: %v", tok.id, err)
		}
	}
	if err := rt.RevokeChain(ctx, "g0"); err != nil {
		t.Fatalf("tx RevokeChain: %v", err)
	}

	revoked := []string{"g0", "g1", "g1-sibling", "g2", "g3", "g2-sibling"}
	untouched := []string{"other-root", "other-child"}
	for _, id := range revoked {
		got, err := rt.Find(ctx, id)
		if err != nil {
			t.Fatalf("tx Find %s: %v", id, err)
		}
		if !got.Revoked || got.ConsumedAt == nil {
			t.Errorf("in-tx view of %s: Revoked=%v ConsumedAt=%v, want revoked and consumed", id, got.Revoked, got.ConsumedAt)
		}
	}
	for _, id := range untouched {
		got, err := rt.Find(ctx, id)
		if err != nil {
			t.Fatalf("tx Find %s: %v", id, err)
		}
		if got.Revoked {
			t.Errorf("in-tx view of %s: revoked, want untouched", id)
		}
	}
	for _, id := range []string{"g0", "g1", "g1-sibling"} {
		if s.refreshes.m[hashKey(id)].Revoked {
			t.Errorf("committed %s revoked before Commit", id)
		}
	}

	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	for _, id := range revoked {
		assertRefreshRevoked(t, s.refreshes, id, true)
	}
	for _, id := range untouched {
		assertRefreshRevoked(t, s.refreshes, id, false)
	}
}

// TestTxRevokeChainFromStagedRoot covers a chain whose root and every
// descendant exist only in the transaction.
func TestTxRevokeChainFromStagedRoot(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	s := New(WithClock(refreshIndexClock{now: now}))
	ctx := context.Background()

	tx, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	rt := tx.RefreshTokens()
	if err := rt.Save(ctx, newRefreshIndexToken(now, "root", "client", "grant", nil)); err != nil {
		t.Fatalf("Save root: %v", err)
	}
	parent := "root"
	if err := rt.Save(ctx, newRefreshIndexToken(now, "child", "client", "grant", &parent)); err != nil {
		t.Fatalf("Save child: %v", err)
	}
	if err := rt.RevokeChain(ctx, "root"); err != nil {
		t.Fatalf("RevokeChain: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	assertRefreshRevoked(t, s.refreshes, "root", true)
	assertRefreshRevoked(t, s.refreshes, "child", true)
}
