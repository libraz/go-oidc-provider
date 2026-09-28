//go:build testcontainers

package oidcsql_test

import (
	"context"
	"testing"

	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

// TestMySQL_RevokeChainSeesDescendantInsertedAfterSnapshot pins the
// invariant [Dialect.forUpdate] on refreshRevokeChainChildren protects:
// under InnoDB's REPEATABLE READ, a plain SELECT reuses the transaction's
// first read as its snapshot for the rest of the transaction, so a
// descendant a concurrent rotation commits after that snapshot was fixed
// — but before the cascade reaches its parent — must still be caught by
// a locking read rather than missed by a stale one (RFC 9700 §2.2.2).
//
// The transaction is driven here through [store.Tx] rather than two real
// goroutines: the race is a property of one transaction's snapshot, not
// of thread timing, so pinning the ordering with an explicit Tx is both
// deterministic and exactly what a concurrent rotation would produce.
func TestMySQL_RevokeChainSeesDescendantInsertedAfterSnapshot(t *testing.T) {
	t.Parallel()

	b := newMySQLFactory(t)(t)
	s, ok := b.Store.(*oidcsql.Store)
	if !ok {
		t.Fatalf("factory produced %T, want *oidcsql.Store", b.Store)
	}
	ctx := context.Background()
	now := b.Now()
	rt := s.RefreshTokens()

	const (
		root  = "snapshot-root"
		nodeA = "snapshot-a"
		nodeB = "snapshot-b"
		nodeC = "snapshot-c"
	)
	if err := rt.Save(ctx, guardRefresh(now, root, nil)); err != nil {
		t.Fatalf("Save root: %v", err)
	}
	if err := rt.Save(ctx, guardRefresh(now, nodeA, strPtrSQL(root))); err != nil {
		t.Fatalf("Save A: %v", err)
	}
	if err := rt.Save(ctx, guardRefresh(now, nodeB, strPtrSQL(nodeA))); err != nil {
		t.Fatalf("Save B: %v", err)
	}

	tx, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	// A plain read fixes this transaction's REPEATABLE READ snapshot
	// before nodeC exists. RevokeChain's own internal reads reuse this
	// same snapshot rather than establishing a fresh one per statement.
	if _, err := tx.RefreshTokens().Find(ctx, root); err != nil {
		t.Fatalf("Find root (fixing the snapshot): %v", err)
	}

	// nodeC is inserted and committed through a separate connection
	// after the snapshot above was fixed but before the cascade below
	// reaches nodeB — the timing a rotation racing a replay cascade
	// produces.
	if err := rt.Save(ctx, guardRefresh(now, nodeC, strPtrSQL(nodeB))); err != nil {
		t.Fatalf("Save C: %v", err)
	}

	if err := tx.RefreshTokens().RevokeChain(ctx, root); err != nil {
		t.Fatalf("RevokeChain: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	got, err := rt.Find(ctx, nodeC)
	if err != nil {
		t.Fatalf("Find nodeC after cascade: %v", err)
	}
	if !got.Revoked {
		t.Fatal("nodeC, inserted after the cascade's snapshot was fixed, was left unrevoked by RevokeChain")
	}
}
