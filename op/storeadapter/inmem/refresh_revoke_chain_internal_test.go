package inmem

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

func saveChain(t *testing.T, s *Store, now time.Time, prefix, grant string, depth int) []string {
	t.Helper()
	ids := make([]string, 0, depth)
	var parent *string
	for i := range depth {
		id := fmt.Sprintf("%s-%d", prefix, i)
		if err := s.refreshes.Save(context.Background(), newRefreshIndexToken(now, id, "client", grant, parent)); err != nil {
			t.Fatalf("Save %s: %v", id, err)
		}
		ids = append(ids, id)
		p := id
		parent = &p
	}
	return ids
}

func revokedState(t *testing.T, s *Store, id string) bool {
	t.Helper()
	rec, ok := s.refreshes.m[hashKey(id)]
	if !ok {
		t.Fatalf("token %s missing", id)
	}
	return rec.Revoked && rec.ConsumedAt != nil
}

func TestRevokeChain_RevokesWholeChainAndLeavesSiblingsUntouched(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	s := New(WithClock(refreshIndexClock{now: now}))
	ctx := context.Background()

	chain := saveChain(t, s, now, "a", "grant-a", 6)
	other := saveChain(t, s, now, "b", "grant-b", 4)

	// A fork: a second child of the chain's third token.
	fork := chain[2]
	if err := s.refreshes.Save(ctx, newRefreshIndexToken(now, "a-fork", "client", "grant-a", &fork)); err != nil {
		t.Fatalf("Save fork: %v", err)
	}

	// Revoking from the middle covers that node and everything below it,
	// including the fork, and nothing above or beside.
	if err := s.refreshes.RevokeChain(ctx, chain[2]); err != nil {
		t.Fatalf("RevokeChain: %v", err)
	}
	for _, id := range append(append([]string{}, chain[2:]...), "a-fork") {
		if !revokedState(t, s, id) {
			t.Errorf("%s was not revoked", id)
		}
	}
	for _, id := range append(append([]string{}, chain[:2]...), other...) {
		if revokedState(t, s, id) {
			t.Errorf("%s must not be revoked", id)
		}
	}

	if err := s.refreshes.RevokeChain(ctx, "unknown"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("RevokeChain unknown = %v, want ErrNotFound", err)
	}
}

func TestRevokeChain_FromRootCoversEveryGeneration(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	s := New(WithClock(refreshIndexClock{now: now}))
	ctx := context.Background()

	chain := saveChain(t, s, now, "c", "grant-c", 3)
	if err := s.refreshes.RevokeChain(ctx, chain[0]); err != nil {
		t.Fatalf("RevokeChain: %v", err)
	}
	for _, id := range chain {
		if !revokedState(t, s, id) {
			t.Errorf("%s was not revoked", id)
		}
	}
}

// BenchmarkRevokeChain_ManyUnrelatedTokens revokes a short chain while the
// store holds many unrelated tokens; the cost should track the chain.
func BenchmarkRevokeChain_ManyUnrelatedTokens(b *testing.B) {
	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	s := New(WithClock(refreshIndexClock{now: now}))
	ctx := context.Background()
	for i := range 20000 {
		tok := newRefreshIndexToken(now, fmt.Sprintf("noise-%d", i), "client", "noise", nil)
		if err := s.refreshes.Save(ctx, tok); err != nil {
			b.Fatal(err)
		}
	}
	var parent *string
	for i := range 8 {
		id := fmt.Sprintf("chain-%d", i)
		if err := s.refreshes.Save(ctx, newRefreshIndexToken(now, id, "client", "chain", parent)); err != nil {
			b.Fatal(err)
		}
		p := id
		parent = &p
	}
	b.ResetTimer()
	for range b.N {
		if err := s.refreshes.RevokeChain(ctx, "chain-0"); err != nil {
			b.Fatal(err)
		}
	}
}
