package inmem_test

import (
	"context"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestGrantStore_ListBySubject_NoDedup verifies that ListBySubject returns
// every active grant for a subject even when multiple grants share the same
// (subject, clientID) pair. The grantStore map is keyed on grant ID, so two
// saves with different IDs but identical (subject, clientID) produce two
// independent rows; ListBySubject must return both rather than collapsing to
// the most-recently-updated one.
func TestGrantStore_ListBySubject_NoDedup(t *testing.T) {
	t.Parallel()
	now := contract.Reference
	s := inmem.New(inmem.WithClock(fakeClock{now: now}))
	ctx := context.Background()

	// Two grants: same subject, same clientID, different IDs and UpdatedAt.
	g1 := &store.Grant{
		ID:        "grant-dedup-1",
		Subject:   "sub-dedup",
		ClientID:  "client-shared",
		Scope:     []string{"openid"},
		CreatedAt: now,
		UpdatedAt: now,
	}
	g2 := &store.Grant{
		ID:        "grant-dedup-2",
		Subject:   "sub-dedup",
		ClientID:  "client-shared",
		Scope:     []string{"openid", "profile"},
		CreatedAt: now,
		UpdatedAt: now.Add(time.Minute), // later UpdatedAt to distinguish the rows
	}
	if err := s.Grants().Save(ctx, g1); err != nil {
		t.Fatalf("Save g1: %v", err)
	}
	if err := s.Grants().Save(ctx, g2); err != nil {
		t.Fatalf("Save g2: %v", err)
	}

	got, err := s.Grants().ListBySubject(ctx, "sub-dedup")
	if err != nil {
		t.Fatalf("ListBySubject: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ListBySubject returned %d grant(s), want 2 (both rows must survive — no dedup by clientID)", len(got))
	}

	ids := make(map[string]struct{}, 2)
	for _, g := range got {
		if g.Subject != "sub-dedup" {
			t.Errorf("ListBySubject returned wrong subject: got %q", g.Subject)
		}
		ids[g.ID] = struct{}{}
	}
	if _, ok := ids["grant-dedup-1"]; !ok {
		t.Error("ListBySubject missing grant-dedup-1")
	}
	if _, ok := ids["grant-dedup-2"]; !ok {
		t.Error("ListBySubject missing grant-dedup-2")
	}
}

// TestGrantStore_ListBySubject_NoDedup_OnlyMatchingSubject confirms that
// grants belonging to a different subject are excluded even when the clientID
// matches, so the no-dedup behaviour does not accidentally widen the filter.
func TestGrantStore_ListBySubject_NoDedup_OnlyMatchingSubject(t *testing.T) {
	t.Parallel()
	now := contract.Reference
	s := inmem.New(inmem.WithClock(fakeClock{now: now}))
	ctx := context.Background()

	grants := []*store.Grant{
		{ID: "g-match-1", Subject: "target", ClientID: "c", Scope: []string{"openid"}, CreatedAt: now, UpdatedAt: now},
		{ID: "g-match-2", Subject: "target", ClientID: "c", Scope: []string{"openid"}, CreatedAt: now, UpdatedAt: now.Add(time.Second)},
		{ID: "g-other", Subject: "other", ClientID: "c", Scope: []string{"openid"}, CreatedAt: now, UpdatedAt: now},
	}
	for _, g := range grants {
		if err := s.Grants().Save(ctx, g); err != nil {
			t.Fatalf("Save %s: %v", g.ID, err)
		}
	}

	got, err := s.Grants().ListBySubject(ctx, "target")
	if err != nil {
		t.Fatalf("ListBySubject: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ListBySubject for 'target' returned %d grant(s), want 2", len(got))
	}
	for _, g := range got {
		if g.Subject != "target" {
			t.Errorf("ListBySubject leaked grant with subject %q", g.Subject)
		}
	}
}

// TestTxGrants_ListBySubject_NoDedup mirrors TestGrantStore_ListBySubject_NoDedup
// over the transactional path to confirm that txGrants.collectBySubject also
// returns every matching row without collapsing by clientID.
func TestTxGrants_ListBySubject_NoDedup(t *testing.T) {
	t.Parallel()
	now := contract.Reference
	s := inmem.New(inmem.WithClock(fakeClock{now: now}))
	ctx := context.Background()

	// Pre-seed one grant directly so the tx sees a parent-map row.
	seed := &store.Grant{
		ID:        "tx-dedup-seed",
		Subject:   "sub-tx-dedup",
		ClientID:  "client-shared",
		Scope:     []string{"openid"},
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.Grants().Save(ctx, seed); err != nil {
		t.Fatalf("pre-seed Save: %v", err)
	}

	tx, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Stage a second grant with the same (subject, clientID) inside the tx.
	staged := &store.Grant{
		ID:        "tx-dedup-staged",
		Subject:   "sub-tx-dedup",
		ClientID:  "client-shared",
		Scope:     []string{"openid", "email"},
		CreatedAt: now,
		UpdatedAt: now.Add(time.Minute),
	}
	if err := tx.Grants().Save(ctx, staged); err != nil {
		t.Fatalf("tx Save: %v", err)
	}

	got, err := tx.Grants().ListBySubject(ctx, "sub-tx-dedup")
	if err != nil {
		t.Fatalf("tx ListBySubject: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("tx ListBySubject returned %d grant(s), want 2 (parent + staged, no dedup)", len(got))
	}

	ids := make(map[string]struct{}, 2)
	for _, g := range got {
		ids[g.ID] = struct{}{}
	}
	if _, ok := ids["tx-dedup-seed"]; !ok {
		t.Error("tx ListBySubject missing tx-dedup-seed (parent row)")
	}
	if _, ok := ids["tx-dedup-staged"]; !ok {
		t.Error("tx ListBySubject missing tx-dedup-staged (staged row)")
	}
}

// TestTxGrants_ListBySubject_NoDedup_AfterCommit confirms that both rows
// remain visible after the transaction commits and a direct Grants() call
// lists them.
func TestTxGrants_ListBySubject_NoDedup_AfterCommit(t *testing.T) {
	t.Parallel()
	now := contract.Reference
	s := inmem.New(inmem.WithClock(fakeClock{now: now}))
	ctx := context.Background()

	tx, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}

	for _, id := range []string{"commit-grant-1", "commit-grant-2"} {
		g := &store.Grant{
			ID:        id,
			Subject:   "sub-commit",
			ClientID:  "client-shared",
			Scope:     []string{"openid"},
			CreatedAt: now,
			UpdatedAt: now,
		}
		if err := tx.Grants().Save(ctx, g); err != nil {
			t.Fatalf("tx Save %s: %v", id, err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	got, err := s.Grants().ListBySubject(ctx, "sub-commit")
	if err != nil {
		t.Fatalf("ListBySubject after Commit: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ListBySubject after Commit returned %d grant(s), want 2", len(got))
	}
}
