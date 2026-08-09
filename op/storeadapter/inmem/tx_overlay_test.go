package inmem_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// The auxiliary atomic-cluster substores stage their writes through an
// overlay onto the committed maps. These tests pin the guarantees
// [store.Tx] states for that arrangement: a transaction reads its own
// writes down to individual fields, a rollback discards every one of
// them, and nothing becomes visible to a direct reader before Commit.

func TestTxAccessTokens_ReadsItsOwnWrites(t *testing.T) {
	t.Parallel()
	now := contract.Reference
	s := inmem.New(inmem.WithClock(fakeClock{now: now}))
	ctx := context.Background()

	if err := s.AccessTokens().Register(ctx, store.AccessTokenRecord{
		JTI: "committed-jti", GrantID: "grant-1", ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("Register committed: %v", err)
	}

	tx, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	// A committed record is visible through the overlay.
	got, err := tx.AccessTokens().Find(ctx, "committed-jti")
	if err != nil || got == nil {
		t.Fatalf("Find committed record inside tx: rec=%+v err=%v", got, err)
	}

	// A staged registration is visible to a later read on the same tx.
	if err := tx.AccessTokens().Register(ctx, store.AccessTokenRecord{
		JTI: "staged-jti", GrantID: "grant-1", ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("Register staged: %v", err)
	}
	got, err = tx.AccessTokens().Find(ctx, "staged-jti")
	if err != nil || got == nil {
		t.Fatalf("Find staged registration: rec=%+v err=%v", got, err)
	}
	// ... and re-registering it is a duplicate, not a silent overwrite.
	if err := tx.AccessTokens().Register(ctx, store.AccessTokenRecord{
		JTI: "staged-jti", GrantID: "grant-1",
	}); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("re-Register staged: want ErrAlreadyExists, got %v", err)
	}

	// A revocation staged against a committed record is visible field
	// by field on the same tx.
	if err := tx.AccessTokens().RevokeByJTI(ctx, "committed-jti"); err != nil {
		t.Fatalf("RevokeByJTI: %v", err)
	}
	got, err = tx.AccessTokens().Find(ctx, "committed-jti")
	if err != nil || got == nil || !got.Revoked {
		t.Fatalf("revocation not visible on the same tx: rec=%+v err=%v", got, err)
	}

	// A cascade covers both the committed and the staged record.
	n, err := tx.AccessTokens().RevokeByGrant(ctx, "grant-1")
	if err != nil {
		t.Fatalf("RevokeByGrant: %v", err)
	}
	if n != 1 {
		t.Fatalf("RevokeByGrant flipped %d rows, want 1 (the already-revoked row must not be counted twice)", n)
	}
	got, err = tx.AccessTokens().Find(ctx, "staged-jti")
	if err != nil || got == nil || !got.Revoked {
		t.Fatalf("cascade not visible on the staged record: rec=%+v err=%v", got, err)
	}
}

func TestTxAccessTokens_GCThenRegisterSurvivesCommit(t *testing.T) {
	t.Parallel()
	now := contract.Reference
	s := inmem.New(inmem.WithClock(fakeClock{now: now}))
	ctx := context.Background()

	if err := s.AccessTokens().Register(ctx, store.AccessTokenRecord{
		JTI: "recycled-jti", GrantID: "grant-1", ExpiresAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	tx, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	n, err := tx.AccessTokens().GC(ctx, now)
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if n != 1 {
		t.Fatalf("GC dropped %d rows, want 1", n)
	}
	if got, err := tx.AccessTokens().Find(ctx, "recycled-jti"); err != nil || got != nil {
		t.Fatalf("swept record still visible on the same tx: rec=%+v err=%v", got, err)
	}
	// Re-registering the same JTI after the sweep must survive Commit:
	// the sweep's deletion cannot be applied after the insert.
	if err := tx.AccessTokens().Register(ctx, store.AccessTokenRecord{
		JTI: "recycled-jti", GrantID: "grant-2", ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("Register after GC: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	got, err := s.AccessTokens().Find(ctx, "recycled-jti")
	if err != nil || got == nil {
		t.Fatalf("re-registered record lost at Commit: rec=%+v err=%v", got, err)
	}
	if got.GrantID != "grant-2" {
		t.Fatalf("committed record has GrantID %q, want grant-2", got.GrantID)
	}
}

func TestTxAccessTokens_RollbackDiscardsSweep(t *testing.T) {
	t.Parallel()
	now := contract.Reference
	s := inmem.New(inmem.WithClock(fakeClock{now: now}))
	ctx := context.Background()

	if err := s.AccessTokens().Register(ctx, store.AccessTokenRecord{
		JTI: "expired-jti", GrantID: "grant-1", ExpiresAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	tx, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if _, err := tx.AccessTokens().GC(ctx, now); err != nil {
		t.Fatalf("GC: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	got, err := s.AccessTokens().Find(ctx, "expired-jti")
	if err != nil || got == nil {
		t.Fatalf("a rolled-back sweep deleted the row anyway: rec=%+v err=%v", got, err)
	}
}

func TestTxOpaqueAccessTokens_ReadsItsOwnWrites(t *testing.T) {
	t.Parallel()
	now := contract.Reference
	s := inmem.New(inmem.WithClock(fakeClock{now: now}))
	ctx := context.Background()

	if err := s.OpaqueAccessTokens().Save(ctx, &store.OpaqueAccessToken{
		ID: "committed-opaque", GrantID: "grant-1", ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("Save committed: %v", err)
	}

	tx, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	// The raw id round-trips through the overlay even though the stored
	// record only ever carries the digest.
	got, err := tx.OpaqueAccessTokens().Find(ctx, "committed-opaque")
	if err != nil {
		t.Fatalf("Find committed inside tx: %v", err)
	}
	if got.ID != "committed-opaque" {
		t.Fatalf("Find returned ID %q, want the raw id back", got.ID)
	}

	if err := tx.OpaqueAccessTokens().Save(ctx, &store.OpaqueAccessToken{
		ID: "staged-opaque", GrantID: "grant-1", ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("Save staged: %v", err)
	}
	if err := tx.OpaqueAccessTokens().Save(ctx, &store.OpaqueAccessToken{
		ID: "staged-opaque", GrantID: "grant-1",
	}); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("re-Save staged: want ErrAlreadyExists, got %v", err)
	}

	if err := tx.OpaqueAccessTokens().RevokeByID(ctx, "committed-opaque"); err != nil {
		t.Fatalf("RevokeByID: %v", err)
	}
	got, err = tx.OpaqueAccessTokens().Find(ctx, "committed-opaque")
	if err != nil || !got.Revoked {
		t.Fatalf("revocation not visible on the same tx: rec=%+v err=%v", got, err)
	}

	n, err := tx.OpaqueAccessTokens().RevokeByGrant(ctx, "grant-1")
	if err != nil {
		t.Fatalf("RevokeByGrant: %v", err)
	}
	if n != 1 {
		t.Fatalf("RevokeByGrant flipped %d rows, want 1", n)
	}
	got, err = tx.OpaqueAccessTokens().Find(ctx, "staged-opaque")
	if err != nil || !got.Revoked {
		t.Fatalf("cascade not visible on the staged record: rec=%+v err=%v", got, err)
	}
}

func TestTxGrantRevocations_ReadsItsOwnWrites(t *testing.T) {
	t.Parallel()
	now := contract.Reference
	s := inmem.New(inmem.WithClock(fakeClock{now: now}))
	ctx := context.Background()

	tx, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := tx.GrantRevocations().RevokeGrant(ctx, store.GrantTombstone{
		GrantID: "grant-1", RevokedAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	revoked, err := tx.GrantRevocations().IsRevoked(ctx, "grant-1", "", now)
	if err != nil || !revoked {
		t.Fatalf("tombstone not visible on the same tx: revoked=%v err=%v", revoked, err)
	}

	// A second cascade inside the same transaction extends RevokedAt,
	// so a token issued between the two calls is covered as well.
	later := now.Add(time.Minute)
	if err := tx.GrantRevocations().RevokeGrant(ctx, store.GrantTombstone{
		GrantID: "grant-1", RevokedAt: later, ExpiresAt: later.Add(time.Hour),
	}); err != nil {
		t.Fatalf("second RevokeGrant: %v", err)
	}
	revoked, err = tx.GrantRevocations().IsRevoked(ctx, "grant-1", "", later)
	if err != nil || !revoked {
		t.Fatalf("extended tombstone not visible on the same tx: revoked=%v err=%v", revoked, err)
	}

	if err := tx.GrantRevocations().RevokeJTI(ctx, store.RevokedJTI{
		JTI: "denied-jti", GrantID: "grant-2", ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("RevokeJTI: %v", err)
	}
	// The denylist is consulted ahead of the tombstone, so a JTI whose
	// grant carries no tombstone is still reported revoked.
	revoked, err = tx.GrantRevocations().IsRevoked(ctx, "grant-2", "denied-jti", now.Add(time.Hour))
	if err != nil || !revoked {
		t.Fatalf("denylist row not visible on the same tx: revoked=%v err=%v", revoked, err)
	}
}

func TestTxGrantRevocations_RollbackDiscardsSweep(t *testing.T) {
	t.Parallel()
	now := contract.Reference
	s := inmem.New(inmem.WithClock(fakeClock{now: now}))
	ctx := context.Background()

	if err := s.GrantRevocations().RevokeGrant(ctx, store.GrantTombstone{
		GrantID: "grant-1", RevokedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	if err := s.GrantRevocations().RevokeJTI(ctx, store.RevokedJTI{
		JTI: "old-jti", GrantID: "grant-1", ExpiresAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("RevokeJTI: %v", err)
	}

	tx, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	n, err := tx.GrantRevocations().GC(ctx, now)
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if n != 2 {
		t.Fatalf("GC dropped %d rows, want 2 (one tombstone and one denylist row)", n)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	// A revocation is a fail-secure record: a rolled-back sweep must
	// never be the reason a token becomes acceptable again.
	revoked, err := s.GrantRevocations().IsRevoked(ctx, "grant-1", "old-jti", now.Add(-3*time.Hour))
	if err != nil {
		t.Fatalf("IsRevoked after rollback: %v", err)
	}
	if !revoked {
		t.Fatal("a rolled-back sweep deleted the revocation rows anyway")
	}
}

// TestTxRefreshTokens_RevokeChainVisibleBeforeCommit pins the
// requirement that a RevokeChain issued inside a transaction is
// observable on that same transaction with Revoked set, not merely with
// ConsumedAt stamped: a handler that revokes and then re-reads inside
// one transaction must not act on state the store has already
// invalidated.
func TestTxRefreshTokens_RevokeChainVisibleBeforeCommit(t *testing.T) {
	t.Parallel()
	now := contract.Reference
	s := inmem.New(inmem.WithClock(fakeClock{now: now}))
	ctx := context.Background()

	root := "chain-root"
	if err := s.RefreshTokens().Save(ctx, &store.RefreshToken{
		ID: root, ClientID: "c", Subject: "s", GrantID: "g",
		ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}); err != nil {
		t.Fatalf("Save root: %v", err)
	}

	tx, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	child := "chain-child"
	if err := tx.RefreshTokens().Save(ctx, &store.RefreshToken{
		ID: child, ClientID: "c", Subject: "s", GrantID: "g",
		ParentID: &root, ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}); err != nil {
		t.Fatalf("Save child inside tx: %v", err)
	}
	if err := tx.RefreshTokens().RevokeChain(ctx, root); err != nil {
		t.Fatalf("RevokeChain: %v", err)
	}

	for _, id := range []string{root, child} {
		got, findErr := tx.RefreshTokens().Find(ctx, id)
		if findErr != nil {
			t.Fatalf("Find %s inside tx after RevokeChain: %v", id, findErr)
		}
		if !got.Revoked {
			t.Errorf("%s reports Revoked=false inside the tx that revoked it: %+v", id, got)
		}
		if got.ConsumedAt == nil {
			t.Errorf("%s has no ConsumedAt stamp inside the tx that revoked it: %+v", id, got)
		}
	}

	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	for _, id := range []string{root, child} {
		got, findErr := s.RefreshTokens().Find(ctx, id)
		if findErr != nil {
			t.Fatalf("Find %s after Commit: %v", id, findErr)
		}
		if !got.Revoked {
			t.Errorf("%s reports Revoked=false after Commit: %+v", id, got)
		}
	}
}
