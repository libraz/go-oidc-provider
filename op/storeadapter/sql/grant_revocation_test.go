package oidcsql_test

import (
	"context"
	databasesql "database/sql"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/libraz/go-oidc-provider/op/store"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

// openGrantRevocationStore is the test-local helper for opening an in-memory SQLite
// database, applying the bundled schema, and returning a ready-to-use
// adapter. The helper centralises the boilerplate so each grant-
// revocation case stays focused on the contract under test.
func openGrantRevocationStore(t *testing.T) *oidcsql.Store {
	t.Helper()
	db, err := databasesql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := oidcsql.New(db, oidcsql.SQLite())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return s
}

// TestGrantRevocation_SQL_RoundTrip pins the happy path on the SQL
// adapter: a tombstone written through RevokeGrant is observable via
// IsRevoked for every iat at or before the tombstone's RevokedAt, and
// not observable for iats strictly after.
func TestGrantRevocation_SQL_RoundTrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openGrantRevocationStore(t)
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	gr := s.GrantRevocations()
	if err := gr.RevokeGrant(ctx, store.GrantTombstone{
		GrantID:   "g-1",
		RevokedAt: now,
		ExpiresAt: now.Add(time.Hour),
		Reason:    "code_replay",
	}); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	cases := []struct {
		name string
		iat  time.Time
		want bool
	}{
		{"before", now.Add(-time.Second), true},
		{"equal", now, true},
		{"after_1ns", now.Add(time.Nanosecond), false},
		{"after_1s", now.Add(time.Second), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := gr.IsRevoked(ctx, "g-1", "", tc.iat)
			if err != nil {
				t.Fatalf("IsRevoked: %v", err)
			}
			if got != tc.want {
				t.Fatalf("IsRevoked(iat=%s) = %v, want %v", tc.iat, got, tc.want)
			}
		})
	}
}

// TestGrantRevocation_SQL_Idempotent verifies that a second
// RevokeGrant against the same grant_id extends ExpiresAt to the max of
// the supplied / existing values and leaves RevokedAt untouched. The
// SQL implementation uses the dialect's GREATEST / MAX scalar in the
// upsert tail to satisfy this contract.
func TestGrantRevocation_SQL_Idempotent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openGrantRevocationStore(t)
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	gr := s.GrantRevocations()
	if err := gr.RevokeGrant(ctx, store.GrantTombstone{
		GrantID:   "g-idem",
		RevokedAt: now,
		ExpiresAt: now.Add(30 * time.Minute),
	}); err != nil {
		t.Fatalf("first RevokeGrant: %v", err)
	}
	// Second call: drift RevokedAt forward, extend ExpiresAt.
	if err := gr.RevokeGrant(ctx, store.GrantTombstone{
		GrantID:   "g-idem",
		RevokedAt: now.Add(10 * time.Minute),
		ExpiresAt: now.Add(2 * time.Hour),
	}); err != nil {
		t.Fatalf("second RevokeGrant: %v", err)
	}
	// RevokedAt MUST be the original instant: a token issued at the
	// original RevokedAt must still be revoked.
	revoked, err := gr.IsRevoked(ctx, "g-idem", "", now)
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if !revoked {
		t.Fatal("RevokedAt drifted: original instant no longer revoked")
	}
	// ExpiresAt MUST be the max: a GC cutoff between the original and
	// extended ExpiresAt MUST leave the row intact.
	n, err := gr.GC(ctx, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if n != 0 {
		t.Fatalf("GC dropped a row whose ExpiresAt was extended: count=%d", n)
	}
}

// TestGrantRevocation_SQL_DenylistPrecedence pins the precedence rule:
// a JTI denylist hit returns true even when the matching grant has no
// tombstone, and a different JTI under the same grant is not a wildcard
// match.
func TestGrantRevocation_SQL_DenylistPrecedence(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openGrantRevocationStore(t)
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	gr := s.GrantRevocations()
	if err := gr.RevokeJTI(ctx, store.RevokedJTI{
		JTI:       "jti-1",
		GrantID:   "g-1",
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("RevokeJTI: %v", err)
	}
	revoked, err := gr.IsRevoked(ctx, "g-1", "jti-1", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if !revoked {
		t.Fatal("denylist hit must report revoked even when grant is not tombstoned")
	}
	// A different JTI under the same grant MUST NOT be revoked
	// (the denylist is keyed exactly on jti).
	revoked, err = gr.IsRevoked(ctx, "g-1", "jti-other", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("IsRevoked unrelated jti: %v", err)
	}
	if revoked {
		t.Fatal("denylist must not be a wildcard")
	}
}

// TestGrantRevocation_SQL_RevokeJTIIdempotent verifies that a second
// RevokeJTI against the same JTI does not surface
// [store.ErrAlreadyExists]. The SQL implementation relies on the
// dialect-specific DO NOTHING tail (or `ON DUPLICATE KEY UPDATE
// jti = jti` on MySQL) to satisfy this contract; without it the
// duplicate INSERT would trip the PK uniqueness constraint and the
// test would fail with a unique-violation error.
func TestGrantRevocation_SQL_RevokeJTIIdempotent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openGrantRevocationStore(t)
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	gr := s.GrantRevocations()
	if err := gr.RevokeJTI(ctx, store.RevokedJTI{
		JTI:       "jti-dup",
		GrantID:   "g-1",
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("first RevokeJTI: %v", err)
	}
	if err := gr.RevokeJTI(ctx, store.RevokedJTI{
		JTI:       "jti-dup",
		GrantID:   "g-1",
		ExpiresAt: now.Add(2 * time.Hour),
	}); err != nil {
		t.Fatalf("second RevokeJTI: %v", err)
	}
	revoked, err := gr.IsRevoked(ctx, "g-1", "jti-dup", now)
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if !revoked {
		t.Fatal("denylist row vanished after a duplicate insert")
	}
}

// TestGrantRevocation_SQL_GC drops rows whose ExpiresAt is strictly
// before cutoff and leaves zero-expiry rows in place. The behaviour
// mirrors the inmem reference adapter byte-for-byte so the contract is
// portable across backends.
func TestGrantRevocation_SQL_GC(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openGrantRevocationStore(t)
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	gr := s.GrantRevocations()
	if err := gr.RevokeGrant(ctx, store.GrantTombstone{
		GrantID:   "g-live",
		RevokedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("RevokeGrant live: %v", err)
	}
	if err := gr.RevokeGrant(ctx, store.GrantTombstone{
		GrantID:   "g-expired",
		RevokedAt: now.Add(-2 * time.Hour),
		ExpiresAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("RevokeGrant expired: %v", err)
	}
	if err := gr.RevokeGrant(ctx, store.GrantTombstone{
		GrantID:   "g-no-exp",
		RevokedAt: now,
	}); err != nil {
		t.Fatalf("RevokeGrant zero-exp: %v", err)
	}
	if err := gr.RevokeJTI(ctx, store.RevokedJTI{
		JTI:       "jti-expired",
		GrantID:   "g-x",
		ExpiresAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("RevokeJTI expired: %v", err)
	}
	if err := gr.RevokeJTI(ctx, store.RevokedJTI{
		JTI:       "jti-live",
		GrantID:   "g-y",
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("RevokeJTI live: %v", err)
	}
	n, err := gr.GC(ctx, now)
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if n != 2 {
		t.Fatalf("GC count = %d, want 2 (one expired tombstone + one expired denylist row)", n)
	}
	if revoked, _ := gr.IsRevoked(ctx, "g-live", "", now.Add(-time.Second)); !revoked {
		t.Error("live tombstone collected by GC")
	}
	if revoked, _ := gr.IsRevoked(ctx, "g-no-exp", "", now); !revoked {
		t.Error("zero-expiry tombstone collected by GC")
	}
	if revoked, _ := gr.IsRevoked(ctx, "g-expired", "", now.Add(-3*time.Hour)); revoked {
		t.Error("expired tombstone survived GC")
	}
	if revoked, _ := gr.IsRevoked(ctx, "g-y", "jti-live", now); !revoked {
		t.Error("live denylist row collected by GC")
	}
	if revoked, _ := gr.IsRevoked(ctx, "g-x", "jti-expired", now); revoked {
		t.Error("expired denylist row survived GC")
	}
}

// TestGrantRevocation_SQL_EmptyInputs locks in the boundary semantics:
// empty GrantID / JTI inputs are no-ops and never seed wildcard rows.
func TestGrantRevocation_SQL_EmptyInputs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openGrantRevocationStore(t)
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	gr := s.GrantRevocations()
	if err := gr.RevokeGrant(ctx, store.GrantTombstone{RevokedAt: now}); err != nil {
		t.Fatalf("RevokeGrant empty: %v", err)
	}
	if err := gr.RevokeJTI(ctx, store.RevokedJTI{}); err != nil {
		t.Fatalf("RevokeJTI empty: %v", err)
	}
	revoked, err := gr.IsRevoked(ctx, "", "", now)
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if revoked {
		t.Fatal("IsRevoked with empty inputs must not match")
	}
}
