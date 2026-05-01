package inmem_test

import (
	"context"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestGrantRevocation_RoundTrip pins the happy path: a tombstone written
// with RevokeGrant is observable via IsRevoked for any iat at or before
// the tombstone's RevokedAt.
func TestGrantRevocation_RoundTrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	now := time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)
	if err := s.GrantRevocations().RevokeGrant(ctx, store.GrantTombstone{
		GrantID:   "g-1",
		RevokedAt: now,
		ExpiresAt: now.Add(time.Hour),
		Reason:    "code_replay",
	}); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	revoked, err := s.GrantRevocations().IsRevoked(ctx, "g-1", "", now.Add(-time.Second))
	if err != nil {
		t.Fatalf("IsRevoked before RevokedAt: %v", err)
	}
	if !revoked {
		t.Fatal("IsRevoked: token issued before RevokedAt must be revoked")
	}
}

// TestGrantRevocation_IatBoundary nails down the
// "revoked iff !iat.After(RevokedAt)" rule the verifier relies on.
// iat == RevokedAt is the tombstone-after-mint race the rule defends
// against.
func TestGrantRevocation_IatBoundary(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	now := time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)
	if err := s.GrantRevocations().RevokeGrant(ctx, store.GrantTombstone{
		GrantID:   "g-edge",
		RevokedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	cases := []struct {
		name string
		iat  time.Time
		want bool
	}{
		{"before", now.Add(-time.Nanosecond), true},
		{"equal", now, true},
		{"after_1ns", now.Add(time.Nanosecond), false},
		{"after_1s", now.Add(time.Second), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := s.GrantRevocations().IsRevoked(ctx, "g-edge", "", tc.iat)
			if err != nil {
				t.Fatalf("IsRevoked: %v", err)
			}
			if got != tc.want {
				t.Fatalf("IsRevoked(iat=%s) = %v, want %v", tc.iat, got, tc.want)
			}
		})
	}
}

// TestGrantRevocation_Idempotent verifies the contract: a second
// RevokeGrant against the same GrantID extends BOTH RevokedAt and
// ExpiresAt to max(existing, supplied). Advancing RevokedAt covers ATs
// minted under a Grant the OP reused across repeat /authorize flows
// after an earlier cascade.
func TestGrantRevocation_Idempotent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	now := time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)
	if err := s.GrantRevocations().RevokeGrant(ctx, store.GrantTombstone{
		GrantID:   "g-idem",
		RevokedAt: now,
		ExpiresAt: now.Add(30 * time.Minute),
	}); err != nil {
		t.Fatalf("first RevokeGrant: %v", err)
	}
	// Second call: later RevokedAt, longer ExpiresAt.
	if err := s.GrantRevocations().RevokeGrant(ctx, store.GrantTombstone{
		GrantID:   "g-idem",
		RevokedAt: now.Add(10 * time.Minute),
		ExpiresAt: now.Add(2 * time.Hour),
	}); err != nil {
		t.Fatalf("second RevokeGrant: %v", err)
	}
	// A token issued at the original RevokedAt MUST still be revoked
	// (advancing RevokedAt strictly widens the iat window).
	revoked, err := s.GrantRevocations().IsRevoked(ctx, "g-idem", "", now)
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if !revoked {
		t.Fatal("original RevokedAt no longer covers iat=original_RevokedAt")
	}
	// A token issued at the new RevokedAt MUST also be revoked: the
	// second RevokeGrant must have advanced RevokedAt to now+10m.
	revoked, err = s.GrantRevocations().IsRevoked(ctx, "g-idem", "", now.Add(10*time.Minute))
	if err != nil {
		t.Fatalf("IsRevoked at advanced RevokedAt: %v", err)
	}
	if !revoked {
		t.Fatal("RevokedAt did not advance: an AT issued after the prior cascade is still accepted")
	}
	// ExpiresAt MUST be the max: a GC cutoff between the original and
	// extended ExpiresAt MUST leave the row intact.
	n, err := s.GrantRevocations().GC(ctx, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if n != 0 {
		t.Fatalf("GC dropped a row whose ExpiresAt was extended: count=%d", n)
	}
}

// TestGrantRevocation_DenylistPrecedence pins the precedence rule: a
// JTI denylist hit returns true even when the matching grant has no
// tombstone.
func TestGrantRevocation_DenylistPrecedence(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	now := time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)
	if err := s.GrantRevocations().RevokeJTI(ctx, store.RevokedJTI{
		JTI:       "jti-1",
		GrantID:   "g-1",
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("RevokeJTI: %v", err)
	}
	revoked, err := s.GrantRevocations().IsRevoked(ctx, "g-1", "jti-1", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if !revoked {
		t.Fatal("denylist hit must report revoked even when grant is not tombstoned")
	}
	// A different JTI under the same grant MUST NOT be revoked.
	revoked, err = s.GrantRevocations().IsRevoked(ctx, "g-1", "jti-other", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("IsRevoked unrelated jti: %v", err)
	}
	if revoked {
		t.Fatal("denylist must not be a wildcard")
	}
}

// TestGrantRevocation_GC drops rows whose ExpiresAt is strictly before
// the supplied cutoff. Records without an ExpiresAt (zero time) opt
// out of GC so the store never silently drops a row that was registered
// without a TTL -- mirroring the access-token substore behaviour.
func TestGrantRevocation_GC(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	now := time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)
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
	// Live tombstone survives.
	if revoked, _ := gr.IsRevoked(ctx, "g-live", "", now.Add(-time.Second)); !revoked {
		t.Error("live tombstone collected by GC")
	}
	// Zero-expiry tombstone survives.
	if revoked, _ := gr.IsRevoked(ctx, "g-no-exp", "", now); !revoked {
		t.Error("zero-expiry tombstone collected by GC")
	}
	// Expired tombstone is gone.
	if revoked, _ := gr.IsRevoked(ctx, "g-expired", "", now.Add(-3*time.Hour)); revoked {
		t.Error("expired tombstone survived GC")
	}
	// Live denylist row survives.
	if revoked, _ := gr.IsRevoked(ctx, "g-y", "jti-live", now); !revoked {
		t.Error("live denylist row collected by GC")
	}
	// Expired denylist row is gone.
	if revoked, _ := gr.IsRevoked(ctx, "g-x", "jti-expired", now); revoked {
		t.Error("expired denylist row survived GC")
	}
}

// TestGrantRevocation_EmptyInputs locks in the boundary semantics: an
// empty GrantID skips the tombstone check, an empty JTI skips the
// denylist check, and RevokeGrant / RevokeJTI with empty keys are
// no-ops rather than seeding wildcard rows.
func TestGrantRevocation_EmptyInputs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	now := time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)
	gr := s.GrantRevocations()
	// Empty GrantID: no-op.
	if err := gr.RevokeGrant(ctx, store.GrantTombstone{RevokedAt: now}); err != nil {
		t.Fatalf("RevokeGrant empty: %v", err)
	}
	// Empty JTI: no-op.
	if err := gr.RevokeJTI(ctx, store.RevokedJTI{}); err != nil {
		t.Fatalf("RevokeJTI empty: %v", err)
	}
	// IsRevoked with empty inputs MUST report not-revoked.
	revoked, err := gr.IsRevoked(ctx, "", "", now)
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if revoked {
		t.Fatal("IsRevoked with empty inputs must not match")
	}
}

// TestGrantRevocation_DefensiveCopy verifies that mutating a tombstone
// after it is handed to RevokeGrant does NOT mutate the stored row;
// the inmem implementation must clone the value into its map.
func TestGrantRevocation_DefensiveCopy(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	now := time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)
	t1 := store.GrantTombstone{
		GrantID:   "g-clone",
		RevokedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}
	if err := s.GrantRevocations().RevokeGrant(ctx, t1); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	// Mutate the local copy after Save; the stored row must be
	// unaffected.
	t1.RevokedAt = now.Add(time.Hour)
	revoked, err := s.GrantRevocations().IsRevoked(ctx, "g-clone", "", now)
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if !revoked {
		t.Fatal("stored RevokedAt mutated by caller-side change to the input value")
	}
}
