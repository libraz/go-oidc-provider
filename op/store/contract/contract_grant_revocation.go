package contract

import (
	"context"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// --- GrantRevocationStore ---------------------------------------------------
//
// The contract subgroup pins the substore semantics that requires
// across every backend that ships op/storeadapter:
//
//   - tombstone insert is idempotent: a second RevokeGrant against the same
//     GrantID extends both RevokedAt and ExpiresAt to max(existing,
//     supplied). Advancing RevokedAt covers ATs minted under a Grant the
//     OP reused across repeat /authorize flows after an earlier cascade;
//     the verifier's "iat <= RevokedAt" rule then catches them on the
//     next cascade;
//   - the verifier rule itself: iat == RevokedAt is rejected (clock-tick
//     race) and iat == RevokedAt + 1ns is accepted;
//   - JTI denylist precedence: an access token whose jti has been
//     /revocation-ed is revoked even when its grant has no tombstone;
//   - GC: rows whose ExpiresAt is strictly before the cutoff are dropped.
//
// Backends that participate in the atomic-routing cluster (every backend
// the library ships under the grant-tombstone strategy) MUST satisfy
// every case here.

//nolint:gochecknoglobals // sub-test table; declared once so [Run] can iterate.
var grantRevocationCases = []subtest{
	{"RevokeGrantSaveAndIsRevoked", grantRevSaveLookup},
	{"RevokeGrantIdempotent", grantRevIdempotent},
	{"IsRevokedIatBoundary", grantRevIatBoundary},
	{"IsRevokedAfterTombstone", grantRevAfterTombstone},
	{"RevokeJTIDenylistPrecedence", grantRevJTIPrecedence},
	{"RevokeJTIIdempotent", grantRevJTIIdempotent},
	{"IsRevokedAbsent", grantRevAbsent},
	{"GC", grantRevGC},
}

// requireGrantRevocations fetches the substore handle and skips the
// current test when the backend opts out by returning nil. Backends
// that do not enable the grant-tombstone strategy are allowed to return
// nil from [store.Store.GrantRevocations]; the contract still exercises
// every backend that does ship the substore.
func requireGrantRevocations(t *testing.T, s store.Store) store.GrantRevocationStore {
	t.Helper()
	gr := s.GrantRevocations()
	if gr == nil {
		t.Skipf("backend %T returns nil from GrantRevocations()", s)
	}
	return gr
}

func grantRevSaveLookup(t *testing.T, f Factory) {
	b := f(t)
	gr := requireGrantRevocations(t, b.Store)
	ctx := context.Background()
	now := b.Now()
	tomb := store.GrantTombstone{
		GrantID:   "grant-1",
		RevokedAt: now,
		ExpiresAt: now.Add(time.Hour),
		Reason:    "code_replay",
	}
	if err := gr.RevokeGrant(ctx, tomb); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	// iat strictly before RevokedAt MUST be revoked.
	revoked, err := gr.IsRevoked(ctx, "grant-1", "", now.Add(-time.Second))
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if !revoked {
		t.Fatal("IsRevoked: token issued before RevokedAt must be revoked")
	}
}

func grantRevIdempotent(t *testing.T, f Factory) {
	b := f(t)
	gr := requireGrantRevocations(t, b.Store)
	ctx := context.Background()
	now := b.Now()
	first := store.GrantTombstone{
		GrantID:   "grant-idem",
		RevokedAt: now,
		ExpiresAt: now.Add(time.Hour),
		Reason:    "logout",
	}
	if err := gr.RevokeGrant(ctx, first); err != nil {
		t.Fatalf("first RevokeGrant: %v", err)
	}
	// Second RevokeGrant: shorter ExpiresAt MUST NOT shrink the row,
	// and RevokedAt MUST advance to max(existing, supplied) so a
	// follow-up cascade against a (subject, client) Grant the OP has
	// reused across repeat /authorize flows covers any AT minted under
	// the grant after the previous cascade.
	second := store.GrantTombstone{
		GrantID:   "grant-idem",
		RevokedAt: now.Add(10 * time.Second),
		ExpiresAt: now.Add(30 * time.Minute),
		Reason:    "operator",
	}
	if err := gr.RevokeGrant(ctx, second); err != nil {
		t.Fatalf("second RevokeGrant: %v", err)
	}
	// A token issued at the original RevokedAt MUST still be considered
	// revoked: a later RevokedAt strictly widens the iat window, never
	// shrinks it.
	revoked, err := gr.IsRevoked(ctx, "grant-idem", "", now)
	if err != nil {
		t.Fatalf("IsRevoked at original RevokedAt: %v", err)
	}
	if !revoked {
		t.Fatal("original RevokedAt no longer covers iat=original_RevokedAt")
	}
	// A token issued at the new RevokedAt MUST also be revoked: this is
	// the new behaviour the second RevokeGrant introduced.
	revoked, err = gr.IsRevoked(ctx, "grant-idem", "", now.Add(10*time.Second))
	if err != nil {
		t.Fatalf("IsRevoked at advanced RevokedAt: %v", err)
	}
	if !revoked {
		t.Fatal("RevokedAt did not advance: an AT issued after the prior cascade is still accepted")
	}
	// Third RevokeGrant: longer ExpiresAt MUST extend the row, and
	// RevokedAt MUST advance further.
	third := store.GrantTombstone{
		GrantID:   "grant-idem",
		RevokedAt: now.Add(20 * time.Second),
		ExpiresAt: now.Add(2 * time.Hour),
		Reason:    "operator",
	}
	if err := gr.RevokeGrant(ctx, third); err != nil {
		t.Fatalf("third RevokeGrant: %v", err)
	}
	revoked, err = gr.IsRevoked(ctx, "grant-idem", "", now.Add(20*time.Second))
	if err != nil {
		t.Fatalf("IsRevoked at third RevokedAt: %v", err)
	}
	if !revoked {
		t.Fatal("RevokedAt did not advance to third value")
	}
	// A GC cutoff between the first and third ExpiresAt values MUST
	// leave the row intact, proving ExpiresAt was extended to the max.
	n, err := gr.GC(ctx, now.Add(90*time.Minute))
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if n != 0 {
		t.Fatalf("GC dropped a row whose ExpiresAt was extended to %s: count=%d", third.ExpiresAt, n)
	}
}

func grantRevIatBoundary(t *testing.T, f Factory) {
	b := f(t)
	gr := requireGrantRevocations(t, b.Store)
	ctx := context.Background()
	now := b.Now()
	if err := gr.RevokeGrant(ctx, store.GrantTombstone{
		GrantID:   "grant-edge",
		RevokedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	// iat == RevokedAt MUST be revoked (clock-tick collision).
	revoked, err := gr.IsRevoked(ctx, "grant-edge", "", now)
	if err != nil {
		t.Fatalf("IsRevoked at RevokedAt: %v", err)
	}
	if !revoked {
		t.Fatal("iat == RevokedAt must be revoked (defends against tombstone-after-mint race)")
	}
	// iat == RevokedAt + 1ns MUST NOT be revoked.
	revoked, err = gr.IsRevoked(ctx, "grant-edge", "", now.Add(time.Nanosecond))
	if err != nil {
		t.Fatalf("IsRevoked just after RevokedAt: %v", err)
	}
	if revoked {
		t.Fatal("iat strictly after RevokedAt must NOT be revoked")
	}
}

func grantRevAfterTombstone(t *testing.T, f Factory) {
	b := f(t)
	gr := requireGrantRevocations(t, b.Store)
	ctx := context.Background()
	now := b.Now()
	if err := gr.RevokeGrant(ctx, store.GrantTombstone{
		GrantID:   "grant-after",
		RevokedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	// A token issued well after the tombstone is not revoked.
	revoked, err := gr.IsRevoked(ctx, "grant-after", "", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if revoked {
		t.Fatal("token issued after RevokedAt must not be revoked")
	}
}

func grantRevJTIPrecedence(t *testing.T, f Factory) {
	b := f(t)
	gr := requireGrantRevocations(t, b.Store)
	ctx := context.Background()
	now := b.Now()
	// A JTI denylist row with no matching grant tombstone MUST still
	// cause IsRevoked to report true.
	if err := gr.RevokeJTI(ctx, store.RevokedJTI{
		JTI:       "jti-1",
		GrantID:   "grant-x",
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("RevokeJTI: %v", err)
	}
	revoked, err := gr.IsRevoked(ctx, "grant-x", "jti-1", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if !revoked {
		t.Fatal("JTI denylist precedence: revoked jti must report revoked even when grant has no tombstone")
	}
	// A different JTI under the same (un-tombstoned) grant must NOT be
	// revoked.
	revoked, err = gr.IsRevoked(ctx, "grant-x", "jti-other", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("IsRevoked unrelated jti: %v", err)
	}
	if revoked {
		t.Fatal("denylist must not be a wildcard: unrelated jti reported revoked")
	}
}

func grantRevJTIIdempotent(t *testing.T, f Factory) {
	b := f(t)
	gr := requireGrantRevocations(t, b.Store)
	ctx := context.Background()
	now := b.Now()
	row := store.RevokedJTI{
		JTI:       "jti-idem",
		GrantID:   "grant-y",
		ExpiresAt: now.Add(time.Hour),
	}
	if err := gr.RevokeJTI(ctx, row); err != nil {
		t.Fatalf("first RevokeJTI: %v", err)
	}
	if err := gr.RevokeJTI(ctx, row); err != nil {
		t.Fatalf("second RevokeJTI: %v", err)
	}
	revoked, err := gr.IsRevoked(ctx, "grant-y", "jti-idem", now)
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if !revoked {
		t.Fatal("RevokeJTI idempotent: second call should leave the denylist row intact")
	}
}

func grantRevAbsent(t *testing.T, f Factory) {
	b := f(t)
	gr := requireGrantRevocations(t, b.Store)
	ctx := context.Background()
	revoked, err := gr.IsRevoked(ctx, "grant-absent", "jti-absent", b.Now())
	if err != nil {
		t.Fatalf("IsRevoked absent: %v", err)
	}
	if revoked {
		t.Fatal("IsRevoked(absent) must return (false, nil)")
	}
	// Empty (grantID, jti) must also be (false, nil): both axes are
	// vacuously absent rather than wildcards.
	revoked, err = gr.IsRevoked(ctx, "", "", b.Now())
	if err != nil {
		t.Fatalf("IsRevoked empty: %v", err)
	}
	if revoked {
		t.Fatal("IsRevoked with empty inputs must not match anything")
	}
}

func grantRevGC(t *testing.T, f Factory) {
	b := f(t)
	gr := requireGrantRevocations(t, b.Store)
	ctx := context.Background()
	now := b.Now()
	seedGrantTombstones(t, gr, ctx,
		store.GrantTombstone{GrantID: "grant-live", RevokedAt: now, ExpiresAt: now.Add(time.Hour)},
		store.GrantTombstone{GrantID: "grant-expired", RevokedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)},
	)
	seedRevokedJTIs(t, gr, ctx,
		store.RevokedJTI{JTI: "jti-expired", GrantID: "grant-x", ExpiresAt: now.Add(-time.Hour)},
		store.RevokedJTI{JTI: "jti-live", GrantID: "grant-y", ExpiresAt: now.Add(time.Hour)},
	)
	n, err := gr.GC(ctx, now)
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if n < 2 {
		t.Fatalf("GC count = %d, want >= 2 (one expired tombstone + one expired denylist row)", n)
	}
	expectRevoked(t, gr, ctx, "grant-live", "", now.Add(-time.Second), true, "GC dropped a still-live tombstone")
	expectRevoked(t, gr, ctx, "grant-y", "jti-live", now, true, "GC dropped a still-live denylist row")
	// Expired rows are gone — the only signal they left is that
	// IsRevoked no longer reports the grant or jti revoked.
	expectRevoked(t, gr, ctx, "grant-expired", "", now.Add(-3*time.Hour), false, "expired tombstone survived GC")
	expectRevoked(t, gr, ctx, "grant-x", "jti-expired", now.Add(-3*time.Hour), false, "expired denylist row survived GC")
}

func seedGrantTombstones(t *testing.T, gr store.GrantRevocationStore, ctx context.Context, rows ...store.GrantTombstone) {
	t.Helper()
	for _, tomb := range rows {
		if err := gr.RevokeGrant(ctx, tomb); err != nil {
			t.Fatalf("RevokeGrant %s: %v", tomb.GrantID, err)
		}
	}
}

func seedRevokedJTIs(t *testing.T, gr store.GrantRevocationStore, ctx context.Context, rows ...store.RevokedJTI) {
	t.Helper()
	for _, row := range rows {
		if err := gr.RevokeJTI(ctx, row); err != nil {
			t.Fatalf("RevokeJTI %s: %v", row.JTI, err)
		}
	}
}

func expectRevoked(t *testing.T, gr store.GrantRevocationStore, ctx context.Context, grantID, jti string, when time.Time, want bool, failMsg string) {
	t.Helper()
	got, err := gr.IsRevoked(ctx, grantID, jti, when)
	if err != nil {
		t.Fatalf("IsRevoked(grant=%q jti=%q): %v", grantID, jti, err)
	}
	if got != want {
		t.Fatal(failMsg)
	}
}
