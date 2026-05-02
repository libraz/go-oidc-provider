package contract

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// AssertExpiredSessionReturnsNotFound exercises the [store.SessionStore]
// expiry contract: a session whose ExpiresAt is strictly before the
// adapter clock MUST be reported as absent on every read path. The
// helper writes a session with a past-dated ExpiresAt (now - 1h) and
// asserts that:
//
//   - [store.SessionStore.Find] returns [store.ErrNotFound];
//   - [store.SessionStore.Touch] returns [store.ErrNotFound] (Touch
//     MUST NOT resurrect an expired session);
//   - [store.SessionStore.ListByChooserGroup] does not surface the
//     session for its chooser group.
//
// The helper is intentionally exported so adapters that embed only
// the SessionStore (the Redis volatile tier in particular) can pin
// the contract without taking a dependency on the full [Run]
// aggregate. Backends whose Save silently drops past-dated records
// MUST still pass: the post-condition is "Find reports absent", and
// dropping a write satisfies that post-condition.
//
// AssertExpiredSessionReturnsNotFound uses the supplied now value as
// the adapter's reference clock; pass the same value the backend's
// fixed clock returns so the strict-less-than expiry comparison
// lands consistently. The helper writes a single session keyed by
// "expired-session" with ChooserGroupID "cg-expired"; callers must
// not pre-populate either ID.
func AssertExpiredSessionReturnsNotFound(t *testing.T, sessions store.SessionStore, now time.Time) {
	t.Helper()
	ctx := context.Background()

	const id = "expired-session"
	const chooserGroupID = "cg-expired"
	expired := &store.Session{
		ID:             id,
		Subject:        "sub-expired",
		AuthTime:       now.Add(-2 * time.Hour),
		AMR:            []string{"pwd"},
		ChooserGroupID: chooserGroupID,
		ExpiresAt:      now.Add(-time.Hour),
		CreatedAt:      now.Add(-2 * time.Hour),
		UpdatedAt:      now.Add(-2 * time.Hour),
	}
	// Some adapters (Redis) drop past-dated writes silently; the
	// contract permits this because the post-condition Find / Touch
	// observers are both ErrNotFound either way. Save is best-effort
	// here for the same reason.
	_ = sessions.Save(ctx, expired)

	if _, err := sessions.Find(ctx, id); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("AssertExpiredSessionReturnsNotFound: Find on expired session: want ErrNotFound, got %v", err)
	}
	err := sessions.Touch(ctx, id, now.Add(time.Hour), now)
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("AssertExpiredSessionReturnsNotFound: Touch on expired session: want ErrNotFound, got %v", err)
	}

	listed, err := sessions.ListByChooserGroup(ctx, chooserGroupID)
	if err != nil {
		t.Fatalf("AssertExpiredSessionReturnsNotFound: ListByChooserGroup: %v", err)
	}
	for _, sess := range listed {
		if sess.ID == id {
			t.Errorf("AssertExpiredSessionReturnsNotFound: expired session %q surfaced via ListByChooserGroup", id)
		}
	}
}

// AssertSessionNotFoundOnMissing exercises the contract's "absent ID
// returns ErrNotFound" floor on every read path of [store.SessionStore].
// The helper assumes the supplied SessionStore has not been
// pre-populated with the synthetic ID "absent-session" or the chooser
// group "cg-absent"; the helper does not write either. The asserted
// post-conditions are:
//
//   - [store.SessionStore.Find] returns [store.ErrNotFound];
//   - [store.SessionStore.Touch] returns [store.ErrNotFound];
//   - [store.SessionStore.Delete] returns [store.ErrNotFound];
//   - [store.SessionStore.ListByChooserGroup] returns a non-error
//     empty slice.
//
// The supplied now value drives the synthetic Touch timestamps so
// the helper does not depend on the wall clock; pass the same value
// the backend's fixed clock returns so the call lands consistently
// with the rest of the contract suite.
//
// The helper is exported for the same reason the rotation helper is:
// adapters that host only the SessionStore can pin the contract
// without taking a dependency on the full [Run] aggregate.
func AssertSessionNotFoundOnMissing(t *testing.T, sessions store.SessionStore, now time.Time) {
	t.Helper()
	ctx := context.Background()

	const id = "absent-session"
	const chooserGroupID = "cg-absent"

	if _, err := sessions.Find(ctx, id); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("AssertSessionNotFoundOnMissing: Find: want ErrNotFound, got %v", err)
	}
	err := sessions.Touch(ctx, id, now.Add(time.Hour), now)
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("AssertSessionNotFoundOnMissing: Touch: want ErrNotFound, got %v", err)
	}
	if err := sessions.Delete(ctx, id); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("AssertSessionNotFoundOnMissing: Delete: want ErrNotFound, got %v", err)
	}
	listed, err := sessions.ListByChooserGroup(ctx, chooserGroupID)
	if err != nil {
		t.Fatalf("AssertSessionNotFoundOnMissing: ListByChooserGroup: %v", err)
	}
	if len(listed) != 0 {
		t.Errorf("AssertSessionNotFoundOnMissing: ListByChooserGroup returned %d sessions; want 0", len(listed))
	}
}

// AssertSessionBatchListMatches pins the [store.SessionStore.ListByChooserGroup]
// post-condition that every persisted session in the chooser group is
// surfaced exactly once. The helper writes count synthetic sessions
// under the same chooser-group identifier and asserts that:
//
//   - the returned slice has length count;
//   - every persisted ID appears exactly once (no duplicates);
//   - every Find against a returned ID succeeds (no aliasing or
//     orphaned secondary-index entries).
//
// Backends that implement the chooser-group lookup via a secondary
// index (Redis SETs, SQL secondary tables) commonly need to dedup the
// raw membership read because writes can land twice during a Save
// upsert. This helper exercises that path against count records,
// which is large enough to surface bookkeeping errors without
// stretching the harness's wall-clock budget.
//
// The helper uses the chooser-group ID "cg-batch-list" and synthesises
// session IDs of the form "batch-session-N" for N in [0, count);
// callers must not pre-populate either. The supplied now value
// drives every record's CreatedAt / UpdatedAt / ExpiresAt baseline so
// the harness can reuse the adapter's fixed clock.
//
//nolint:gocognit // contract assertion is intentionally exhaustive; splitting hurts readability.
func AssertSessionBatchListMatches(t *testing.T, sessions store.SessionStore, count int, now time.Time) {
	t.Helper()
	ctx := context.Background()

	const chooserGroupID = "cg-batch-list"
	if count <= 0 {
		t.Fatalf("AssertSessionBatchListMatches: count=%d must be positive", count)
	}

	for i := range count {
		id := batchSessionID(i)
		sess := &store.Session{
			ID:             id,
			Subject:        "sub-batch",
			AuthTime:       now,
			AMR:            []string{"pwd"},
			ChooserGroupID: chooserGroupID,
			ExpiresAt:      now.Add(time.Hour),
			CreatedAt:      now,
			UpdatedAt:      now,
		}
		if err := sessions.Save(ctx, sess); err != nil {
			t.Fatalf("AssertSessionBatchListMatches: Save %q: %v", id, err)
		}
	}

	listed, err := sessions.ListByChooserGroup(ctx, chooserGroupID)
	if err != nil {
		t.Fatalf("AssertSessionBatchListMatches: ListByChooserGroup: %v", err)
	}
	if len(listed) != count {
		t.Errorf("AssertSessionBatchListMatches: ListByChooserGroup returned %d sessions; want %d", len(listed), count)
	}

	seen := make(map[string]int, len(listed))
	for _, sess := range listed {
		seen[sess.ID]++
		if seen[sess.ID] > 1 {
			t.Errorf("AssertSessionBatchListMatches: duplicate session ID %q in batch result", sess.ID)
		}
	}
	for i := range count {
		id := batchSessionID(i)
		if seen[id] == 0 {
			t.Errorf("AssertSessionBatchListMatches: session %q missing from batch result", id)
			continue
		}
		got, err := sessions.Find(ctx, id)
		if err != nil {
			t.Errorf("AssertSessionBatchListMatches: Find %q after batch list: %v", id, err)
			continue
		}
		if got.ID != id {
			t.Errorf("AssertSessionBatchListMatches: Find(%q) returned ID=%q", id, got.ID)
		}
	}
}

// batchSessionID synthesises a stable session ID for the i'th record
// in [AssertSessionBatchListMatches]. It is a free-standing helper so
// callers can reproduce the IDs externally if a failure prompts a
// targeted reproduction step.
func batchSessionID(i int) string {
	return "batch-session-" + strconv.Itoa(i)
}
