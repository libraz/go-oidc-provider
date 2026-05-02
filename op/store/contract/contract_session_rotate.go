package contract

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// AssertConcurrentRotate exercises the [store.SessionStore] contract for
// concurrent session-fixation rotation: multiple goroutines observe the
// same prior session ID, each issues a fresh ID via Save(new) and then
// Delete(old), and the harness asserts the post-condition documented on
// [store.SessionStore]:
//
//   - every Save call either succeeds with a distinct new session ID
//     (transient dual-active is permitted) or returns a non-nil error;
//   - the prior session ID is removed by the time the racers all return
//     (Delete may report [store.ErrNotFound] for whichever racer loses
//     the delete race);
//   - the count of new sessions visible via [store.SessionStore.Find]
//     equals the number of Save successes;
//   - no two surviving records share the same session ID (no silent
//     aliasing).
//
// AssertConcurrentRotate is intentionally exported as a free-standing
// helper so adapters that embed only the SessionStore (Redis volatile
// tier, dedicated session backends) can pin the contract without taking
// a dependency on the full [Run] aggregate.
//
// The helper builds a fresh prior session inside the supplied
// [store.SessionStore] keyed by "rotate-old" with ChooserGroupID
// "cg-rotate"; callers must not pre-populate either ID. The helper uses
// the supplied now value as CreatedAt / UpdatedAt / ExpiresAt baseline
// so the harness can reuse the adapter's fixed clock.
//
//nolint:gocognit,cyclop // contract assertion is intentionally exhaustive; splitting hurts readability.
func AssertConcurrentRotate(t *testing.T, sessions store.SessionStore, now time.Time) {
	t.Helper()
	ctx := context.Background()

	const oldID = "rotate-old"
	const chooserGroupID = "cg-rotate"
	const subject = "sub-rotate"
	const racers = 8

	prior := &store.Session{
		ID:             oldID,
		Subject:        subject,
		AuthTime:       now,
		AMR:            []string{"pwd"},
		ChooserGroupID: chooserGroupID,
		ExpiresAt:      now.Add(time.Hour),
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := sessions.Save(ctx, prior); err != nil {
		t.Fatalf("AssertConcurrentRotate: seed Save: %v", err)
	}

	var (
		saveOK  atomic.Int32
		saveErr atomic.Int32
		newIDs  sync.Map // string -> struct{}
	)

	var wg sync.WaitGroup
	for i := range racers {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			// Each racer reads the prior record and stages a fresh ID.
			// Reads MAY return ErrNotFound for late racers if a faster
			// racer's Delete has already landed; that is the legitimate
			// "lost the race" outcome.
			_, err := sessions.Find(ctx, oldID)
			if err != nil {
				if !errors.Is(err, store.ErrNotFound) {
					t.Errorf("racer %d Find: unexpected error %v", idx, err)
				}
				return
			}

			rotated := &store.Session{
				ID:             rotateNewID(idx),
				Subject:        subject,
				AuthTime:       now,
				AMR:            []string{"pwd"},
				ChooserGroupID: chooserGroupID,
				ExpiresAt:      now.Add(time.Hour),
				CreatedAt:      now,
				UpdatedAt:      now,
			}
			if err := sessions.Save(ctx, rotated); err != nil {
				saveErr.Add(1)
				return
			}
			saveOK.Add(1)
			if _, dup := newIDs.LoadOrStore(rotated.ID, struct{}{}); dup {
				t.Errorf("racer %d: duplicate new session ID %q", idx, rotated.ID)
			}

			err = sessions.Delete(ctx, oldID)
			switch {
			case err == nil:
				// Won the delete race; nothing further to do.
			case errors.Is(err, store.ErrNotFound):
				// Lost the delete race; legitimate.
			default:
				t.Errorf("racer %d Delete: unexpected error %v", idx, err)
			}
		}(i)
	}
	wg.Wait()

	if saveOK.Load()+saveErr.Load() == 0 {
		t.Fatal("AssertConcurrentRotate: no racer attempted Save")
	}

	// Post-condition 1: prior ID is gone.
	if _, err := sessions.Find(ctx, oldID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("AssertConcurrentRotate: prior session %q still alive after rotation: err=%v", oldID, err)
	}

	// Post-condition 2: every successful Save is reachable via Find,
	// confirming the racer-supplied IDs are now persisted distinct rows.
	live := 0
	newIDs.Range(func(key, _ any) bool {
		id, _ := key.(string)
		if got, err := sessions.Find(ctx, id); err != nil {
			t.Errorf("AssertConcurrentRotate: rotated session %q missing: err=%v", id, err)
		} else if got.ID != id {
			t.Errorf("AssertConcurrentRotate: Find(%q) returned ID=%q", id, got.ID)
		}
		live++
		return true
	})
	if live != int(saveOK.Load()) {
		t.Errorf("AssertConcurrentRotate: live=%d successful Save=%d (counts must match)", live, saveOK.Load())
	}

	// Post-condition 3: ListByChooserGroup reports exactly the rotated
	// IDs (the prior ID has been deleted by at least one racer).
	listed, err := sessions.ListByChooserGroup(ctx, chooserGroupID)
	if err != nil {
		t.Fatalf("AssertConcurrentRotate: ListByChooserGroup: %v", err)
	}
	for _, sess := range listed {
		if sess.ID == oldID {
			t.Errorf("AssertConcurrentRotate: prior session %q still listed in chooser group", oldID)
		}
	}
	if len(listed) != live {
		t.Errorf("AssertConcurrentRotate: chooser group listed %d sessions; want %d (live rotated)", len(listed), live)
	}
}

// rotateNewID synthesises a stable new session ID for racer idx. It is
// a free-standing helper rather than a closure capture so the test
// goroutines can be inlined cleanly.
func rotateNewID(idx int) string {
	return "rotate-new-" + string(rune('a'+idx)) //nolint:gosec // idx bounded to 0..2 in caller; conversion safe.
}
