package lockout_test

import (
	"context"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/auditevent"
	"github.com/libraz/go-oidc-provider/internal/authn/lockout"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestRecordFailure_EmitsEngagedOnce pins when the counter reports a lock:
// once for the attempt that newly engages it, never for attempts made
// while it runs, and again for a lock engaged after the previous one lapsed.
func TestRecordFailure_EmitsEngagedOnce(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	start := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)

	fail := func(t *testing.T, c *lockout.Counter, n int) {
		t.Helper()
		for range n {
			if _, err := c.RecordFailure(ctx, "alice"); err != nil {
				t.Fatalf("RecordFailure: %v", err)
			}
		}
	}
	assertEngaged := func(t *testing.T, em *recordingEmitter, want int) {
		t.Helper()
		events := em.snapshot()
		if len(events) != want {
			t.Fatalf("emitted %d events, want %d: %+v", len(events), want, events)
		}
		for _, ev := range events {
			if ev.Name != string(auditevent.AuditLockoutEngaged) {
				t.Errorf("event name = %q, want %q", ev.Name, auditevent.AuditLockoutEngaged)
			}
			if ev.Level != audit.LevelWarn {
				t.Errorf("event level = %v, want LevelWarn", ev.Level)
			}
			if ev.ActorID != "alice" {
				t.Errorf("event ActorID = %q, want the locked subject", ev.ActorID)
			}
		}
	}

	t.Run("short lock then relock after lapse", func(t *testing.T) {
		t.Parallel()

		clock := &fakeClock{t: start}
		em := &recordingEmitter{}
		c, err := lockout.New(inmem.New().AuthnLockouts(), clock)
		if err != nil {
			t.Fatalf("lockout.New: %v", err)
		}
		c = c.WithEmitter(em)

		fail(t, c, 29)
		assertEngaged(t, em, 0)
		fail(t, c, 1)
		assertEngaged(t, em, 1)

		// Failures while the lock runs do not repeat the event.
		fail(t, c, 5)
		assertEngaged(t, em, 1)

		// The lock lapses inside the counting window; the next failure
		// is over the threshold and engages a fresh lock.
		clock.advance(time.Hour + time.Second)
		fail(t, c, 1)
		assertEngaged(t, em, 2)
		fail(t, c, 1)
		assertEngaged(t, em, 2)
	})

	t.Run("long lock engaged from an unlocked record", func(t *testing.T) {
		t.Parallel()

		clock := &fakeClock{t: start}
		em := &recordingEmitter{}
		st := inmem.New().AuthnLockouts()
		c, err := lockout.New(st, clock)
		if err != nil {
			t.Fatalf("lockout.New: %v", err)
		}
		c = c.WithEmitter(em)

		// Seed an unlocked record one failure short of the long threshold.
		seeded, err := st.CompareAndSwap(ctx, 0, &store.AuthnLockoutRecord{
			Subject:        "alice",
			FailedCount:    89,
			FirstFailureAt: start,
		})
		if err != nil || !seeded {
			t.Fatalf("seed CompareAndSwap = (%t, %v)", seeded, err)
		}

		out, err := c.RecordFailure(ctx, "alice")
		if err != nil {
			t.Fatalf("RecordFailure: %v", err)
		}
		if !out.ResetRequired || !out.LockedUntil.Equal(start.Add(24*time.Hour)) {
			t.Fatalf("Outcome = %+v, want the 24h lock with ResetRequired", out)
		}
		assertEngaged(t, em, 1)

		fail(t, c, 3)
		assertEngaged(t, em, 1)
	})
}
