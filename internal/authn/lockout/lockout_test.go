package lockout_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn/lockout"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// fakeClock is the deterministic [timex.Clock] tests use to drive the
// rolling-window rollover.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newFixture(t *testing.T) (*lockout.Counter, *fakeClock) {
	t.Helper()
	clock := &fakeClock{t: time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)}
	store := inmem.New().AuthnLockouts()
	c, err := lockout.New(store, clock)
	if err != nil {
		t.Fatalf("lockout.New: %v", err)
	}
	return c, clock
}

func TestCounter_NewRejectsNilStore(t *testing.T) {
	t.Parallel()
	if _, err := lockout.New(nil, timex.SystemClock); err == nil {
		t.Fatal("expected error for nil store")
	}
}

func TestCounter_GuardBeginNoRecord(t *testing.T) {
	t.Parallel()
	c, _ := newFixture(t)
	if err := c.GuardBegin(context.Background(), "alice"); err != nil {
		t.Fatalf("GuardBegin without record: %v", err)
	}
}

func TestCounter_RecordFailureIncrementsAcrossCallers(t *testing.T) {
	t.Parallel()
	c, _ := newFixture(t)
	for i := 1; i <= 5; i++ {
		out, err := c.RecordFailure(context.Background(), "alice")
		if err != nil {
			t.Fatalf("RecordFailure: %v", err)
		}
		if out.FailedCount != i {
			t.Fatalf("attempt %d: FailedCount=%d want %d", i, out.FailedCount, i)
		}
		if !out.LockedUntil.IsZero() {
			t.Fatalf("attempt %d: LockedUntil set prematurely (%v)", i, out.LockedUntil)
		}
	}
}

func TestCounter_ShortLockAtThirty(t *testing.T) {
	t.Parallel()
	c, clock := newFixture(t)
	for i := 1; i <= 30; i++ {
		out, err := c.RecordFailure(context.Background(), "alice")
		if err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
		if i < 30 {
			if !out.LockedUntil.IsZero() {
				t.Fatalf("attempt %d: LockedUntil set prematurely (%v)", i, out.LockedUntil)
			}
			continue
		}
		want := clock.Now().Add(1 * time.Hour)
		if !out.LockedUntil.Equal(want) {
			t.Fatalf("attempt %d: LockedUntil=%v want %v", i, out.LockedUntil, want)
		}
	}

	// GuardBegin reflects the lock.
	err := c.GuardBegin(context.Background(), "alice")
	if !errors.Is(err, lockout.ErrLocked) {
		t.Fatalf("GuardBegin err=%v want ErrLocked", err)
	}
	locked, until, err := c.IsLocked(context.Background(), "alice")
	if err != nil {
		t.Fatalf("IsLocked: %v", err)
	}
	if !locked {
		t.Fatalf("IsLocked = false; want true")
	}
	if until.Before(clock.Now()) {
		t.Fatalf("IsLocked until=%v not in future", until)
	}
}

func TestCounter_LongLockAtNinety(t *testing.T) {
	t.Parallel()
	c, _ := newFixture(t)
	for i := 1; i <= 89; i++ {
		if _, err := c.RecordFailure(context.Background(), "alice"); err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	out, err := c.RecordFailure(context.Background(), "alice")
	if err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}
	if !out.ResetRequired {
		t.Fatalf("ResetRequired=false; want true at FailedCount=%d", out.FailedCount)
	}
	if out.LockedUntil.IsZero() {
		t.Fatalf("LockedUntil zero; want 24h stamp at FailedCount=%d", out.FailedCount)
	}
}

func TestCounter_Reset(t *testing.T) {
	t.Parallel()
	c, _ := newFixture(t)
	for i := 1; i <= 5; i++ {
		if _, err := c.RecordFailure(context.Background(), "alice"); err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if err := c.Reset(context.Background(), "alice"); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	out, err := c.RecordFailure(context.Background(), "alice")
	if err != nil {
		t.Fatalf("RecordFailure after Reset: %v", err)
	}
	if out.FailedCount != 1 {
		t.Fatalf("FailedCount after Reset=%d want 1", out.FailedCount)
	}
}

func TestCounter_WindowRollover(t *testing.T) {
	t.Parallel()
	c, clock := newFixture(t)
	for i := 1; i <= 5; i++ {
		if _, err := c.RecordFailure(context.Background(), "alice"); err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	// Advance past the 24-hour rolling window.
	clock.advance(25 * time.Hour)
	out, err := c.RecordFailure(context.Background(), "alice")
	if err != nil {
		t.Fatalf("RecordFailure after rollover: %v", err)
	}
	if out.FailedCount != 1 {
		t.Fatalf("FailedCount after rollover=%d want 1", out.FailedCount)
	}
}

// TestCounter_AtomicIncrementUnderConcurrency exercises M-AUTHN-4. Two
// or more goroutines each call RecordFailure; the post-increment counts
// MUST be a unique permutation of [1..N], and the final FailedCount on
// any subsequent read MUST equal N. A lost-update race would surface
// either as repeated counts (e.g. two goroutines both reporting count=1)
// or as a final count below N.
func TestCounter_AtomicIncrementUnderConcurrency(t *testing.T) {
	t.Parallel()
	c, _ := newFixture(t)

	const goroutines = 32
	var wg sync.WaitGroup
	wg.Add(goroutines)
	results := make([]int, goroutines)
	for i := range goroutines {
		go func(i int) {
			defer wg.Done()
			out, err := c.RecordFailure(context.Background(), "alice")
			if err != nil {
				t.Errorf("goroutine %d: RecordFailure: %v", i, err)
				return
			}
			results[i] = out.FailedCount
		}(i)
	}
	wg.Wait()

	seen := make(map[int]bool, goroutines)
	for i, r := range results {
		if r < 1 || r > goroutines {
			t.Fatalf("goroutine %d: FailedCount=%d outside [1..%d]", i, r, goroutines)
		}
		if seen[r] {
			t.Fatalf("duplicate FailedCount=%d (lost-update race)", r)
		}
		seen[r] = true
	}

	// Verify the rolling counter row reflects the full set.
	final, err := c.RecordFailure(context.Background(), "alice")
	if err != nil {
		t.Fatalf("RecordFailure (post-loop): %v", err)
	}
	if final.FailedCount != goroutines+1 {
		t.Fatalf("post-loop FailedCount=%d want %d", final.FailedCount, goroutines+1)
	}
}

// TestCounter_CrossFactorAggregation exercises M-AUTHN-1 directly: a
// caller pretending to be email-OTP records 3 failures, then a caller
// pretending to be TOTP records 2 more — the lockout helper must
// observe the cumulative count across factors. The test does NOT mock
// the per-factor authenticators; it exercises the shared counter so a
// future refactor that splits the helper into per-factor counters
// (which would defeat M-1) breaks the test.
func TestCounter_CrossFactorAggregation(t *testing.T) {
	t.Parallel()
	c, _ := newFixture(t)
	// Three failures attributed to email-OTP.
	for i := 1; i <= 3; i++ {
		out, err := c.RecordFailure(context.Background(), "alice")
		if err != nil {
			t.Fatalf("emailotp attempt %d: %v", i, err)
		}
		if out.FailedCount != i {
			t.Fatalf("emailotp attempt %d: FailedCount=%d want %d", i, out.FailedCount, i)
		}
	}
	// Two more attributed to TOTP.
	for i := 1; i <= 2; i++ {
		out, err := c.RecordFailure(context.Background(), "alice")
		if err != nil {
			t.Fatalf("totp attempt %d: %v", i, err)
		}
		want := 3 + i
		if out.FailedCount != want {
			t.Fatalf("totp attempt %d: FailedCount=%d want %d", i, out.FailedCount, want)
		}
	}
}
