package lockout_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn/lockout"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
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

// TestCounter_WindowRollover drives the rolling window past its 24-hour
// edge twice: once from a sub-threshold count, and once from a count
// that crossed the short threshold and left a lock stamp behind. The
// second half is the one that matters — a rollover resets the count to
// 1 and so crosses no threshold, and the transition must not re-adopt
// the stamp of a lock that already ran out. If it does, the subject is
// locked again by the very attempt that should have started a fresh
// budget, and stays locked until they happen to enter a correct code.
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

	// Climb to the short threshold so the record carries a real lock
	// stamp, then let both the lock and the window elapse.
	for i := 2; i <= 30; i++ {
		out, err = c.RecordFailure(context.Background(), "alice")
		if err != nil {
			t.Fatalf("threshold attempt %d: %v", i, err)
		}
	}
	if out.LockedUntil.IsZero() {
		t.Fatalf("LockedUntil zero at FailedCount=%d; want the short-threshold stamp", out.FailedCount)
	}
	locked := out.LockedUntil

	clock.advance(25 * time.Hour)
	now := clock.Now()
	if locked.After(now) {
		t.Fatalf("test setup: lock %v still in force at %v", locked, now)
	}
	out, err = c.RecordFailure(context.Background(), "alice")
	if err != nil {
		t.Fatalf("RecordFailure after lock expiry and rollover: %v", err)
	}
	if out.FailedCount != 1 {
		t.Fatalf("FailedCount after second rollover=%d want 1", out.FailedCount)
	}
	if !out.LockedUntil.IsZero() {
		t.Fatalf("rollover resurrected the expired lock stamp: LockedUntil=%v (expired %v ago), want zero",
			out.LockedUntil, now.Sub(out.LockedUntil))
	}
	if err := c.GuardBegin(context.Background(), "alice"); err != nil {
		t.Fatalf("GuardBegin after lock expiry and rollover: %v; want the subject unlocked", err)
	}
}

// TestCounter_RecordFailureNeverPersistsElapsedLock pins the storage
// side of the same invariant. A stamp that is only dropped on the way
// out of RecordFailure but written back to the row would resurrect on
// the next read, so the assertion is made against what the store holds,
// not only against the returned Outcome. The elapsed stamp is seeded
// directly through the store so the case is reachable however the row
// acquired it — a rollover, an operator edit, or a backend that
// restored an old snapshot.
func TestCounter_RecordFailureNeverPersistsElapsedLock(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	clock := &fakeClock{t: time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)}
	base := inmem.New().AuthnLockouts()
	c, err := lockout.New(base, clock)
	if err != nil {
		t.Fatalf("lockout.New: %v", err)
	}

	now := clock.Now()
	seeded := &store.AuthnLockoutRecord{
		Subject:        "alice",
		FailedCount:    30,
		FirstFailureAt: now.Add(-30 * time.Hour),
		LockedUntil:    now.Add(-29 * time.Hour),
	}
	swapped, err := base.CompareAndSwap(ctx, 0, seeded)
	if err != nil {
		t.Fatalf("seed CompareAndSwap: %v", err)
	}
	if !swapped {
		t.Fatal("seed CompareAndSwap did not commit")
	}

	out, err := c.RecordFailure(ctx, "alice")
	if err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}
	if !out.LockedUntil.IsZero() {
		t.Fatalf("Outcome carries an elapsed lock: LockedUntil=%v, now=%v", out.LockedUntil, now)
	}
	got, err := base.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("Get after RecordFailure: %v", err)
	}
	if !got.LockedUntil.IsZero() {
		t.Fatalf("stored record kept an elapsed lock: LockedUntil=%v, now=%v", got.LockedUntil, now)
	}
}

// TestCounter_RunningLockSurvivesWindowRollover is the counterweight to
// the two tests above: dropping an elapsed stamp must not turn into
// dropping a live one. The long threshold stamps a 24-hour lock, which
// outlives the 24-hour counter window, so the next failure arrives after
// a rollover while the lock is still in force and must neither shorten
// nor clear it.
func TestCounter_RunningLockSurvivesWindowRollover(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	clock := &fakeClock{t: time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)}
	base := inmem.New().AuthnLockouts()
	c, err := lockout.New(base, clock)
	if err != nil {
		t.Fatalf("lockout.New: %v", err)
	}

	// Anchor the window, then cross the long threshold a day later so
	// the 24-hour lock reaches past the window's edge.
	if _, err := c.RecordFailure(ctx, "alice"); err != nil {
		t.Fatalf("anchor RecordFailure: %v", err)
	}
	clock.advance(23 * time.Hour)
	var out lockout.Outcome
	for i := 2; i <= 90; i++ {
		out, err = c.RecordFailure(ctx, "alice")
		if err != nil {
			t.Fatalf("threshold attempt %d: %v", i, err)
		}
	}
	if !out.ResetRequired {
		t.Fatalf("ResetRequired=false at FailedCount=%d; want the long threshold crossed", out.FailedCount)
	}
	held := out.LockedUntil

	// Two more hours: the window (anchored 25 hours ago) has rolled over
	// but the lock still has 22 hours to run.
	clock.advance(2 * time.Hour)
	out, err = c.RecordFailure(ctx, "alice")
	if err != nil {
		t.Fatalf("RecordFailure after rollover: %v", err)
	}
	if out.FailedCount != 1 {
		t.Fatalf("FailedCount after rollover=%d want 1", out.FailedCount)
	}
	if !out.LockedUntil.Equal(held) {
		t.Fatalf("running lock changed across rollover: LockedUntil=%v want %v", out.LockedUntil, held)
	}
	if err := c.GuardBegin(ctx, "alice"); !errors.Is(err, lockout.ErrLocked) {
		t.Fatalf("GuardBegin during a running lock: err=%v want ErrLocked", err)
	}
}

// casBarrierStore makes the first two transitions observe the same
// pre-transition state before either may commit. Later retries pass through
// immediately so Counter can resolve the forced conflict.
type casBarrierStore struct {
	store   store.AuthnLockoutStore
	calls   atomic.Int32
	ready   chan struct{}
	release chan struct{}
}

func newCASBarrierStore(s store.AuthnLockoutStore) *casBarrierStore {
	return &casBarrierStore{
		store:   s,
		ready:   make(chan struct{}, 2),
		release: make(chan struct{}),
	}
}

func (s *casBarrierStore) Get(ctx context.Context, subject string) (*store.AuthnLockoutRecord, error) {
	return s.store.Get(ctx, subject)
}

func (s *casBarrierStore) CompareAndSwap(ctx context.Context, expectedVersion uint64, next *store.AuthnLockoutRecord) (bool, error) {
	if s.calls.Add(1) <= 2 {
		s.ready <- struct{}{}
		<-s.release
	}
	return s.store.CompareAndSwap(ctx, expectedVersion, next)
}

func (s *casBarrierStore) releaseBoth(t *testing.T) {
	t.Helper()
	<-s.ready
	<-s.ready
	close(s.release)
}

func TestCounter_ConcurrentResetAndFailurePreservesFailure(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	clock := &fakeClock{t: time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)}
	base := inmem.New().AuthnLockouts()
	seed, err := lockout.New(base, clock)
	if err != nil {
		t.Fatalf("lockout.New seed: %v", err)
	}
	for i := range 29 {
		if _, err := seed.RecordFailure(ctx, "alice"); err != nil {
			t.Fatalf("seed RecordFailure %d: %v", i+1, err)
		}
	}

	barrier := newCASBarrierStore(base)
	counter, err := lockout.New(barrier, clock)
	if err != nil {
		t.Fatalf("lockout.New barrier: %v", err)
	}
	resetErr := make(chan error, 1)
	failureErr := make(chan error, 1)
	go func() {
		resetErr <- counter.Reset(ctx, "alice")
	}()
	go func() {
		_, err := counter.RecordFailure(ctx, "alice")
		failureErr <- err
	}()

	barrier.releaseBoth(t)
	if err := <-resetErr; err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if err := <-failureErr; err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}

	got, err := base.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("Get final: %v", err)
	}
	if got.FailedCount == 0 {
		t.Fatalf("concurrent success erased failure: %+v", got)
	}
	if got.FailedCount != 1 && got.FailedCount != 30 {
		t.Fatalf("FailedCount = %d, want 1 or 30 according to CAS winner", got.FailedCount)
	}
	if got.FailedCount == 30 && got.LockedUntil.IsZero() {
		t.Fatal("threshold-crossing failure won CAS but its lock stamp was erased")
	}
}

func TestCounter_ConcurrentRolloverFailuresPreserveBoth(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	clock := &fakeClock{t: time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)}
	base := inmem.New().AuthnLockouts()
	seed, err := lockout.New(base, clock)
	if err != nil {
		t.Fatalf("lockout.New seed: %v", err)
	}
	for i := range 5 {
		if _, err := seed.RecordFailure(ctx, "alice"); err != nil {
			t.Fatalf("seed RecordFailure %d: %v", i+1, err)
		}
	}
	clock.advance(25 * time.Hour)
	now := clock.Now()

	barrier := newCASBarrierStore(base)
	counter, err := lockout.New(barrier, clock)
	if err != nil {
		t.Fatalf("lockout.New barrier: %v", err)
	}
	results := make(chan outcomeResult, 2)
	for range 2 {
		go func() {
			out, err := counter.RecordFailure(ctx, "alice")
			results <- outcomeResult{count: out.FailedCount, err: err}
		}()
	}

	barrier.releaseBoth(t)
	seen := map[int]bool{}
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatalf("RecordFailure: %v", result.err)
		}
		seen[result.count] = true
	}
	if !seen[1] || !seen[2] {
		t.Fatalf("post-rollover counts = %v, want both 1 and 2", seen)
	}

	got, err := base.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("Get final: %v", err)
	}
	if got.FailedCount != 2 {
		t.Fatalf("FailedCount = %d, want 2", got.FailedCount)
	}
	if !got.FirstFailureAt.Equal(now) {
		t.Fatalf("FirstFailureAt = %v, want %v", got.FirstFailureAt, now)
	}
}

type outcomeResult struct {
	count int
	err   error
}

// TestCounter_AtomicIncrementUnderConcurrency exercises. Two or more
// goroutines each call RecordFailure; the post-increment counts MUST
// be a unique permutation of [1..N], and the final FailedCount on any
// subsequent read MUST equal N. A lost-update race would surface
// either as repeated counts (e.g. two goroutines both reporting
// count=1) or as a final count below N.
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

// TestCounter_CrossFactorAggregation exercises directly: a caller
// pretending to be email-OTP records 3 failures, then a caller
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
