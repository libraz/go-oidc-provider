package lockout_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn/lockout"
	"github.com/libraz/go-oidc-provider/op/store"
)

// contendedStore answers every Get with a fresh versioned record and
// reports every compare-and-swap as lost — the contract's "another
// writer committed first" outcome, which is a normal result rather than
// an error. A row under a credential-stuffing burst looks like this for
// as long as the burst lasts, so the counter must give up instead of
// turning the brute-force gate into a store amplifier.
type contendedStore struct {
	gets   atomic.Int32
	swaps  atomic.Int32
	onSwap func()
}

func (s *contendedStore) Get(_ context.Context, subject string) (*store.AuthnLockoutRecord, error) {
	s.gets.Add(1)
	// A fresh record per call: the counter mutates what it reads.
	return &store.AuthnLockoutRecord{Subject: subject, Version: 1, FailedCount: 1}, nil
}

func (s *contendedStore) CompareAndSwap(_ context.Context, _ uint64, _ *store.AuthnLockoutRecord) (bool, error) {
	s.swaps.Add(1)
	if s.onSwap != nil {
		s.onSwap()
	}
	return false, nil
}

// nilRecordStore breaks the store contract by answering Get with a nil
// record and a nil error. Every read path must fail closed on it rather
// than dereference the nil.
type nilRecordStore struct{}

func (nilRecordStore) Get(_ context.Context, _ string) (*store.AuthnLockoutRecord, error) {
	return nil, nil //nolint:nilnil // deliberate contract violation under test.
}

func (nilRecordStore) CompareAndSwap(_ context.Context, _ uint64, _ *store.AuthnLockoutRecord) (bool, error) {
	return false, nil
}

// foreignRecordStore answers Get with another subject's row. Trusting
// it would let one subject's lock stamp gate a different subject.
type foreignRecordStore struct{}

func (foreignRecordStore) Get(_ context.Context, _ string) (*store.AuthnLockoutRecord, error) {
	return &store.AuthnLockoutRecord{
		Subject:     "mallory",
		Version:     1,
		FailedCount: 30,
		LockedUntil: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
	}, nil
}

func (foreignRecordStore) CompareAndSwap(_ context.Context, _ uint64, _ *store.AuthnLockoutRecord) (bool, error) {
	return false, nil
}

// TestCounter_RecordFailureGivesUpUnderSustainedContention pins the
// bound on the compare-and-swap loop: a store that never lets a swap
// commit must produce a terminating error after a finite number of
// round trips, not an unbounded spin.
func TestCounter_RecordFailureGivesUpUnderSustainedContention(t *testing.T) {
	t.Parallel()

	st := &contendedStore{}
	c, err := lockout.New(st, &fakeClock{t: time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("lockout.New: %v", err)
	}

	out, err := c.RecordFailure(context.Background(), "alice")
	if !errors.Is(err, lockout.ErrSwapContention) {
		t.Fatalf("RecordFailure err = %v, want lockout.ErrSwapContention", err)
	}
	if out != (lockout.Outcome{}) {
		t.Fatalf("Outcome = %+v, want zero value on the abandoned path", out)
	}
	swaps := st.swaps.Load()
	if swaps < 2 {
		t.Fatalf("swap attempts = %d, want more than one before giving up", swaps)
	}
	if swaps > 64 {
		t.Fatalf("swap attempts = %d, want a small bounded number", swaps)
	}
	if gets := st.gets.Load(); gets != swaps {
		t.Fatalf("gets = %d, swaps = %d, want one read per swap attempt", gets, swaps)
	}
}

// TestCounter_RecordFailureStopsOnCancelledContext covers the case a
// bound alone does not: the caller went away mid-burst, so the loop
// must abandon the remaining attempts immediately.
func TestCounter_RecordFailureStopsOnCancelledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	st := &contendedStore{onSwap: cancel}
	c, err := lockout.New(st, &fakeClock{t: time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("lockout.New: %v", err)
	}

	if _, err := c.RecordFailure(ctx, "alice"); !errors.Is(err, context.Canceled) {
		t.Fatalf("RecordFailure err = %v, want context.Canceled", err)
	}
	if swaps := st.swaps.Load(); swaps != 1 {
		t.Fatalf("swap attempts = %d, want the loop to stop at the first cancelled check", swaps)
	}
}

// TestCounter_RecordFailureRejectsPreCancelledContext keeps the store
// untouched when the caller is already gone.
func TestCounter_RecordFailureRejectsPreCancelledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	st := &contendedStore{}
	c, err := lockout.New(st, &fakeClock{t: time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("lockout.New: %v", err)
	}

	if _, err := c.RecordFailure(ctx, "alice"); !errors.Is(err, context.Canceled) {
		t.Fatalf("RecordFailure err = %v, want context.Canceled", err)
	}
	if gets := st.gets.Load(); gets != 0 {
		t.Fatalf("gets = %d, want no store round trip for a cancelled caller", gets)
	}
}

// TestCounter_NilRecordFromStoreFailsClosed asserts every entry point
// survives a store that answers Get with (nil, nil).
func TestCounter_NilRecordFromStoreFailsClosed(t *testing.T) {
	t.Parallel()

	c, err := lockout.New(nilRecordStore{}, &fakeClock{t: time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("lockout.New: %v", err)
	}
	ctx := context.Background()

	if err := c.GuardBegin(ctx, "alice"); err == nil {
		t.Error("GuardBegin err = nil, want a store-contract error")
	}
	locked, until, err := c.IsLocked(ctx, "alice")
	if err == nil {
		t.Error("IsLocked err = nil, want a store-contract error")
	}
	if locked || !until.IsZero() {
		t.Errorf("IsLocked = (%t, %v), want the zero verdict alongside the error", locked, until)
	}
	if _, err := c.RecordFailure(ctx, "alice"); err == nil {
		t.Error("RecordFailure err = nil, want a store-contract error")
	}
	if err := c.Reset(ctx, "alice"); err == nil {
		t.Error("Reset err = nil, want a store-contract error")
	}
}

// TestCounter_ForeignRecordFromStoreFailsClosed asserts the read paths
// refuse a row belonging to another subject instead of applying its
// lock stamp to the requested one.
func TestCounter_ForeignRecordFromStoreFailsClosed(t *testing.T) {
	t.Parallel()

	c, err := lockout.New(foreignRecordStore{}, &fakeClock{t: time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("lockout.New: %v", err)
	}
	ctx := context.Background()

	err = c.GuardBegin(ctx, "alice")
	if err == nil {
		t.Error("GuardBegin err = nil, want a store-contract error")
	}
	if errors.Is(err, lockout.ErrLocked) {
		t.Error("GuardBegin applied another subject's lock stamp")
	}
	locked, _, err := c.IsLocked(ctx, "alice")
	if err == nil {
		t.Error("IsLocked err = nil, want a store-contract error")
	}
	if locked {
		t.Error("IsLocked reported another subject's lock stamp")
	}
}
