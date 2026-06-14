package inmem_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestAuthnLockoutStore_StampLockSetsOnlyLockedUntil pins the
// [store.AuthnLockoutStamper] contract on the reference store: StampLock
// writes LockedUntil without disturbing FailedCount or FirstFailureAt.
func TestAuthnLockoutStore_StampLockSetsOnlyLockedUntil(t *testing.T) {
	t.Parallel()

	s := inmem.New().AuthnLockouts()
	stamper, ok := s.(store.AuthnLockoutStamper)
	if !ok {
		t.Fatal("inmem AuthnLockouts does not implement store.AuthnLockoutStamper")
	}
	ctx := context.Background()
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	if _, err := s.Increment(ctx, "alice", now); err != nil {
		t.Fatalf("Increment: %v", err)
	}
	if _, err := s.Increment(ctx, "alice", now); err != nil {
		t.Fatalf("Increment: %v", err)
	}

	lockedUntil := now.Add(time.Hour)
	if err := stamper.StampLock(ctx, "alice", lockedUntil); err != nil {
		t.Fatalf("StampLock: %v", err)
	}
	got, err := s.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.LockedUntil.Equal(lockedUntil) {
		t.Errorf("LockedUntil=%v want %v", got.LockedUntil, lockedUntil)
	}
	if got.FailedCount != 2 {
		t.Errorf("StampLock disturbed FailedCount=%d want 2", got.FailedCount)
	}
	if !got.FirstFailureAt.Equal(now) {
		t.Errorf("StampLock disturbed FirstFailureAt=%v want %v", got.FirstFailureAt, now)
	}
}

// TestAuthnLockoutStore_StampLockMissingSubject pins that StampLock reports
// [store.ErrNotFound] for a subject with no record rather than creating a
// lock-only row.
func TestAuthnLockoutStore_StampLockMissingSubject(t *testing.T) {
	t.Parallel()

	s := inmem.New().AuthnLockouts()
	stamper := s.(store.AuthnLockoutStamper)
	err := stamper.StampLock(context.Background(), "nobody", time.Now().UTC())
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("StampLock(missing) err=%v want ErrNotFound", err)
	}
}

// TestAuthnLockoutStore_StampLockDoesNotLoseConcurrentIncrement pins the
// M-AUTHN-4 fix at the store level: a StampLock running concurrently with an
// Increment for the same subject must not overwrite the increment. The race
// is what the read-modify-write Put path lost; the targeted StampLock cannot.
func TestAuthnLockoutStore_StampLockDoesNotLoseConcurrentIncrement(t *testing.T) {
	t.Parallel()

	s := inmem.New().AuthnLockouts()
	stamper := s.(store.AuthnLockoutStamper)
	ctx := context.Background()
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	if _, err := s.Increment(ctx, "alice", now); err != nil {
		t.Fatalf("seed Increment: %v", err)
	}

	const extra = 32
	var wg sync.WaitGroup
	wg.Add(extra + 1)
	go func() {
		defer wg.Done()
		if err := stamper.StampLock(ctx, "alice", now.Add(time.Hour)); err != nil {
			t.Errorf("StampLock: %v", err)
		}
	}()
	for range extra {
		go func() {
			defer wg.Done()
			if _, err := s.Increment(ctx, "alice", now); err != nil {
				t.Errorf("Increment: %v", err)
			}
		}()
	}
	wg.Wait()

	got, err := s.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.FailedCount != extra+1 {
		t.Fatalf("FailedCount=%d want %d (StampLock overwrote a concurrent Increment)", got.FailedCount, extra+1)
	}
	if got.LockedUntil.IsZero() {
		t.Fatal("LockedUntil not stamped")
	}
}
