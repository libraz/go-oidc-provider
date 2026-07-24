package contract

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// AuthnLockoutFactory builds a fresh standalone [store.AuthnLockoutStore]
// for a single contract sub-test. Authn lockout storage is supplied directly
// through op.WithAuthnLockoutStore rather than the aggregate [store.Store].
type AuthnLockoutFactory func(t *testing.T) store.AuthnLockoutStore

// RunAuthnLockouts exercises the versioned transition guarantees of
// [store.AuthnLockoutStore]. Adapter authors should call it from their
// black-box test suite.
func RunAuthnLockouts(t *testing.T, f AuthnLockoutFactory) {
	t.Helper()

	cases := []struct {
		name string
		run  func(*testing.T, AuthnLockoutFactory)
	}{
		{"Missing", authnLockoutMissing},
		{"CreateAndUpdateVersions", authnLockoutCreateAndUpdate},
		{"StaleTransitionLeavesStateUnchanged", authnLockoutStale},
		{"UpdateMissingDoesNotInsert", authnLockoutUpdateMissing},
		{"DefensiveCopies", authnLockoutDefensiveCopies},
		{"ConcurrentSameVersionHasOneWinner", authnLockoutConcurrentCAS},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.run(t, f)
		})
	}
}

func authnLockoutMissing(t *testing.T, f AuthnLockoutFactory) {
	_, err := f(t).Get(context.Background(), "missing")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get(missing) error = %v, want ErrNotFound", err)
	}
}

func authnLockoutCreateAndUpdate(t *testing.T, f AuthnLockoutFactory) {
	ctx := context.Background()
	s := f(t)
	create := &store.AuthnLockoutRecord{
		Subject:        "alice",
		FailedCount:    1,
		FirstFailureAt: Reference,
		Version:        999, // The backend, not the caller, owns Version.
	}
	swapped, err := s.CompareAndSwap(ctx, 0, create)
	if err != nil || !swapped {
		t.Fatalf("CompareAndSwap create = (%v, %v), want (true, nil)", swapped, err)
	}
	got, err := s.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("Get created: %v", err)
	}
	if got.Version != 1 {
		t.Fatalf("created Version = %d, want 1", got.Version)
	}
	if create.Version != 999 {
		t.Fatalf("CompareAndSwap mutated caller Version = %d, want 999", create.Version)
	}

	update := *got
	update.FailedCount = 2
	update.Version = 888
	swapped, err = s.CompareAndSwap(ctx, got.Version, &update)
	if err != nil || !swapped {
		t.Fatalf("CompareAndSwap update = (%v, %v), want (true, nil)", swapped, err)
	}
	got, err = s.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("Get updated: %v", err)
	}
	if got.Version != 2 || got.FailedCount != 2 {
		t.Fatalf("updated record = %+v, want Version=2 FailedCount=2", got)
	}
}

func authnLockoutStale(t *testing.T, f AuthnLockoutFactory) {
	ctx := context.Background()
	s := f(t)
	seed := lockoutContractRecord()
	swapped, err := s.CompareAndSwap(ctx, 0, seed)
	if err != nil || !swapped {
		t.Fatalf("CompareAndSwap seed = (%v, %v), want (true, nil)", swapped, err)
	}

	fresh := *seed
	fresh.FailedCount = 8
	swapped, err = s.CompareAndSwap(ctx, 1, &fresh)
	if err != nil || !swapped {
		t.Fatalf("CompareAndSwap fresh = (%v, %v), want (true, nil)", swapped, err)
	}

	stale := *seed
	stale.FailedCount = 99
	stale.LockedUntil = Reference.Add(24 * time.Hour)
	swapped, err = s.CompareAndSwap(ctx, 1, &stale)
	if err != nil {
		t.Fatalf("CompareAndSwap stale: %v", err)
	}
	if swapped {
		t.Fatal("CompareAndSwap stale = true, want false")
	}

	got, err := s.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.FailedCount != fresh.FailedCount || !got.LockedUntil.IsZero() || got.Version != 2 {
		t.Fatalf("stale transition changed state: %+v", got)
	}
}

func authnLockoutUpdateMissing(t *testing.T, f AuthnLockoutFactory) {
	ctx := context.Background()
	s := f(t)
	next := lockoutContractRecord()
	swapped, err := s.CompareAndSwap(ctx, 7, next)
	if err != nil {
		t.Fatalf("CompareAndSwap update missing: %v", err)
	}
	if swapped {
		t.Fatal("CompareAndSwap update missing = true, want false")
	}
	_, err = s.Get(ctx, next.Subject)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get after rejected update error = %v, want ErrNotFound", err)
	}
}

func authnLockoutDefensiveCopies(t *testing.T, f AuthnLockoutFactory) {
	ctx := context.Background()
	s := f(t)
	next := lockoutContractRecord()
	swapped, err := s.CompareAndSwap(ctx, 0, next)
	if err != nil || !swapped {
		t.Fatalf("CompareAndSwap = (%v, %v), want (true, nil)", swapped, err)
	}
	next.FailedCount = 99

	first, err := s.Get(ctx, next.Subject)
	if err != nil {
		t.Fatalf("first Get: %v", err)
	}
	if first.FailedCount != 7 {
		t.Fatalf("input mutation leaked: FailedCount = %d, want 7", first.FailedCount)
	}
	first.FailedCount = 100
	second, err := s.Get(ctx, next.Subject)
	if err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if second.FailedCount != 7 {
		t.Fatalf("Get result mutation leaked: FailedCount = %d, want 7", second.FailedCount)
	}
}

func authnLockoutConcurrentCAS(t *testing.T, f AuthnLockoutFactory) {
	ctx := context.Background()
	s := f(t)
	seed := lockoutContractRecord()
	swapped, err := s.CompareAndSwap(ctx, 0, seed)
	if err != nil || !swapped {
		t.Fatalf("CompareAndSwap seed = (%v, %v), want (true, nil)", swapped, err)
	}
	current, err := s.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get seed: %v", err)
	}

	ready := make(chan struct{}, 2)
	release := make(chan struct{})
	results := make(chan bool, 2)
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for count := 8; count <= 9; count++ {
		next := *current
		next.FailedCount = count
		wg.Add(1)
		go func() {
			defer wg.Done()
			ready <- struct{}{}
			<-release
			ok, err := s.CompareAndSwap(ctx, current.Version, &next)
			results <- ok
			errs <- err
		}()
	}
	<-ready
	<-ready
	close(release)
	wg.Wait()

	winners := 0
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatalf("CompareAndSwap concurrent: %v", err)
		}
		if <-results {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("successful concurrent transitions = %d, want 1", winners)
	}
	got, err := s.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get final: %v", err)
	}
	if got.Version != 2 || (got.FailedCount != 8 && got.FailedCount != 9) {
		t.Fatalf("final record = %+v, want Version=2 and one candidate count", got)
	}
}

func lockoutContractRecord() *store.AuthnLockoutRecord {
	return &store.AuthnLockoutRecord{
		Subject:        "alice",
		FailedCount:    7,
		FirstFailureAt: Reference,
	}
}
