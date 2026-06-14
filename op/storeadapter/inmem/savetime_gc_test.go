package inmem_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestCIBARequests_SaveTimeGC_ExpiredRowEvictedBeforeDupCheck verifies that
// maybeGCLocked evicts an already-expired CIBA row so that a subsequent Save
// with the same auth_req_id succeeds (returns nil) rather than ErrAlreadyExists.
// A parallel control case confirms that a non-expired row is NOT evicted, so
// the second Save for a live ID still returns ErrAlreadyExists.
func TestCIBARequests_SaveTimeGC_ExpiredRowEvictedBeforeDupCheck(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Use a mutable clock so the test can advance time without racing wall-clock.
	clk := &mutableClock{now: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)}
	s := inmem.New(inmem.WithClock(clk))
	cs := s.CIBARequests()

	// --- expired-row case (GC path) ---
	// Save a record that is already expired relative to the clock.
	expired := makeCIBARequest("gc-ciba-x", store.CIBARequestStatusPending, clk.Now().Add(-time.Minute))
	if err := cs.Save(ctx, expired); err != nil {
		t.Fatalf("Save expired: %v", err)
	}

	// Re-save with the same ID but a fresh ExpiresAt.  GC must remove the
	// expired row before the dup check fires, so this must succeed.
	fresh := makeCIBARequest("gc-ciba-x", store.CIBARequestStatusPending, clk.Now().Add(10*time.Minute))
	if err := cs.Save(ctx, fresh); err != nil {
		t.Fatalf("Save fresh after GC eviction: got %v, want nil (GC must have removed the expired row)", err)
	}

	// The fresh record is findable by its original ID.
	got, err := cs.FindByAuthReqID(ctx, "gc-ciba-x")
	if err != nil {
		t.Fatalf("FindByAuthReqID after re-save: %v", err)
	}
	if got.ID != "gc-ciba-x" {
		t.Errorf("FindByAuthReqID.ID = %q, want gc-ciba-x", got.ID)
	}

	// --- control: non-expired row (no-GC path) ---
	// Save a live record with ID "y".
	live := makeCIBARequest("gc-ciba-y", store.CIBARequestStatusPending, clk.Now().Add(10*time.Minute))
	if err := cs.Save(ctx, live); err != nil {
		t.Fatalf("Save live: %v", err)
	}

	// Re-save "y" while it is still live — must return ErrAlreadyExists.
	if err := cs.Save(ctx, live); !errors.Is(err, store.ErrAlreadyExists) {
		t.Errorf("Save duplicate live record: want ErrAlreadyExists, got %v", err)
	}
}

// TestCIBARequests_SaveTimeGC_OnlyEvictsExpired confirms that GC does not
// touch rows whose ExpiresAt is in the future, even when an expired row is
// present in the same Save call.
func TestCIBARequests_SaveTimeGC_OnlyEvictsExpired(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	clk := &mutableClock{now: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)}
	s := inmem.New(inmem.WithClock(clk))
	cs := s.CIBARequests()

	// Seed one live record and one expired record.
	live := makeCIBARequest("gc-only-live", store.CIBARequestStatusPending, clk.Now().Add(time.Hour))
	if err := cs.Save(ctx, live); err != nil {
		t.Fatalf("Save live: %v", err)
	}
	exp := makeCIBARequest("gc-only-exp", store.CIBARequestStatusPending, clk.Now().Add(-time.Second))
	if err := cs.Save(ctx, exp); err != nil {
		t.Fatalf("Save expired: %v", err)
	}

	// Trigger GC by saving a new record; GC runs before the dup check.
	trigger := makeCIBARequest("gc-only-trigger", store.CIBARequestStatusPending, clk.Now().Add(time.Hour))
	if err := cs.Save(ctx, trigger); err != nil {
		t.Fatalf("Save trigger: %v", err)
	}

	// The live record must still be findable.
	if _, err := cs.FindByAuthReqID(ctx, "gc-only-live"); err != nil {
		t.Errorf("FindByAuthReqID live after GC trigger: %v (GC must not evict unexpired rows)", err)
	}

	// The expired record is gone — Find returns ErrNotFound.
	if _, err := cs.FindByAuthReqID(ctx, "gc-only-exp"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("FindByAuthReqID expired after GC: want ErrNotFound, got %v", err)
	}
}

// TestDeviceCodes_SaveTimeGC_ExpiredRowEvictedBeforeDupCheck mirrors the CIBA
// test for the deviceCodeStore: an expired device_code row is evicted by
// maybeGCLocked so that a fresh Save with the same ID succeeds, and the
// user_code index is rebuilt for the fresh record.
func TestDeviceCodes_SaveTimeGC_ExpiredRowEvictedBeforeDupCheck(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	clk := &mutableClock{now: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)}
	s := inmem.New(inmem.WithClock(clk))
	ds := s.DeviceCodes()

	// --- expired-row case (GC path) ---
	// device_id "gc-dev-x" with user_code "GC-CODE-X", already expired.
	expired := makeDeviceCode("gc-dev-x", "GC-CODE-X", store.DeviceCodeStatusPending, clk.Now().Add(-time.Minute))
	if err := ds.Save(ctx, expired); err != nil {
		t.Fatalf("Save expired: %v", err)
	}

	// Re-save the same device_id with a fresh ExpiresAt.  GC must remove
	// the expired row (and its user_code index entry) before the dup
	// check, so this must succeed.
	fresh := makeDeviceCode("gc-dev-x", "GC-CODE-X", store.DeviceCodeStatusPending, clk.Now().Add(10*time.Minute))
	if err := ds.Save(ctx, fresh); err != nil {
		t.Fatalf("Save fresh after GC eviction: got %v, want nil (GC must have removed the expired row)", err)
	}

	// The fresh record is findable by device_code.
	got, err := ds.FindByDeviceCode(ctx, "gc-dev-x")
	if err != nil {
		t.Fatalf("FindByDeviceCode after re-save: %v", err)
	}
	if got.UserCode != "GC-CODE-X" {
		t.Errorf("FindByDeviceCode.UserCode = %q, want GC-CODE-X", got.UserCode)
	}

	// The fresh record is findable by user_code, confirming the index was
	// rebuilt for the re-saved record.
	byUser, err := ds.FindByUserCode(ctx, "GC-CODE-X")
	if err != nil {
		t.Fatalf("FindByUserCode after re-save: %v (user_code index must be rebuilt on re-save)", err)
	}
	if byUser.UserCode != "GC-CODE-X" {
		t.Errorf("FindByUserCode.UserCode = %q, want GC-CODE-X", byUser.UserCode)
	}

	// --- control: non-expired row (no-GC path) ---
	live := makeDeviceCode("gc-dev-y", "GC-CODE-Y", store.DeviceCodeStatusPending, clk.Now().Add(10*time.Minute))
	if err := ds.Save(ctx, live); err != nil {
		t.Fatalf("Save live: %v", err)
	}
	if err := ds.Save(ctx, live); !errors.Is(err, store.ErrAlreadyExists) {
		t.Errorf("Save duplicate live record: want ErrAlreadyExists, got %v", err)
	}
}

// TestDeviceCodes_SaveTimeGC_OnlyEvictsExpired confirms the device-code
// store's maybeGCLocked leaves unexpired rows intact, mirroring the CIBA
// selective-eviction check.
func TestDeviceCodes_SaveTimeGC_OnlyEvictsExpired(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	clk := &mutableClock{now: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)}
	s := inmem.New(inmem.WithClock(clk))
	ds := s.DeviceCodes()

	// Seed one live and one expired device code.
	live := makeDeviceCode("gc-dc-live", "DC-LIVE-1", store.DeviceCodeStatusPending, clk.Now().Add(time.Hour))
	if err := ds.Save(ctx, live); err != nil {
		t.Fatalf("Save live: %v", err)
	}
	exp := makeDeviceCode("gc-dc-exp", "DC-EXP-1", store.DeviceCodeStatusPending, clk.Now().Add(-time.Second))
	if err := ds.Save(ctx, exp); err != nil {
		t.Fatalf("Save expired: %v", err)
	}

	// Trigger GC via a new Save.
	trigger := makeDeviceCode("gc-dc-trigger", "DC-TRIG-1", store.DeviceCodeStatusPending, clk.Now().Add(time.Hour))
	if err := ds.Save(ctx, trigger); err != nil {
		t.Fatalf("Save trigger: %v", err)
	}

	// Live record must survive.
	if _, err := ds.FindByDeviceCode(ctx, "gc-dc-live"); err != nil {
		t.Errorf("FindByDeviceCode live after GC trigger: %v (must not evict unexpired rows)", err)
	}
	if _, err := ds.FindByUserCode(ctx, "DC-LIVE-1"); err != nil {
		t.Errorf("FindByUserCode live after GC trigger: %v (user_code index must retain live row)", err)
	}

	// Expired record is gone from both indexes.
	if _, err := ds.FindByDeviceCode(ctx, "gc-dc-exp"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("FindByDeviceCode expired after GC: want ErrNotFound, got %v", err)
	}
	if _, err := ds.FindByUserCode(ctx, "DC-EXP-1"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("FindByUserCode expired after GC: want ErrNotFound, got %v", err)
	}
}
