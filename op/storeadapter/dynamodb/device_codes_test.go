//go:build testcontainers

package oidcdynamo_test

import (
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
)

// TestDeviceCode_StrikesSurviveConcurrentTransitions guards the
// brute-force counter against the hazard specific to a
// document-per-item layout: a state transition rewrites the record, and
// a rewrite that carried the counter along would roll back every strike
// that landed while it was in flight.
//
// The traffic modelled here is exactly what the counter defends
// against — a device polling on its own schedule while a user_code is
// guessed in parallel — so the polls and the strikes are issued
// together. The contract harness pins that concurrent strikes are all
// counted; this pins that a concurrent transition does not undo them.
func TestDeviceCode_StrikesSurviveConcurrentTransitions(t *testing.T) {
	t.Parallel()

	s := newIsolatedStore(t, "dcstrike_")
	ctx := t.Context()
	codes := s.DeviceCodes()

	const (
		deviceCode = "dc-strike-race"
		racers     = 8
	)
	if err := codes.Save(ctx, &store.DeviceCode{
		ID:        deviceCode,
		ClientID:  "client-race",
		UserCode:  "BBBB-0001",
		Scope:     []string{"openid"},
		Interval:  5 * time.Second,
		Status:    store.DeviceCodeStatusPending,
		IssuedAt:  contract.Reference,
		ExpiresAt: contract.Reference.Add(time.Hour),
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	errs := make([]error, 2*racers)
	var wg sync.WaitGroup
	wg.Add(2 * racers)
	for i := range racers {
		go func() {
			defer wg.Done()
			_, errs[i] = codes.IncrementUserCodeStrike(ctx, deviceCode)
		}()
		go func() {
			defer wg.Done()
			errs[racers+i] = codes.RecordPoll(ctx, deviceCode, contract.Reference, 5*time.Second)
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent operation %d: %v", i, err)
		}
	}

	got, err := codes.FindByDeviceCode(ctx, deviceCode)
	if err != nil {
		t.Fatalf("FindByDeviceCode: %v", err)
	}
	if got.UserCodeStrikes != racers {
		t.Errorf("UserCodeStrikes = %d after %d strikes raced against %d polls, want %d",
			got.UserCodeStrikes, racers, racers, racers)
	}
}
