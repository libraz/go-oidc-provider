//go:build testcontainers

package oidcdynamo_test

import (
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
	oidcdynamo "github.com/libraz/go-oidc-provider/op/storeadapter/dynamodb"
)

// movableClock is the mutable counterpart to fixedClock. The shared contract
// factory pins one instant for the whole suite, so a case that has to land on
// a record's own expiry instant needs its own clock.
type movableClock struct{ now time.Time }

func (c *movableClock) Now() time.Time { return c.now }

// TestConsumedJTIs_ExpiryBoundIsInclusive pins the boundary
// [store.ConsumedJTIStore] declares: a replay marker is expired from its
// expiresAt onwards, and Mark and Has apply that bound identically. The case
// lives here rather than in the contract harness because the shared DynamoDB
// factory has no mutable clock, and without one there is no way to observe the
// backend exactly at the boundary instant.
//
// The two directions matter for different reasons. Has still reporting a
// marker Mark would overwrite lets a caller read a jti as consumed and then
// consume it again; Mark refusing a jti Has reports as free rejects a
// legitimate proof as a replay.
func TestConsumedJTIs_ExpiryBoundIsInclusive(t *testing.T) {
	t.Parallel()

	client := newEmulatorClient(t)
	clock := &movableClock{now: contract.Reference}
	s, err := oidcdynamo.New(client,
		oidcdynamo.WithTablePrefix("jtibound_"),
		oidcdynamo.WithClock(clock),
	)
	if err != nil {
		t.Fatalf("oidcdynamo.New: %v", err)
	}
	if err := s.CreateTables(t.Context()); err != nil {
		t.Fatalf("CreateTables: %v", err)
	}
	disableEmulatorTTL(t, client, s)

	ctx := t.Context()
	jtis := s.ConsumedJTIs()
	const ttl = time.Hour
	expiresAt := clock.now.Add(ttl)
	if err := jtis.Mark(ctx, "jti-boundary", expiresAt); err != nil {
		t.Fatalf("Mark: %v", err)
	}

	// One nanosecond before expiry the marker is still live.
	clock.now = expiresAt.Add(-time.Nanosecond)
	live, err := jtis.Has(ctx, "jti-boundary")
	if err != nil {
		t.Fatalf("Has just before expiry: %v", err)
	}
	if !live {
		t.Fatal("Has reported a marker absent before its expiresAt")
	}
	if err := jtis.Mark(ctx, "jti-boundary", expiresAt); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("Mark just before expiry: want ErrAlreadyConsumed, got %v", err)
	}

	// At the expiry instant itself the marker is gone for both methods.
	clock.now = expiresAt
	stale, err := jtis.Has(ctx, "jti-boundary")
	if err != nil {
		t.Fatalf("Has at the expiry instant: %v", err)
	}
	if stale {
		t.Fatal("Has reported a marker live at its own expiresAt; the bound is inclusive")
	}
	if err := jtis.Mark(ctx, "jti-boundary", clock.now.Add(ttl)); err != nil {
		t.Fatalf("Mark at the expiry instant: want the stale marker replaced, got %v", err)
	}
}
