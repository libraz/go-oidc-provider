package inmem

import (
	"errors"
	"math"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
)

func TestSaturatingIncrement(t *testing.T) {
	t.Parallel()

	c := uint8(math.MaxUint8 - 2)
	for _, want := range []uint8{math.MaxUint8 - 1, math.MaxUint8, math.MaxUint8, math.MaxUint8} {
		if got := saturatingIncrement(&c); got != want || c != want {
			t.Fatalf("saturatingIncrement = %d (stored %d), want %d", got, c, want)
		}
	}
}

func TestIncrementCounter_ReportsMissingRecord(t *testing.T) {
	t.Parallel()

	rec := &store.DeviceCode{UserCodeStrikes: math.MaxUint8}
	got, err := incrementCounter(
		func(mutate func(*store.DeviceCode) error) error { return mutate(rec) },
		func(r *store.DeviceCode) *uint8 { return &r.UserCodeStrikes },
	)
	if err != nil || got != math.MaxUint8 || rec.UserCodeStrikes != math.MaxUint8 {
		t.Fatalf("saturated bump = %d, %v (stored %d)", got, err, rec.UserCodeStrikes)
	}

	got, err = incrementCounter(
		func(func(*store.DeviceCode) error) error { return store.ErrNotFound },
		func(r *store.DeviceCode) *uint8 { return &r.UserCodeStrikes },
	)
	if !errors.Is(err, store.ErrNotFound) || got != 0 {
		t.Fatalf("missing record = %d, %v; want 0, ErrNotFound", got, err)
	}
}
