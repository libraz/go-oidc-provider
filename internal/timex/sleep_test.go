package timex_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/timex"
)

func TestPadUntilReturnsImmediatelyWhenNoPaddingIsNeeded(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	clock := timex.ClockFunc(func() time.Time { return start.Add(20 * time.Millisecond) })

	if err := timex.PadUntil(context.Background(), clock, start, 0); err != nil {
		t.Fatalf("PadUntil with zero target returned error: %v", err)
	}
	if err := timex.PadUntil(context.Background(), clock, start, -time.Millisecond); err != nil {
		t.Fatalf("PadUntil with negative target returned error: %v", err)
	}
	if err := timex.PadUntil(context.Background(), clock, start, 10*time.Millisecond); err != nil {
		t.Fatalf("PadUntil after target elapsed returned error: %v", err)
	}
}

func TestPadUntilHonorsCancellationWhileWaiting(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	clock := timex.ClockFunc(func() time.Time { return start })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := timex.PadUntil(ctx, clock, start, time.Hour)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("PadUntil error = %v, want context.Canceled", err)
	}
}

func TestPadUntilWaitsUntilTargetFloor(t *testing.T) {
	t.Parallel()

	start := time.Now()
	target := 8 * time.Millisecond

	err := timex.PadUntil(context.Background(), nil, start, target)
	if err != nil {
		t.Fatalf("PadUntil returned error: %v", err)
	}
	if elapsed := time.Since(start); elapsed < target {
		t.Fatalf("PadUntil returned before target floor: elapsed=%v target=%v", elapsed, target)
	}
}
