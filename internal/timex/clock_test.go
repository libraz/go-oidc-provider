package timex_test

import (
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/timex"
)

func TestSystemClock_Monotonic(t *testing.T) {
	t.Parallel()

	a := timex.SystemClock.Now()
	b := timex.SystemClock.Now()
	if b.Before(a) {
		t.Fatalf("SystemClock went backwards: %v -> %v", a, b)
	}
}

func TestClockFunc_DriversFakeTime(t *testing.T) {
	t.Parallel()

	want := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	var clock timex.Clock = timex.ClockFunc(func() time.Time { return want })

	if got := clock.Now(); !got.Equal(want) {
		t.Fatalf("ClockFunc.Now() = %v, want %v", got, want)
	}
}

func TestSystemClock_ConcurrentSafe(t *testing.T) {
	t.Parallel()

	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = timex.SystemClock.Now()
		}()
	}
	wg.Wait()
}
