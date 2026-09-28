//nolint:testpackage // white-box coverage reads the process-wide slot state.
package remotecache

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// TestCache_NegativeOnlyRemembersFailuresOnly pins the mode request objects
// need: every success is loaded fresh, while a failure is served from the
// negative entry until NegativeTTL passes.
func TestCache_NegativeOnlyRemembersFailuresOnly(t *testing.T) {
	t.Parallel()

	clock := &movableClock{now: time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)}
	cache := New[string](Config{Clock: clock, NegativeTTL: 5 * time.Second, NegativeOnly: true})
	errUpstream := errors.New("upstream failed")
	var (
		calls atomic.Int32
		fail  atomic.Bool
	)
	loader := func(context.Context, string, bool) (string, error) {
		calls.Add(1)
		if fail.Load() {
			return "", errUpstream
		}
		return "fresh", nil
	}
	ctx := context.Background()

	for i := range 2 {
		if v, err := cache.Load(ctx, "ok", loader); err != nil || v != "fresh" {
			t.Fatalf("success load %d = (%q, %v)", i+1, v, err)
		}
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("loader calls=%d want 2: a success must not be cached", got)
	}

	fail.Store(true)
	for i := range 2 {
		if _, err := cache.Load(ctx, "bad", loader); !errors.Is(err, errUpstream) {
			t.Fatalf("failing load %d err=%v want upstream failure", i+1, err)
		}
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("loader calls=%d want 3: a failure inside NegativeTTL must not reload", got)
	}
	clock.now = clock.now.Add(6 * time.Second)
	if _, err := cache.Load(ctx, "bad", loader); !errors.Is(err, errUpstream) {
		t.Fatalf("post-TTL load err=%v want upstream failure", err)
	}
	if got := calls.Load(); got != 4 {
		t.Fatalf("loader calls=%d want 4 after NegativeTTL", got)
	}
}

// TestLoadGate_GroupBoundAndRelease pins the nonblocking contract: a group
// saturates at its limit with ErrOverloaded, and releasing a slot admits the
// next load.
func TestLoadGate_GroupBoundAndRelease(t *testing.T) {
	t.Parallel()

	gate := SharedLoadGate(2)
	ctx := context.Background()
	first, err := gate.Acquire(ctx)
	if err != nil {
		t.Fatalf("first Acquire: %v", err)
	}
	second, err := gate.Acquire(ctx)
	if err != nil {
		t.Fatalf("second Acquire: %v", err)
	}
	if _, err := SharedLoadGate(2).Acquire(ctx); !errors.Is(err, ErrOverloaded) {
		t.Fatalf("third Acquire on the shared limit-2 group err=%v want ErrOverloaded", err)
	}
	first()
	third, err := gate.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire after release: %v", err)
	}
	second()
	third()
}
