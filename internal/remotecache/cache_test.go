//nolint:testpackage // white-box coverage verifies exact LRU and stale-entry state transitions.
package remotecache

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type movableClock struct {
	now time.Time
}

func (c *movableClock) Now() time.Time {
	return c.now
}

func TestCache_HighCardinalityStaysBoundedAcrossPositiveAndNegativeEntries(t *testing.T) {
	t.Parallel()

	clock := &movableClock{now: time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)}
	cache := New[string](Config{
		Clock:       clock,
		TTL:         time.Hour,
		NegativeTTL: time.Minute,
		MaxEntries:  8,
	})
	errUpstream := errors.New("upstream failed")
	for i := range 200 {
		key := fmt.Sprintf("https://rp-%03d.example/resource", i)
		_, _ = cache.Load(context.Background(), key, func(context.Context, string, bool) (string, error) {
			if i%2 == 0 {
				return key, nil
			}
			return "", errUpstream
		})
		if got := cache.Len(); got > 8 {
			t.Fatalf("entry count=%d exceeds max=8 after key %d", got, i)
		}
	}
	if got := cache.Len(); got != 8 {
		t.Fatalf("entry count=%d want 8 after high-cardinality load", got)
	}
}

func TestCache_LRUEvictsLeastRecentlyUsedEntry(t *testing.T) {
	t.Parallel()

	cache := New[string](Config{TTL: time.Hour, MaxEntries: 2})
	var loads atomic.Int32
	load := func(value string) Loader[string] {
		return func(context.Context, string, bool) (string, error) {
			loads.Add(1)
			return value, nil
		}
	}
	if _, err := cache.Load(context.Background(), "a", load("a")); err != nil {
		t.Fatalf("load a: %v", err)
	}
	if _, err := cache.Load(context.Background(), "b", load("b")); err != nil {
		t.Fatalf("load b: %v", err)
	}
	if _, err := cache.Load(context.Background(), "a", load("unexpected")); err != nil {
		t.Fatalf("touch a: %v", err)
	}
	if _, err := cache.Load(context.Background(), "c", load("c")); err != nil {
		t.Fatalf("load c: %v", err)
	}
	if _, err := cache.Load(context.Background(), "b", load("b-reloaded")); err != nil {
		t.Fatalf("reload b: %v", err)
	}
	if got := loads.Load(); got != 4 {
		t.Fatalf("loader calls=%d want 4; b should be the LRU eviction", got)
	}
}

func TestCache_ExpiredEntryIsPhysicallyRemoved(t *testing.T) {
	t.Parallel()

	clock := &movableClock{now: time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)}
	cache := New[string](Config{Clock: clock, TTL: time.Minute, MaxEntries: 4})
	cache.Put("expired", "value")
	clock.now = clock.now.Add(2 * time.Minute)

	if _, ok, _ := cache.Get("expired"); ok {
		t.Fatal("Get returned an expired entry")
	}
	if got := cache.Len(); got != 0 {
		t.Fatalf("entry count=%d want 0 after expiry eviction", got)
	}
}

func TestCache_SingleflightCollapsesConcurrentLoad(t *testing.T) {
	t.Parallel()

	cache := New[string](Config{TTL: time.Hour})
	var calls atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	loader := func(context.Context, string, bool) (string, error) {
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-release
		return "value", nil
	}

	const concurrent = 32
	start := make(chan struct{})
	results := make(chan error, concurrent)
	var wg sync.WaitGroup
	for range concurrent {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			value, err := cache.Load(context.Background(), "same", loader)
			if err == nil && value != "value" {
				err = fmt.Errorf("value=%q want value", value)
			}
			results <- err
		}()
	}
	close(start)
	<-entered
	close(release)
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("loader calls=%d want 1", got)
	}
}

func TestCache_NegativeCacheRecoversAfterTTL(t *testing.T) {
	t.Parallel()

	clock := &movableClock{now: time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)}
	cache := New[string](Config{
		Clock:       clock,
		TTL:         time.Hour,
		NegativeTTL: 5 * time.Second,
	})
	errUpstream := errors.New("upstream failed")
	var (
		calls atomic.Int32
		fail  atomic.Bool
	)
	fail.Store(true)
	loader := func(context.Context, string, bool) (string, error) {
		calls.Add(1)
		if fail.Load() {
			return "", errUpstream
		}
		return "recovered", nil
	}

	if _, err := cache.Load(context.Background(), "key", loader); !errors.Is(err, errUpstream) {
		t.Fatalf("first Load err=%v want upstream failure", err)
	}
	if _, err := cache.Load(context.Background(), "key", loader); !errors.Is(err, errUpstream) {
		t.Fatalf("negative-cache Load err=%v want upstream failure", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("loader calls=%d want 1 inside negative TTL", got)
	}

	clock.now = clock.now.Add(6 * time.Second)
	fail.Store(false)
	value, err := cache.Load(context.Background(), "key", loader)
	if err != nil {
		t.Fatalf("recovery Load: %v", err)
	}
	if value != "recovered" {
		t.Fatalf("recovery value=%q want recovered", value)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("loader calls=%d want 2 after negative TTL", got)
	}
}

func TestCache_StaleValueSurvivesNegativeWindowForChangeDetection(t *testing.T) {
	t.Parallel()

	clock := &movableClock{now: time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)}
	cache := New[string](Config{
		Clock:       clock,
		TTL:         time.Minute,
		NegativeTTL: 5 * time.Second,
	})
	cache.Put("key", "original")
	clock.now = clock.now.Add(2 * time.Minute)
	errUpstream := errors.New("upstream failed")

	if _, err := cache.Load(context.Background(), "key", func(_ context.Context, stale string, hasStale bool) (string, error) {
		if !hasStale || stale != "original" {
			t.Fatalf("first retry stale=%q hasStale=%v want original,true", stale, hasStale)
		}
		return "", errUpstream
	}); !errors.Is(err, errUpstream) {
		t.Fatalf("first retry err=%v want upstream failure", err)
	}

	clock.now = clock.now.Add(6 * time.Second)
	value, err := cache.Load(context.Background(), "key", func(_ context.Context, stale string, hasStale bool) (string, error) {
		if !hasStale || stale != "original" {
			t.Fatalf("recovery stale=%q hasStale=%v want original,true", stale, hasStale)
		}
		return "rotated", nil
	})
	if err != nil || value != "rotated" {
		t.Fatalf("recovery value=%q err=%v want rotated,nil", value, err)
	}
}

func TestCache_RefreshBypassesAFreshEntry(t *testing.T) {
	t.Parallel()

	cache := New[string](Config{TTL: time.Hour})
	cache.Put("key", "original")

	value, err := cache.RefreshTTL(context.Background(), "key", func(_ context.Context, stale string, hasStale bool) (string, time.Duration, error) {
		if !hasStale || stale != "original" {
			t.Fatalf("refresh stale=%q hasStale=%v want original,true", stale, hasStale)
		}
		return "rotated", 0, nil
	})
	if err != nil || value != "rotated" {
		t.Fatalf("refresh value=%q err=%v want rotated,nil", value, err)
	}
	if cached, ok, _ := cache.Get("key"); !ok || cached != "rotated" {
		t.Fatalf("cached value=%q ok=%v want rotated,true", cached, ok)
	}
}

// TestCache_FailedRefreshKeepsTheStoredValue pins that a refresh cannot be used
// to discard a value the cache is still serving correctly. The trigger for a
// refresh is an identifier any peer can supply, so a peer timing its probes
// against a brief upstream outage would otherwise take the key down for the
// whole negative window.
func TestCache_FailedRefreshKeepsTheStoredValue(t *testing.T) {
	t.Parallel()

	cache := New[string](Config{TTL: time.Hour, NegativeTTL: time.Hour})
	cache.Put("key", "original")
	errUpstream := errors.New("upstream failed")

	if _, err := cache.RefreshTTL(context.Background(), "key", func(context.Context, string, bool) (string, time.Duration, error) {
		return "", 0, errUpstream
	}); !errors.Is(err, errUpstream) {
		t.Fatalf("refresh err=%v want upstream failure", err)
	}
	value, ok, cachedErr := cache.Get("key")
	if !ok || cachedErr != nil || value != "original" {
		t.Fatalf("after a failed refresh value=%q ok=%v err=%v want original,true,nil", value, ok, cachedErr)
	}
}

// TestCache_FailedRefreshOfAnUnknownKeyIsNegativeCached is the control: with no
// value to protect, a refresh failure takes the same negative entry a plain
// load would have produced, so the amplification guard still applies.
func TestCache_FailedRefreshOfAnUnknownKeyIsNegativeCached(t *testing.T) {
	t.Parallel()

	cache := New[string](Config{TTL: time.Hour, NegativeTTL: time.Hour})
	errUpstream := errors.New("upstream failed")
	var calls atomic.Int32
	loader := func(context.Context, string, bool) (string, time.Duration, error) {
		calls.Add(1)
		return "", 0, errUpstream
	}

	if _, err := cache.RefreshTTL(context.Background(), "key", loader); !errors.Is(err, errUpstream) {
		t.Fatalf("refresh err=%v want upstream failure", err)
	}
	if _, err := cache.Load(context.Background(), "key", func(context.Context, string, bool) (string, error) {
		t.Fatal("the negative entry should have short-circuited the load")
		return "", nil
	}); !errors.Is(err, errUpstream) {
		t.Fatalf("load err=%v want the cached upstream failure", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("loader calls=%d want 1", got)
	}
}

// TestCache_AbandonedCallerDoesNotStallOrPoison pins that a caller whose
// context is cancelled mid-load returns promptly with its own context error,
// while the loader it shares with everyone else runs to completion and its
// result lands in the cache.
func TestCache_AbandonedCallerDoesNotStallOrPoison(t *testing.T) {
	t.Parallel()

	cache := New[string](Config{TTL: time.Hour, NegativeTTL: time.Hour})
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	loader := func(context.Context, string, bool) (string, error) {
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-release
		return "value", nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	abandoned := make(chan error, 1)
	go func() {
		_, err := cache.Load(ctx, "key", loader)
		abandoned <- err
	}()

	<-entered
	cancel()
	if err := <-abandoned; !errors.Is(err, context.Canceled) {
		t.Fatalf("abandoned Load err=%v want context.Canceled", err)
	}
	close(release)

	value, err := cache.Load(context.Background(), "key", loader)
	if err != nil || value != "value" {
		t.Fatalf("Load after an abandoned one value=%q err=%v want value,nil", value, err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("loader calls=%d want 1; the abandoned load should have served the retry", got)
	}
}

func TestCache_ContextFailureIsNotNegativeCached(t *testing.T) {
	t.Parallel()

	cache := New[string](Config{NegativeTTL: time.Hour})
	var calls atomic.Int32
	loader := func(context.Context, string, bool) (string, error) {
		if calls.Add(1) == 1 {
			return "", context.Canceled
		}
		return "retry", nil
	}
	if _, err := cache.Load(context.Background(), "key", loader); !errors.Is(err, context.Canceled) {
		t.Fatalf("first Load err=%v want context.Canceled", err)
	}
	value, err := cache.Load(context.Background(), "key", loader)
	if err != nil || value != "retry" {
		t.Fatalf("retry value=%q err=%v want retry,nil", value, err)
	}
}
