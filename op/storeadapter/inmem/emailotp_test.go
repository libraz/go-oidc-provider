package inmem_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func newEmailOTPRecord(subject string) *store.EmailOTPRecord {
	return &store.EmailOTPRecord{
		Subject:   subject,
		CodeSalt:  []byte{0x01, 0x02, 0x03},
		CodeHash:  []byte{0xaa, 0xbb, 0xcc},
		SentAt:    time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
}

// emailOTPTestClock is a settable clock so retention tests can advance
// time deterministically past a code's ExpiresAt.
type emailOTPTestClock struct{ now time.Time }

func (c *emailOTPTestClock) Now() time.Time { return c.now }

// TestEmailOTPStore_RetainUntilOutlivesCodeExpiry pins the #16 fix: once
// the code's ExpiresAt has passed, Get MUST still return the record (with
// its rate-limit / brute-force counters) while RetainUntil is in the
// future, so those counters do not silently reset. Consume, which redeems
// the code, MUST still reject the expired code.
func TestEmailOTPStore_RetainUntilOutlivesCodeExpiry(t *testing.T) {
	t.Parallel()

	clk := &emailOTPTestClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	s := inmem.New(inmem.WithClock(clk))
	es := s.EmailOTPs()
	ctx := context.Background()

	rec := &store.EmailOTPRecord{
		Subject:     "user-retain",
		CodeSalt:    []byte{0x01},
		CodeHash:    []byte{0xaa},
		SentAt:      clk.now,
		ExpiresAt:   clk.now.Add(5 * time.Minute), // code validity
		RetainUntil: clk.now.Add(24 * time.Hour),  // record retention
		FailedCount: 3,
		SendCount:   4,
	}
	if err := es.Put(ctx, rec); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Advance past the code's ExpiresAt but well within RetainUntil.
	clk.now = clk.now.Add(10 * time.Minute)

	got, err := es.Get(ctx, rec.Subject)
	if err != nil {
		t.Fatalf("Get after code expiry: want record, got %v", err)
	}
	if got.FailedCount != 3 || got.SendCount != 4 {
		t.Fatalf("counters reset: FailedCount=%d SendCount=%d want 3/4", got.FailedCount, got.SendCount)
	}

	// The expired code itself must not be redeemable.
	if err := es.Consume(ctx, got); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Consume expired code: want ErrNotFound, got %v", err)
	}

	// Past RetainUntil the record finally disappears.
	clk.now = clk.now.Add(24 * time.Hour)
	if _, err := es.Get(ctx, rec.Subject); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get past RetainUntil: want ErrNotFound, got %v", err)
	}
}

func TestEmailOTPStore_ConsumeRaceSingleWinner(t *testing.T) {
	t.Parallel()

	s := inmem.New()
	es := s.EmailOTPs()
	ctx := context.Background()
	rec := newEmailOTPRecord("user-alice")
	if err := es.Put(ctx, rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	consumed := *rec
	consumed.ConsumedAt = time.Now().UTC()

	var wins atomic.Int64
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := es.Consume(ctx, &consumed)
			switch {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, store.ErrAlreadyConsumed):
			default:
				t.Errorf("Consume: %v", err)
			}
		}()
	}
	wg.Wait()
	if got := wins.Load(); got != 1 {
		t.Fatalf("Consume wins=%d want 1", got)
	}
	got, err := es.Get(ctx, rec.Subject)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ConsumedAt.IsZero() {
		t.Fatal("ConsumedAt was not persisted")
	}
}
