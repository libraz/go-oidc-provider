package inmem_test

import (
	"bytes"
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

// TestEmailOTPStore_CompareAndSwapCannotUndoConsume pins the failure-write
// race: a stale wrong-code snapshot must never clear ConsumedAt after another
// request successfully redeems the same challenge.
func TestEmailOTPStore_CompareAndSwapCannotUndoConsume(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	s := inmem.New(inmem.WithClock(&emailOTPTestClock{now: now}))
	ctx := context.Background()
	rec := &store.EmailOTPRecord{
		Subject: "alice", CodeSalt: []byte("salt"), CodeHash: []byte("hash"),
		ExpiresAt: now.Add(time.Hour), RetainUntil: now.Add(24 * time.Hour),
	}
	if err := s.EmailOTPs().Put(ctx, rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	stale, err := s.EmailOTPs().Get(ctx, rec.Subject)
	if err != nil {
		t.Fatalf("Get stale: %v", err)
	}
	success := *stale
	success.ConsumedAt = now
	if err := s.EmailOTPs().Consume(ctx, &success); err != nil {
		t.Fatalf("Consume: %v", err)
	}
	failure := *stale
	failure.FailedCount++
	if err := s.EmailOTPs().CompareAndSwap(ctx, stale, &failure); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("CompareAndSwap stale failure err=%v want ErrAlreadyConsumed", err)
	}
	current, err := s.EmailOTPs().Get(ctx, rec.Subject)
	if err != nil {
		t.Fatalf("Get current: %v", err)
	}
	if current.ConsumedAt.IsZero() {
		t.Fatal("stale failure write cleared ConsumedAt")
	}
}

// TestEmailOTPStore_CompareAndSwapCannotUndoResend pins the companion
// interleaving: a wrong-code update based on the old challenge must not put
// its hash or counters back after a resend atomically installed a new one.
func TestEmailOTPStore_CompareAndSwapCannotUndoResend(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	s := inmem.New(inmem.WithClock(&emailOTPTestClock{now: now}))
	old := &store.EmailOTPRecord{
		Subject:     "subject",
		CodeSalt:    []byte("old-salt"),
		CodeHash:    []byte("old-hash"),
		ExpiresAt:   now.Add(time.Minute),
		RetainUntil: now.Add(time.Hour),
	}
	if err := s.EmailOTPs().Put(ctx, old); err != nil {
		t.Fatalf("Put(old): %v", err)
	}

	newChallenge := *old
	newChallenge.CodeSalt = []byte("new-salt")
	newChallenge.CodeHash = []byte("new-hash")
	newChallenge.SendCount = 2
	if err := s.EmailOTPs().CompareAndSwap(ctx, old, &newChallenge); err != nil {
		t.Fatalf("CompareAndSwap(resend): %v", err)
	}

	staleFailure := *old
	staleFailure.FailedCount = 1
	if err := s.EmailOTPs().CompareAndSwap(ctx, old, &staleFailure); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("CompareAndSwap(stale failure) = %v, want ErrAlreadyConsumed", err)
	}
	got, err := s.EmailOTPs().Get(ctx, old.Subject)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got.CodeHash, newChallenge.CodeHash) || got.FailedCount != newChallenge.FailedCount || got.SendCount != newChallenge.SendCount {
		t.Fatalf("stale CAS rolled back replacement: got %+v, want new challenge", got)
	}
}

// TestEmailOTPStore_CompareAndSwapResendSingleWinner pins the atomic send
// reservation used before the mailer side effect. All contenders observe the
// same prior record, but exactly one may install its replacement challenge.
func TestEmailOTPStore_CompareAndSwapResendSingleWinner(t *testing.T) {
	t.Parallel()

	s := inmem.New()
	ctx := context.Background()
	prior := newEmailOTPRecord("alice")
	if err := s.EmailOTPs().Put(ctx, prior); err != nil {
		t.Fatalf("Put: %v", err)
	}
	snapshot, err := s.EmailOTPs().Get(ctx, prior.Subject)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	const contenders = 16
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := range contenders {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			next := *snapshot
			next.CodeHash = []byte{byte(i + 1)} //nolint:gosec // i is bounded by contenders (16).
			if err := s.EmailOTPs().CompareAndSwap(ctx, snapshot, &next); err == nil {
				wins.Add(1)
			} else if !errors.Is(err, store.ErrAlreadyConsumed) {
				t.Errorf("CompareAndSwap contender %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	if got := wins.Load(); got != 1 {
		t.Fatalf("CAS resend winners=%d want 1", got)
	}
}
