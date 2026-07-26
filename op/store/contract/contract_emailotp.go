package contract

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// EmailOTPBackend bundles a freshly constructed [store.EmailOTPStore]
// with the wall-clock instant the backend treats as "now". Unlike the
// other authentication-factor substores, the email-OTP contract turns on
// retention windows, so the harness has to pin its records against the
// backend's own clock.
type EmailOTPBackend struct {
	// Store is the substore under test.
	Store store.EmailOTPStore

	// Now reports the wall-clock the backend evaluates retention
	// against. The harness builds records at Now±1h to exercise the
	// live and expired sides of every window.
	Now func() time.Time
}

// EmailOTPFactory builds a fresh standalone email-OTP backend for a
// single contract sub-test.
type EmailOTPFactory func(t *testing.T) EmailOTPBackend

// RunEmailOTPs exercises the retention, compare-and-swap, and single-use
// redemption guarantees of [store.EmailOTPStore]. The retention cases are
// the ones worth porting carefully: a backend that drops the record when
// the code expires silently resets the resend cap and the brute-force
// counter, which is a rate-limit bypass rather than a cosmetic deviation.
func RunEmailOTPs(t *testing.T, f EmailOTPFactory) {
	t.Helper()

	cases := []struct {
		name string
		run  func(*testing.T, EmailOTPBackend)
	}{
		{"Missing", emailOTPMissing},
		{"PutGetRoundTrip", emailOTPRoundTrip},
		{"GetSurvivesCodeExpiryWhileRetained", emailOTPRetainedPastCodeExpiry},
		{"GetDropsRecordPastRetention", emailOTPPastRetention},
		{"RetentionFallsBackToExpiresAt", emailOTPRetentionFallback},
		{"CompareAndSwapAppliesNext", emailOTPCASApplies},
		{"CompareAndSwapStaleSnapshotRejected", emailOTPCASStale},
		{"ConsumeStampsConsumedAt", emailOTPConsume},
		{"ConsumeTwiceRejected", emailOTPConsumeTwice},
		{"ConsumeExpiredCodeRejected", emailOTPConsumeExpired},
		{"ConsumeSupersededCodeRejected", emailOTPConsumeSuperseded},
		{"DeleteRemovesChallenge", emailOTPDelete},
		{"DeleteMissing", emailOTPDeleteMissing},
		{"DefensiveCopies", emailOTPDefensiveCopies},
		{"ConcurrentCompareAndSwapHasOneWinner", emailOTPConcurrentCAS},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.run(t, f(t))
		})
	}
}

func emailOTPMissing(t *testing.T, b EmailOTPBackend) {
	t.Helper()
	if _, err := b.Store.Get(context.Background(), "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get(missing) error = %v, want ErrNotFound", err)
	}
}

func emailOTPRoundTrip(t *testing.T, b EmailOTPBackend) {
	t.Helper()
	ctx := context.Background()
	want := emailOTPContractRecord(b.Now())
	if err := b.Store.Put(ctx, want); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := b.Store.Get(ctx, want.Subject)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	assertEmailOTPEqual(t, got, want)
}

func emailOTPRetainedPastCodeExpiry(t *testing.T, b EmailOTPBackend) {
	t.Helper()
	ctx := context.Background()
	now := b.Now()
	rec := emailOTPContractRecord(now)
	rec.ExpiresAt = now.Add(-time.Minute)     // the code is dead
	rec.RetainUntil = now.Add(23 * time.Hour) // the counters are not
	if err := b.Store.Put(ctx, rec); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := b.Store.Get(ctx, rec.Subject)
	if err != nil {
		t.Fatalf("Get past code expiry error = %v, want the retained record", err)
	}
	if got.FailedCount != rec.FailedCount || got.SendCount != rec.SendCount {
		t.Fatalf("retained counters = (failed %d, send %d), want (%d, %d)",
			got.FailedCount, got.SendCount, rec.FailedCount, rec.SendCount)
	}
}

func emailOTPPastRetention(t *testing.T, b EmailOTPBackend) {
	t.Helper()
	ctx := context.Background()
	now := b.Now()
	rec := emailOTPContractRecord(now)
	rec.ExpiresAt = now.Add(-2 * time.Hour)
	rec.RetainUntil = now.Add(-time.Minute)
	if err := b.Store.Put(ctx, rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := b.Store.Get(ctx, rec.Subject); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get past retention error = %v, want ErrNotFound", err)
	}
}

func emailOTPRetentionFallback(t *testing.T, b EmailOTPBackend) {
	t.Helper()
	ctx := context.Background()
	now := b.Now()

	live := emailOTPContractRecord(now)
	live.Subject = "live"
	live.ExpiresAt = now.Add(time.Hour)
	live.RetainUntil = time.Time{}
	if err := b.Store.Put(ctx, live); err != nil {
		t.Fatalf("Put live: %v", err)
	}
	if _, err := b.Store.Get(ctx, "live"); err != nil {
		t.Fatalf("Get live with zero RetainUntil: %v", err)
	}

	dead := emailOTPContractRecord(now)
	dead.Subject = "dead"
	dead.ExpiresAt = now.Add(-time.Minute)
	dead.RetainUntil = time.Time{}
	if err := b.Store.Put(ctx, dead); err != nil {
		t.Fatalf("Put dead: %v", err)
	}
	if _, err := b.Store.Get(ctx, "dead"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get expired with zero RetainUntil error = %v, want ErrNotFound", err)
	}
}

func emailOTPCASApplies(t *testing.T, b EmailOTPBackend) {
	t.Helper()
	ctx := context.Background()
	seed := emailOTPContractRecord(b.Now())
	if err := b.Store.Put(ctx, seed); err != nil {
		t.Fatalf("Put: %v", err)
	}
	previous, err := b.Store.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get seed: %v", err)
	}

	next := *previous
	next.FailedCount = previous.FailedCount + 1
	next.SendCount = previous.SendCount + 1
	if err := b.Store.CompareAndSwap(ctx, previous, &next); err != nil {
		t.Fatalf("CompareAndSwap: %v", err)
	}

	got, err := b.Store.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get after swap: %v", err)
	}
	assertEmailOTPEqual(t, got, &next)
}

func emailOTPCASStale(t *testing.T, b EmailOTPBackend) {
	t.Helper()
	ctx := context.Background()
	seed := emailOTPContractRecord(b.Now())
	if err := b.Store.Put(ctx, seed); err != nil {
		t.Fatalf("Put: %v", err)
	}
	stale, err := b.Store.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get seed: %v", err)
	}

	winner := *stale
	winner.FailedCount = stale.FailedCount + 1
	if err := b.Store.CompareAndSwap(ctx, stale, &winner); err != nil {
		t.Fatalf("CompareAndSwap winner: %v", err)
	}

	loser := *stale
	loser.FailedCount = 0
	loser.SendCount = 0
	if err := b.Store.CompareAndSwap(ctx, stale, &loser); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("CompareAndSwap stale error = %v, want ErrAlreadyConsumed", err)
	}

	got, err := b.Store.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get after rejected swap: %v", err)
	}
	assertEmailOTPEqual(t, got, &winner)
}

func emailOTPConsume(t *testing.T, b EmailOTPBackend) {
	t.Helper()
	ctx := context.Background()
	now := b.Now()
	seed := emailOTPContractRecord(now)
	if err := b.Store.Put(ctx, seed); err != nil {
		t.Fatalf("Put: %v", err)
	}
	presented, err := b.Store.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get seed: %v", err)
	}

	presented.ConsumedAt = now
	if err := b.Store.Consume(ctx, presented); err != nil {
		t.Fatalf("Consume: %v", err)
	}

	got, err := b.Store.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get after consume: %v", err)
	}
	if !got.ConsumedAt.Equal(now) {
		t.Fatalf("ConsumedAt = %v, want %v", got.ConsumedAt, now)
	}
}

func emailOTPConsumeTwice(t *testing.T, b EmailOTPBackend) {
	t.Helper()
	ctx := context.Background()
	now := b.Now()
	seed := emailOTPContractRecord(now)
	if err := b.Store.Put(ctx, seed); err != nil {
		t.Fatalf("Put: %v", err)
	}
	presented, err := b.Store.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get seed: %v", err)
	}
	presented.ConsumedAt = now
	if err := b.Store.Consume(ctx, presented); err != nil {
		t.Fatalf("Consume first: %v", err)
	}

	replay, err := b.Store.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get before replay: %v", err)
	}
	replay.ConsumedAt = now.Add(time.Minute)
	if err := b.Store.Consume(ctx, replay); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("Consume replay error = %v, want ErrAlreadyConsumed", err)
	}

	got, err := b.Store.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get after replay: %v", err)
	}
	if !got.ConsumedAt.Equal(now) {
		t.Fatalf("ConsumedAt = %v, want the first redemption at %v", got.ConsumedAt, now)
	}
}

func emailOTPConsumeExpired(t *testing.T, b EmailOTPBackend) {
	t.Helper()
	ctx := context.Background()
	now := b.Now()
	// The record is still retained (its counters are live) but the code
	// itself has expired: Consume must refuse to redeem it.
	rec := emailOTPContractRecord(now)
	rec.ExpiresAt = now.Add(-time.Minute)
	rec.RetainUntil = now.Add(23 * time.Hour)
	if err := b.Store.Put(ctx, rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	presented, err := b.Store.Get(ctx, rec.Subject)
	if err != nil {
		t.Fatalf("Get seed: %v", err)
	}

	presented.ConsumedAt = now
	if err := b.Store.Consume(ctx, presented); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Consume expired code error = %v, want ErrNotFound", err)
	}

	got, err := b.Store.Get(ctx, rec.Subject)
	if err != nil {
		t.Fatalf("Get after rejected consume: %v", err)
	}
	if !got.ConsumedAt.IsZero() {
		t.Fatal("an expired code was redeemed")
	}
}

func emailOTPConsumeSuperseded(t *testing.T, b EmailOTPBackend) {
	t.Helper()
	ctx := context.Background()
	now := b.Now()
	seed := emailOTPContractRecord(now)
	if err := b.Store.Put(ctx, seed); err != nil {
		t.Fatalf("Put: %v", err)
	}
	presented, err := b.Store.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get seed: %v", err)
	}

	// A resend overwrites the challenge with a fresh code. The code the
	// caller is holding must no longer redeem the new one.
	resent := emailOTPContractRecord(now)
	resent.CodeSalt = []byte{0xaa, 0xbb, 0xcc, 0xdd}
	resent.CodeHash = []byte{0x11, 0x22, 0x33, 0x44}
	if err := b.Store.Put(ctx, resent); err != nil {
		t.Fatalf("Put resent: %v", err)
	}

	presented.ConsumedAt = now
	if err := b.Store.Consume(ctx, presented); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("Consume superseded code error = %v, want ErrAlreadyConsumed", err)
	}

	got, err := b.Store.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get after rejected consume: %v", err)
	}
	if !got.ConsumedAt.IsZero() {
		t.Fatal("a superseded code redeemed the challenge that replaced it")
	}
}

func emailOTPDelete(t *testing.T, b EmailOTPBackend) {
	t.Helper()
	ctx := context.Background()
	seed := emailOTPContractRecord(b.Now())
	if err := b.Store.Put(ctx, seed); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := b.Store.Delete(ctx, seed.Subject); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := b.Store.Get(ctx, seed.Subject); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get after delete error = %v, want ErrNotFound", err)
	}
}

func emailOTPDeleteMissing(t *testing.T, b EmailOTPBackend) {
	t.Helper()
	if err := b.Store.Delete(context.Background(), "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Delete(missing) error = %v, want ErrNotFound", err)
	}
}

func emailOTPDefensiveCopies(t *testing.T, b EmailOTPBackend) {
	t.Helper()
	ctx := context.Background()
	now := b.Now()
	seed := emailOTPContractRecord(now)
	if err := b.Store.Put(ctx, seed); err != nil {
		t.Fatalf("Put: %v", err)
	}
	seed.FailedCount = 99
	seed.CodeHash[0] ^= 0xff

	pristine := emailOTPContractRecord(now)
	first, err := b.Store.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("first Get: %v", err)
	}
	if first.FailedCount != pristine.FailedCount {
		t.Fatalf("input mutation leaked: FailedCount = %d, want %d", first.FailedCount, pristine.FailedCount)
	}
	if !bytes.Equal(first.CodeHash, pristine.CodeHash) {
		t.Fatalf("input mutation leaked into CodeHash: %x", first.CodeHash)
	}

	first.FailedCount = 100
	first.CodeHash[0] ^= 0xff
	second, err := b.Store.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if second.FailedCount != pristine.FailedCount {
		t.Fatalf("result mutation leaked: FailedCount = %d, want %d", second.FailedCount, pristine.FailedCount)
	}
	if !bytes.Equal(second.CodeHash, pristine.CodeHash) {
		t.Fatalf("result mutation leaked into CodeHash: %x", second.CodeHash)
	}
}

func emailOTPConcurrentCAS(t *testing.T, b EmailOTPBackend) {
	t.Helper()
	ctx := context.Background()
	seed := emailOTPContractRecord(b.Now())
	if err := b.Store.Put(ctx, seed); err != nil {
		t.Fatalf("Put: %v", err)
	}
	current, err := b.Store.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get seed: %v", err)
	}

	ready := make(chan struct{}, 2)
	release := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for count := 8; count <= 9; count++ {
		next := *current
		next.FailedCount = count
		wg.Add(1)
		go func() {
			defer wg.Done()
			ready <- struct{}{}
			<-release
			errs <- b.Store.CompareAndSwap(ctx, current, &next)
		}()
	}
	<-ready
	<-ready
	close(release)
	wg.Wait()

	winners := 0
	for range 2 {
		switch err := <-errs; {
		case err == nil:
			winners++
		case errors.Is(err, store.ErrAlreadyConsumed):
		default:
			t.Fatalf("CompareAndSwap concurrent: %v", err)
		}
	}
	if winners != 1 {
		t.Fatalf("successful concurrent transitions = %d, want 1", winners)
	}

	got, err := b.Store.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get final: %v", err)
	}
	if got.FailedCount != 8 && got.FailedCount != 9 {
		t.Fatalf("final FailedCount = %d, want one of the candidate counts", got.FailedCount)
	}
}

func emailOTPContractRecord(now time.Time) *store.EmailOTPRecord {
	return &store.EmailOTPRecord{
		Subject:           "alice",
		CodeSalt:          []byte{0x01, 0x02, 0x03, 0x04},
		CodeHash:          []byte{0xde, 0xad, 0xbe, 0xef},
		SentAt:            now.Add(-time.Minute),
		ExpiresAt:         now.Add(10 * time.Minute),
		RetainUntil:       now.Add(24 * time.Hour),
		FailedCount:       2,
		FirstFailureAt:    now.Add(-30 * time.Minute),
		LockedUntil:       time.Time{},
		SendCount:         3,
		SendWindowStart:   now.Add(-45 * time.Minute),
		LastSendAttemptAt: now.Add(-time.Minute),
	}
}

func assertEmailOTPEqual(t *testing.T, got, want *store.EmailOTPRecord) {
	t.Helper()
	if got.Subject != want.Subject {
		t.Fatalf("Subject = %q, want %q", got.Subject, want.Subject)
	}
	if !bytes.Equal(got.CodeSalt, want.CodeSalt) {
		t.Fatalf("CodeSalt = %x, want %x", got.CodeSalt, want.CodeSalt)
	}
	if !bytes.Equal(got.CodeHash, want.CodeHash) {
		t.Fatalf("CodeHash = %x, want %x", got.CodeHash, want.CodeHash)
	}
	for _, f := range []struct {
		name      string
		got, want time.Time
	}{
		{"SentAt", got.SentAt, want.SentAt},
		{"ExpiresAt", got.ExpiresAt, want.ExpiresAt},
		{"RetainUntil", got.RetainUntil, want.RetainUntil},
		{"FirstFailureAt", got.FirstFailureAt, want.FirstFailureAt},
		{"LockedUntil", got.LockedUntil, want.LockedUntil},
		{"ConsumedAt", got.ConsumedAt, want.ConsumedAt},
		{"SendWindowStart", got.SendWindowStart, want.SendWindowStart},
		{"LastSendAttemptAt", got.LastSendAttemptAt, want.LastSendAttemptAt},
	} {
		if !f.got.Equal(f.want) {
			t.Fatalf("%s = %v, want %v", f.name, f.got, f.want)
		}
	}
	if got.FailedCount != want.FailedCount {
		t.Fatalf("FailedCount = %d, want %d", got.FailedCount, want.FailedCount)
	}
	if got.SendCount != want.SendCount {
		t.Fatalf("SendCount = %d, want %d", got.SendCount, want.SendCount)
	}
}
