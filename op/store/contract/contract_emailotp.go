package contract

import (
	"bytes"
	"context"
	"errors"
	"math"
	"reflect"
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
		{"CompareAndSwapRejectsInvalidVersion", emailOTPCASInvalidVersion},
		{"CompareAndSwapIdenticalHasOneWinner", emailOTPCASIdentical},
		{"NilPreviousReservesFirstSend", emailOTPCASReserves},
		{"NilPreviousRejectsLiveRecord", emailOTPCASReserveOccupied},
		{"NilPreviousReclaimsRecordPastRetention", emailOTPCASReserveReclaims},
		{"ConcurrentFirstSendHasOneWinner", emailOTPConcurrentReserve},
		{"ConsumeStampsConsumedAt", emailOTPConsume},
		{"ConsumeStampsAnUnstampedChallenge", emailOTPConsumeStampsUnstamped},
		{"ConsumeClearsVerifierFailureState", emailOTPConsumeClearsVerifierFailureState},
		{"ConsumeTwiceRejected", emailOTPConsumeTwice},
		{"ConsumeExpiredCodeRejected", emailOTPConsumeExpired},
		{"ConsumeSupersededCodeRejected", emailOTPConsumeSuperseded},
		{"ConsumeRejectsInvalidVersion", emailOTPConsumeInvalidVersion},
		{"DeleteRemovesChallenge", emailOTPDelete},
		{"DeleteRecreateRejectsStaleSnapshot", emailOTPDeleteRecreateRejectsStaleSnapshot},
		{"DeleteMissing", emailOTPDeleteMissing},
		{"DefensiveCopies", emailOTPDefensiveCopies},
		{"ConcurrentCompareAndSwapHasOneWinner", emailOTPConcurrentCAS},
		{"ConcurrentConsumeHasOneWinner", emailOTPConcurrentConsume},
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
	want.Version = math.MaxInt64
	if err := b.Store.Put(ctx, want); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := b.Store.Get(ctx, want.Subject)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !validEmailOTPVersion(got.Version) {
		t.Fatalf("Put assigned invalid Version %d", got.Version)
	}
	if want.Version != math.MaxInt64 {
		t.Fatalf("Put mutated caller Version = %d", want.Version)
	}
	want.Version = got.Version
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
	next.Version = previous.Version
	next.FailedCount = previous.FailedCount + 1
	next.SendCount = previous.SendCount + 1
	previousBefore, nextBefore := cloneContractEmailOTP(previous), cloneContractEmailOTP(&next)
	if err := b.Store.CompareAndSwap(ctx, previous, &next); err != nil {
		t.Fatalf("CompareAndSwap: %v", err)
	}
	assertContractEmailOTPUnchanged(t, "CAS previous", previous, previousBefore)
	assertContractEmailOTPUnchanged(t, "CAS next", &next, nextBefore)

	got, err := b.Store.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get after swap: %v", err)
	}
	expected := next
	expected.Version = got.Version
	assertEmailOTPVersionChanged(t, previous.Version, got.Version)
	assertEmailOTPEqual(t, got, &expected)
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
	winner.Version = stale.Version
	winner.FailedCount = stale.FailedCount + 1
	staleBefore, winnerBefore := cloneContractEmailOTP(stale), cloneContractEmailOTP(&winner)
	if err := b.Store.CompareAndSwap(ctx, stale, &winner); err != nil {
		t.Fatalf("CompareAndSwap winner: %v", err)
	}
	assertContractEmailOTPUnchanged(t, "winner previous", stale, staleBefore)
	assertContractEmailOTPUnchanged(t, "winner next", &winner, winnerBefore)

	loser := *stale
	loser.FailedCount = 0
	loser.SendCount = 0
	loserBefore := cloneContractEmailOTP(&loser)
	if err := b.Store.CompareAndSwap(ctx, stale, &loser); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("CompareAndSwap stale error = %v, want ErrAlreadyConsumed", err)
	}
	assertContractEmailOTPUnchanged(t, "rejected next", &loser, loserBefore)

	got, err := b.Store.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get after rejected swap: %v", err)
	}
	expected := winner
	expected.Version = got.Version
	assertEmailOTPVersionChanged(t, stale.Version, got.Version)
	assertEmailOTPEqual(t, got, &expected)
}

func emailOTPCASInvalidVersion(t *testing.T, b EmailOTPBackend) {
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

	unequal := *previous
	unequal.Version++
	if err := b.Store.CompareAndSwap(ctx, previous, &unequal); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("CompareAndSwap unequal Version = %v, want ErrAlreadyConsumed", err)
	}

	maxed := *previous
	maxed.Version = math.MaxInt64
	maxedBefore := cloneContractEmailOTP(&maxed)
	if err := b.Store.CompareAndSwap(ctx, &maxed, &maxed); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("CompareAndSwap signed-max Version = %v, want ErrAlreadyConsumed", err)
	}
	assertContractEmailOTPUnchanged(t, "invalid CAS input", &maxed, maxedBefore)
}

func emailOTPCASIdentical(t *testing.T, b EmailOTPBackend) {
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

	ready := make(chan struct{}, 2)
	release := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		next := *previous
		next.CodeSalt = bytes.Clone(previous.CodeSalt)
		next.CodeHash = bytes.Clone(previous.CodeHash)
		wg.Add(1)
		go func() {
			defer wg.Done()
			ready <- struct{}{}
			<-release
			errs <- b.Store.CompareAndSwap(ctx, previous, &next)
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
			t.Fatalf("CompareAndSwap identical: %v", err)
		}
	}
	if winners != 1 {
		t.Fatalf("successful identical transitions = %d, want 1", winners)
	}
	got, err := b.Store.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get after identical CAS: %v", err)
	}
	assertEmailOTPVersionChanged(t, previous.Version, got.Version)
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

	presentedVersion := presented.Version
	presented.ConsumedAt = now
	presentedBefore := cloneContractEmailOTP(presented)
	if err := b.Store.Consume(ctx, presented); err != nil {
		t.Fatalf("Consume: %v", err)
	}
	assertContractEmailOTPUnchanged(t, "Consume input", presented, presentedBefore)

	got, err := b.Store.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get after consume: %v", err)
	}
	if !got.ConsumedAt.Equal(now) {
		t.Fatalf("ConsumedAt = %v, want %v", got.ConsumedAt, now)
	}
	assertEmailOTPVersionChanged(t, presentedVersion, got.Version)
}

// emailOTPConsumeStampsUnstamped pins the post-condition declared on
// [store.EmailOTPStore.Consume]: marking the challenge is the
// implementation's job, so a nil return leaves a non-zero ConsumedAt
// whether or not the caller presented one.
//
// Every other Consume case presents a stamped record, which is what a
// backend that copies the presented value through needs in order to look
// correct. Presenting a zero is the case that separates them: such a
// backend reports success and stores a challenge that still reads as
// pending, so the next holder of the same code redeems it again. The
// second redemption below is that holder. [store.RecoveryStore.Consume]
// carries the same post-condition and the same case.
func emailOTPConsumeStampsUnstamped(t *testing.T, b EmailOTPBackend) {
	t.Helper()
	ctx := context.Background()
	seed := emailOTPContractRecord(b.Now())
	if err := b.Store.Put(ctx, seed); err != nil {
		t.Fatalf("Put: %v", err)
	}
	presented, err := b.Store.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get seed: %v", err)
	}
	if !presented.ConsumedAt.IsZero() {
		t.Fatalf("seeded challenge is already stamped: %v", presented.ConsumedAt)
	}

	// Presented exactly as read: the caller stamps nothing.
	if err := b.Store.Consume(ctx, presented); err != nil {
		t.Fatalf("Consume of an unstamped challenge: %v", err)
	}

	got, err := b.Store.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get after consume: %v", err)
	}
	if got.ConsumedAt.IsZero() {
		t.Fatalf(
			"Consume returned nil but the stored challenge is still unconsumed; " +
				"the code stays redeemable for every later holder",
		)
	}

	// The challenge has to be spent for the next caller, not merely
	// stamped: the replay presents the record as it now reads, so a
	// backend whose only defence is the generation counter does not pass
	// on that alone.
	replay, err := b.Store.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get for replay: %v", err)
	}
	replay.ConsumedAt = time.Time{}
	if err := b.Store.Consume(ctx, replay); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("second Consume of the same challenge: want ErrAlreadyConsumed, got %v", err)
	}
}

// emailOTPConsumeClearsVerifierFailureState mirrors a successful code entry
// after one or more wrong guesses. The verifier resets those counters and
// stamps ConsumedAt on the same record it read; Consume must accept that
// legitimate transition rather than requiring byte-for-byte equality with the
// pre-verification snapshot.
func emailOTPConsumeClearsVerifierFailureState(t *testing.T, b EmailOTPBackend) {
	t.Helper()
	ctx := context.Background()
	now := b.Now()
	seed := emailOTPContractRecord(now)
	if err := b.Store.Put(ctx, seed); err != nil {
		t.Fatalf("Put: %v", err)
	}
	previous, err := b.Store.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get seed: %v", err)
	}
	failed := *previous
	failed.Version = previous.Version
	failed.FailedCount = 2
	failed.FirstFailureAt = now.Add(-time.Minute)
	if err := b.Store.CompareAndSwap(ctx, previous, &failed); err != nil {
		t.Fatalf("CompareAndSwap failed-attempt state: %v", err)
	}

	presented, err := b.Store.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get failed-attempt state: %v", err)
	}
	presentedVersion := presented.Version
	presented.FailedCount = 0
	presented.FirstFailureAt = time.Time{}
	presented.LockedUntil = time.Time{}
	presented.ConsumedAt = now
	presentedBefore := cloneContractEmailOTP(presented)
	if err := b.Store.Consume(ctx, presented); err != nil {
		t.Fatalf("Consume after failed attempts: %v", err)
	}
	assertContractEmailOTPUnchanged(t, "Consume after failed attempts input", presented, presentedBefore)

	got, err := b.Store.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get after consume: %v", err)
	}
	if got.FailedCount != 0 || !got.FirstFailureAt.IsZero() || !got.LockedUntil.IsZero() {
		t.Fatalf("successful consume did not clear verifier state: %+v", got)
	}
	if !got.ConsumedAt.Equal(now) {
		t.Fatalf("ConsumedAt = %v, want %v", got.ConsumedAt, now)
	}
	assertEmailOTPVersionChanged(t, presentedVersion, got.Version)
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
	presentedVersion := presented.Version
	presented.ConsumedAt = now
	presentedBefore := cloneContractEmailOTP(presented)
	if err := b.Store.Consume(ctx, presented); err != nil {
		t.Fatalf("Consume first: %v", err)
	}
	assertContractEmailOTPUnchanged(t, "first Consume input", presented, presentedBefore)
	first, err := b.Store.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get after first consume: %v", err)
	}
	firstVersion := first.Version
	assertEmailOTPVersionChanged(t, presentedVersion, firstVersion)

	replay, err := b.Store.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get before replay: %v", err)
	}
	replay.ConsumedAt = now.Add(time.Minute)
	replayVersion := replay.Version
	replayBefore := cloneContractEmailOTP(replay)
	if err := b.Store.Consume(ctx, replay); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("Consume replay error = %v, want ErrAlreadyConsumed", err)
	}
	_ = replayVersion
	assertContractEmailOTPUnchanged(t, "rejected Consume input", replay, replayBefore)

	got, err := b.Store.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get after replay: %v", err)
	}
	if !got.ConsumedAt.Equal(now) {
		t.Fatalf("ConsumedAt = %v, want the first redemption at %v", got.ConsumedAt, now)
	}
	if got.Version != firstVersion {
		t.Fatalf("Consume replay changed Version = %d, want %d", got.Version, firstVersion)
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

func emailOTPConsumeInvalidVersion(t *testing.T, b EmailOTPBackend) {
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
	presented.Version = math.MaxInt64
	presented.ConsumedAt = now
	presentedBefore := cloneContractEmailOTP(presented)
	if err := b.Store.Consume(ctx, presented); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("Consume signed-max Version = %v, want ErrAlreadyConsumed", err)
	}
	assertContractEmailOTPUnchanged(t, "invalid Consume input", presented, presentedBefore)
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

func emailOTPDeleteRecreateRejectsStaleSnapshot(t *testing.T, b EmailOTPBackend) {
	t.Helper()
	ctx := context.Background()
	seed := emailOTPContractRecord(b.Now())
	if err := b.Store.Put(ctx, seed); err != nil {
		t.Fatalf("Put seed: %v", err)
	}
	stale, err := b.Store.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get stale: %v", err)
	}
	if err := b.Store.Delete(ctx, seed.Subject); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	// The recreated row deliberately has the same document. The token must
	// still identify a fresh incarnation after physical/TTL deletion.
	fresh := *seed
	fresh.CodeSalt = bytes.Clone(seed.CodeSalt)
	fresh.CodeHash = bytes.Clone(seed.CodeHash)
	if err := b.Store.Put(ctx, &fresh); err != nil {
		t.Fatalf("Put recreated record: %v", err)
	}
	recreated, err := b.Store.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get recreated record: %v", err)
	}
	assertEmailOTPVersionChanged(t, stale.Version, recreated.Version)

	staleNext := *stale
	staleNext.FailedCount++
	if err := b.Store.CompareAndSwap(ctx, stale, &staleNext); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("stale CAS after same-value recreate = %v, want ErrAlreadyConsumed", err)
	}
	staleConsume := *stale
	staleConsume.ConsumedAt = b.Now()
	if err := b.Store.Consume(ctx, &staleConsume); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("stale Consume after same-value recreate = %v, want ErrAlreadyConsumed", err)
	}
	got, err := b.Store.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get after stale transitions: %v", err)
	}
	assertEmailOTPEqual(t, got, recreated)
}

func emailOTPDeleteMissing(t *testing.T, b EmailOTPBackend) {
	t.Helper()
	if err := b.Store.Delete(context.Background(), "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Delete(missing) error = %v, want ErrNotFound", err)
	}
}

func assertEmailOTPVersionChanged(t *testing.T, previous, current uint64) {
	t.Helper()
	if !validEmailOTPVersion(current) || (previous != 0 && previous == current) {
		t.Fatalf("Version did not change to a valid opaque token: previous=%d current=%d", previous, current)
	}
}

func validEmailOTPVersion(version uint64) bool {
	return version > 0 && version < uint64(math.MaxInt64)
}

func cloneContractEmailOTP(r *store.EmailOTPRecord) *store.EmailOTPRecord {
	if r == nil {
		return nil
	}
	out := *r
	out.CodeSalt = bytes.Clone(r.CodeSalt)
	out.CodeHash = bytes.Clone(r.CodeHash)
	return &out
}

func assertContractEmailOTPUnchanged(t *testing.T, label string, got, want *store.EmailOTPRecord) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s mutated caller record: got=%+v want=%+v", label, got, want)
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

// emailOTPConcurrentConsume drives the redemption under the traffic that
// makes its single-use rule a security property: the same emailed code
// submitted twice at once, from a retried form post or from an attacker
// racing the legitimate submission.
//
// The sequential replay case pins ErrAlreadyConsumed for the second
// caller, and every read-decide-write implementation passes it. What it
// cannot see is two callers that both read the unredeemed challenge
// before either wrote: both are told the code was theirs to spend, and a
// second factor that may be presented once has been accepted twice.
func emailOTPConcurrentConsume(t *testing.T, b EmailOTPBackend) {
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

	errs := race(func(int) error {
		attempt := *presented
		attempt.ConsumedAt = now
		return b.Store.Consume(ctx, &attempt)
	})
	assertOneWinner(t, "EmailOTPs().Consume", errs)
	for i, err := range errs {
		if err != nil && !errors.Is(err, store.ErrAlreadyConsumed) {
			t.Fatalf("losing Consume %d: want ErrAlreadyConsumed, got %v", i, err)
		}
	}

	got, err := b.Store.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get after the race: %v", err)
	}
	if got.ConsumedAt.IsZero() {
		t.Fatal("the challenge reads as unredeemed after a Consume reported success")
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
	assertEmailOTPVersionChanged(t, current.Version, got.Version)
}

// emailOTPCASReserves covers the nil-previous form against an empty key,
// which is how the first send for a subject claims its record.
func emailOTPCASReserves(t *testing.T, b EmailOTPBackend) {
	t.Helper()
	ctx := context.Background()
	first := emailOTPContractRecord(b.Now())
	firstBefore := cloneContractEmailOTP(first)
	if err := b.Store.CompareAndSwap(ctx, nil, first); err != nil {
		t.Fatalf("CompareAndSwap(nil) on an empty key: %v", err)
	}
	assertContractEmailOTPUnchanged(t, "nil reservation input", first, firstBefore)

	got, err := b.Store.Get(ctx, first.Subject)
	if err != nil {
		t.Fatalf("Get after reservation: %v", err)
	}
	expected := *first
	expected.Version = got.Version
	assertEmailOTPVersionChanged(t, first.Version, got.Version)
	assertEmailOTPEqual(t, got, &expected)
}

// emailOTPCASReserveOccupied is the case that makes the reservation worth
// having. A backend that treats nil previous as a plain upsert passes
// every other case here and still lets a second send overwrite the record
// the first one established — resetting SendCount and FirstFailureAt, and
// with them the resend cap and the brute-force window. That is a
// rate-limit bypass reachable by anyone who can ask for a code.
func emailOTPCASReserveOccupied(t *testing.T, b EmailOTPBackend) {
	t.Helper()
	ctx := context.Background()
	held := emailOTPContractRecord(b.Now())
	if err := b.Store.Put(ctx, held); err != nil {
		t.Fatalf("Put: %v", err)
	}

	intruder := emailOTPContractRecord(b.Now())
	intruder.SendCount = 1
	intruder.FailedCount = 0
	intruder.FirstFailureAt = time.Time{}
	if err := b.Store.CompareAndSwap(ctx, nil, intruder); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("CompareAndSwap(nil) over a live record = %v, want ErrAlreadyConsumed", err)
	}

	got, err := b.Store.Get(ctx, held.Subject)
	if err != nil {
		t.Fatalf("Get after rejected reservation: %v", err)
	}
	expected := *held
	expected.Version = got.Version
	assertEmailOTPVersionChanged(t, held.Version, got.Version)
	assertEmailOTPEqual(t, got, &expected)
}

// emailOTPCASReserveReclaims pins the other half of the boundary: once the
// stored record is past its retention horizon, Get reports ErrNotFound and
// the key is free again, so a reservation MUST succeed. A backend that
// refused here would wedge the subject out of email OTP until whatever
// sweeper it runs caught up.
func emailOTPCASReserveReclaims(t *testing.T, b EmailOTPBackend) {
	t.Helper()
	ctx := context.Background()
	now := b.Now()

	stale := emailOTPContractRecord(now)
	stale.ExpiresAt = now.Add(-2 * time.Hour)
	stale.RetainUntil = now.Add(-time.Minute)
	if err := b.Store.Put(ctx, stale); err != nil {
		t.Fatalf("Put stale: %v", err)
	}

	fresh := emailOTPContractRecord(now)
	fresh.SendCount = 1
	freshBefore := cloneContractEmailOTP(fresh)
	if err := b.Store.CompareAndSwap(ctx, nil, fresh); err != nil {
		t.Fatalf("CompareAndSwap(nil) over a record past retention: %v", err)
	}
	assertContractEmailOTPUnchanged(t, "reclaim reservation input", fresh, freshBefore)

	got, err := b.Store.Get(ctx, fresh.Subject)
	if err != nil {
		t.Fatalf("Get after reclaim: %v", err)
	}
	expected := *fresh
	expected.Version = got.Version
	assertEmailOTPVersionChanged(t, stale.Version, got.Version)
	assertEmailOTPEqual(t, got, &expected)
}

// emailOTPConcurrentReserve is the reservation's actual guarantee: two
// first sends racing on the same empty key must not both deliver a code.
// A read-then-Put backend passes emailOTPCASReserves and fails this.
func emailOTPConcurrentReserve(t *testing.T, b EmailOTPBackend) {
	t.Helper()
	ctx := context.Background()

	ready := make(chan struct{}, 2)
	release := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for count := 1; count <= 2; count++ {
		next := emailOTPContractRecord(b.Now())
		next.SendCount = count
		wg.Add(1)
		go func() {
			defer wg.Done()
			ready <- struct{}{}
			<-release
			errs <- b.Store.CompareAndSwap(ctx, nil, next)
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
			t.Fatalf("CompareAndSwap(nil) concurrent: %v", err)
		}
	}
	if winners != 1 {
		t.Fatalf("successful concurrent reservations = %d, want 1", winners)
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
	if got.Version != want.Version {
		t.Fatalf("Version = %d, want %d", got.Version, want.Version)
	}
}
