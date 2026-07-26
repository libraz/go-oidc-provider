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

// TOTPFactory builds a fresh standalone [store.TOTPStore] for a single
// contract sub-test. TOTP enrolments are intentionally separate from
// [Backend] because they are supplied directly to the TOTP step rather
// than through the aggregate [store.Store].
type TOTPFactory func(t *testing.T) store.TOTPStore

// RunTOTPs exercises the round-trip, compare-and-swap, and single-use
// acceptance guarantees of [store.TOTPStore]. Adapter authors should call
// it from their black-box test suite in addition to any backend-specific
// tests.
func RunTOTPs(t *testing.T, f TOTPFactory) {
	t.Helper()

	cases := []struct {
		name string
		run  func(*testing.T, store.TOTPStore)
	}{
		{"Missing", totpMissing},
		{"PutGetRoundTrip", totpRoundTrip},
		{"PutReplacesEnrolment", totpPutReplaces},
		{"CompareAndSwapAppliesNext", totpCASApplies},
		{"CompareAndSwapStaleSnapshotRejected", totpCASStale},
		{"AcceptAdvancesStep", totpAcceptAdvances},
		{"AcceptRejectsReplayedStep", totpAcceptReplay},
		{"AcceptRejectsEarlierStep", totpAcceptEarlier},
		{"DeleteRemovesEnrolment", totpDelete},
		{"DeleteMissing", totpDeleteMissing},
		{"DefensiveCopies", totpDefensiveCopies},
		{"ConcurrentCompareAndSwapHasOneWinner", totpConcurrentCAS},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.run(t, f(t))
		})
	}
}

func totpMissing(t *testing.T, s store.TOTPStore) {
	t.Helper()
	if _, err := s.Get(context.Background(), "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get(missing) error = %v, want ErrNotFound", err)
	}
}

func totpRoundTrip(t *testing.T, s store.TOTPStore) {
	t.Helper()
	ctx := context.Background()
	want := totpContractRecord()
	if err := s.Put(ctx, want); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get(ctx, want.Subject)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	assertTOTPEqual(t, got, want)
}

func totpPutReplaces(t *testing.T, s store.TOTPStore) {
	t.Helper()
	ctx := context.Background()
	first := totpContractRecord()
	if err := s.Put(ctx, first); err != nil {
		t.Fatalf("Put first: %v", err)
	}
	second := totpContractRecord()
	second.SecretCiphertext = []byte{0x09, 0x08, 0x07}
	second.FailedCount = 0
	second.LastAcceptedStep = 4242
	if err := s.Put(ctx, second); err != nil {
		t.Fatalf("Put second: %v", err)
	}
	got, err := s.Get(ctx, first.Subject)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	assertTOTPEqual(t, got, second)
}

func totpCASApplies(t *testing.T, s store.TOTPStore) {
	t.Helper()
	ctx := context.Background()
	seed := totpContractRecord()
	if err := s.Put(ctx, seed); err != nil {
		t.Fatalf("Put: %v", err)
	}
	previous, err := s.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get seed: %v", err)
	}

	next := *previous
	next.FailedCount = previous.FailedCount + 1
	next.FirstFailureAt = Reference.Add(-time.Minute)
	if err := s.CompareAndSwap(ctx, previous, &next); err != nil {
		t.Fatalf("CompareAndSwap: %v", err)
	}

	got, err := s.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get after swap: %v", err)
	}
	assertTOTPEqual(t, got, &next)
}

func totpCASStale(t *testing.T, s store.TOTPStore) {
	t.Helper()
	ctx := context.Background()
	seed := totpContractRecord()
	if err := s.Put(ctx, seed); err != nil {
		t.Fatalf("Put: %v", err)
	}
	stale, err := s.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get seed: %v", err)
	}

	winner := *stale
	winner.FailedCount = stale.FailedCount + 1
	if err := s.CompareAndSwap(ctx, stale, &winner); err != nil {
		t.Fatalf("CompareAndSwap winner: %v", err)
	}

	// The stale snapshot no longer describes the stored record, so the
	// second transition must be refused rather than rolling the counter
	// back over the winner.
	loser := *stale
	loser.FailedCount = 99
	loser.LockedUntil = Reference.Add(24 * time.Hour)
	if err := s.CompareAndSwap(ctx, stale, &loser); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("CompareAndSwap stale error = %v, want ErrAlreadyConsumed", err)
	}

	got, err := s.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get after rejected swap: %v", err)
	}
	assertTOTPEqual(t, got, &winner)
}

func totpAcceptAdvances(t *testing.T, s store.TOTPStore) {
	t.Helper()
	ctx := context.Background()
	seed := totpContractRecord()
	if err := s.Put(ctx, seed); err != nil {
		t.Fatalf("Put: %v", err)
	}
	current, err := s.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get seed: %v", err)
	}

	success := *current
	success.LastAcceptedStep = current.LastAcceptedStep + 1
	success.FailedCount = 0
	success.FirstFailureAt = time.Time{}
	if err := s.Accept(ctx, &success); err != nil {
		t.Fatalf("Accept: %v", err)
	}

	got, err := s.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get after accept: %v", err)
	}
	assertTOTPEqual(t, got, &success)
}

func totpAcceptReplay(t *testing.T, s store.TOTPStore) {
	t.Helper()
	ctx := context.Background()
	seed := totpContractRecord()
	if err := s.Put(ctx, seed); err != nil {
		t.Fatalf("Put: %v", err)
	}
	current, err := s.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get seed: %v", err)
	}

	first := *current
	first.LastAcceptedStep = current.LastAcceptedStep + 1
	if err := s.Accept(ctx, &first); err != nil {
		t.Fatalf("Accept first: %v", err)
	}

	// Same step replayed inside the 30-second window: the second
	// redemption must lose.
	replay := first
	replay.FailedCount = 42
	if err := s.Accept(ctx, &replay); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("Accept replay error = %v, want ErrAlreadyConsumed", err)
	}

	got, err := s.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get after replay: %v", err)
	}
	assertTOTPEqual(t, got, &first)
}

func totpAcceptEarlier(t *testing.T, s store.TOTPStore) {
	t.Helper()
	ctx := context.Background()
	seed := totpContractRecord()
	seed.LastAcceptedStep = 100
	if err := s.Put(ctx, seed); err != nil {
		t.Fatalf("Put: %v", err)
	}
	current, err := s.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get seed: %v", err)
	}

	earlier := *current
	earlier.LastAcceptedStep = 99
	if err := s.Accept(ctx, &earlier); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("Accept earlier step error = %v, want ErrAlreadyConsumed", err)
	}

	got, err := s.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get after rejected accept: %v", err)
	}
	if got.LastAcceptedStep != 100 {
		t.Fatalf("LastAcceptedStep = %d, want 100", got.LastAcceptedStep)
	}
}

func totpDelete(t *testing.T, s store.TOTPStore) {
	t.Helper()
	ctx := context.Background()
	seed := totpContractRecord()
	if err := s.Put(ctx, seed); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Delete(ctx, seed.Subject); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(ctx, seed.Subject); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get after delete error = %v, want ErrNotFound", err)
	}
}

func totpDeleteMissing(t *testing.T, s store.TOTPStore) {
	t.Helper()
	if err := s.Delete(context.Background(), "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Delete(missing) error = %v, want ErrNotFound", err)
	}
}

func totpDefensiveCopies(t *testing.T, s store.TOTPStore) {
	t.Helper()
	ctx := context.Background()
	seed := totpContractRecord()
	if err := s.Put(ctx, seed); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Mutating the record handed to Put must not reach the backend.
	seed.FailedCount = 99
	seed.SecretCiphertext[0] ^= 0xff

	first, err := s.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("first Get: %v", err)
	}
	if first.FailedCount != 3 {
		t.Fatalf("input mutation leaked: FailedCount = %d, want 3", first.FailedCount)
	}
	if !bytes.Equal(first.SecretCiphertext, totpContractRecord().SecretCiphertext) {
		t.Fatalf("input mutation leaked into SecretCiphertext: %x", first.SecretCiphertext)
	}

	// Mutating a Get result must not reach the backend either.
	first.FailedCount = 100
	first.SecretCiphertext[0] ^= 0xff
	second, err := s.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if second.FailedCount != 3 {
		t.Fatalf("result mutation leaked: FailedCount = %d, want 3", second.FailedCount)
	}
	if !bytes.Equal(second.SecretCiphertext, totpContractRecord().SecretCiphertext) {
		t.Fatalf("result mutation leaked into SecretCiphertext: %x", second.SecretCiphertext)
	}
}

func totpConcurrentCAS(t *testing.T, s store.TOTPStore) {
	t.Helper()
	ctx := context.Background()
	seed := totpContractRecord()
	if err := s.Put(ctx, seed); err != nil {
		t.Fatalf("Put: %v", err)
	}
	current, err := s.Get(ctx, seed.Subject)
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
			errs <- s.CompareAndSwap(ctx, current, &next)
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

	got, err := s.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get final: %v", err)
	}
	if got.FailedCount != 8 && got.FailedCount != 9 {
		t.Fatalf("final FailedCount = %d, want one of the candidate counts", got.FailedCount)
	}
}

func totpContractRecord() *store.TOTPRecord {
	return &store.TOTPRecord{
		Subject:          "alice",
		SecretCiphertext: []byte{0x00, 0x01, 0x02, 0xfe, 0xff},
		ConfirmedAt:      Reference.Add(-time.Hour),
		FailedCount:      3,
		FirstFailureAt:   Reference.Add(-30 * time.Minute),
		LockedUntil:      Reference.Add(time.Hour),
		LastAcceptedStep: 1000,
	}
}

func assertTOTPEqual(t *testing.T, got, want *store.TOTPRecord) {
	t.Helper()
	if got.Subject != want.Subject {
		t.Fatalf("Subject = %q, want %q", got.Subject, want.Subject)
	}
	if !bytes.Equal(got.SecretCiphertext, want.SecretCiphertext) {
		t.Fatalf("SecretCiphertext = %x, want %x", got.SecretCiphertext, want.SecretCiphertext)
	}
	if !got.ConfirmedAt.Equal(want.ConfirmedAt) {
		t.Fatalf("ConfirmedAt = %v, want %v", got.ConfirmedAt, want.ConfirmedAt)
	}
	if got.FailedCount != want.FailedCount {
		t.Fatalf("FailedCount = %d, want %d", got.FailedCount, want.FailedCount)
	}
	if !got.FirstFailureAt.Equal(want.FirstFailureAt) {
		t.Fatalf("FirstFailureAt = %v, want %v", got.FirstFailureAt, want.FirstFailureAt)
	}
	if !got.LockedUntil.Equal(want.LockedUntil) {
		t.Fatalf("LockedUntil = %v, want %v", got.LockedUntil, want.LockedUntil)
	}
	if got.LastAcceptedStep != want.LastAcceptedStep {
		t.Fatalf("LastAcceptedStep = %d, want %d", got.LastAcceptedStep, want.LastAcceptedStep)
	}
}
