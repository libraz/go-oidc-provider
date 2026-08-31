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

// TOTPBackend bundles a freshly constructed [store.TOTPStore] with the
// hooks a backend supplies to reach states its own API cannot produce.
// TOTP enrolments are intentionally separate from [Backend] because they
// are supplied directly to the TOTP step rather than through the
// aggregate [store.Store].
type TOTPBackend struct {
	// Store is the substore under test.
	Store store.TOTPStore

	// Diverge rewrites the stored enrolment for subject out of band: it
	// moves at least one value a caller can read back while leaving the
	// record's Version untouched, the way a writer that bypassed the
	// store would. Backends that can reach their storage directly
	// provide it so the contract can separate a compare-and-swap that
	// matches the whole record from one that matches Version alone.
	// Nothing else in the suite separates the two, because Put,
	// CompareAndSwap and Accept all stamp a fresh Version whenever they
	// change a value. Nil skips only that case.
	Diverge func(t *testing.T, subject string)
}

// TOTPFactory builds a fresh standalone TOTP backend for a single
// contract sub-test.
type TOTPFactory func(t *testing.T) TOTPBackend

// RunTOTPs exercises the round-trip, compare-and-swap, and single-use
// acceptance guarantees of [store.TOTPStore]. Adapter authors should call
// it from their black-box test suite in addition to any backend-specific
// tests.
func RunTOTPs(t *testing.T, f TOTPFactory) {
	t.Helper()

	cases := []struct {
		name string
		run  func(*testing.T, TOTPBackend)
	}{
		{"Missing", totpMissing},
		{"PutGetRoundTrip", totpRoundTrip},
		{"PutReplacesEnrolment", totpPutReplaces},
		{"CompareAndSwapAppliesNext", totpCASApplies},
		{"CompareAndSwapStaleSnapshotRejected", totpCASStale},
		{"CompareAndSwapRejectsVersionEqualDivergedRecord", totpCASDiverged},
		{"CompareAndSwapRejectsInvalidVersion", totpCASInvalidVersion},
		{"CompareAndSwapIdenticalHasOneWinner", totpCASIdentical},
		{"AcceptAdvancesStep", totpAcceptAdvances},
		{"AcceptRejectsReplayedStep", totpAcceptReplay},
		{"AcceptRejectsEarlierStep", totpAcceptEarlier},
		{"AcceptRejectsStaleEnrollment", totpAcceptStaleEnrollment},
		{"AcceptRejectsInvalidVersion", totpAcceptInvalidVersion},
		{"DeleteRemovesEnrolment", totpDelete},
		{"DeleteRecreateRejectsStaleSnapshot", totpDeleteRecreateRejectsStaleSnapshot},
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

func totpMissing(t *testing.T, b TOTPBackend) {
	t.Helper()
	s := b.Store
	if _, err := s.Get(context.Background(), "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get(missing) error = %v, want ErrNotFound", err)
	}
}

func totpRoundTrip(t *testing.T, b TOTPBackend) {
	t.Helper()
	s := b.Store
	ctx := context.Background()
	want := totpContractRecord()
	if err := s.Put(ctx, want); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get(ctx, want.Subject)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !validTOTPVersion(got.Version) {
		t.Fatalf("Put assigned invalid Version %d", got.Version)
	}
	if want.Version != 0 {
		t.Fatalf("Put mutated caller Version = %d", want.Version)
	}
	want.Version = got.Version
	assertTOTPEqual(t, got, want)
}

func totpPutReplaces(t *testing.T, b TOTPBackend) {
	t.Helper()
	s := b.Store
	ctx := context.Background()
	first := totpContractRecord()
	if err := s.Put(ctx, first); err != nil {
		t.Fatalf("Put first: %v", err)
	}
	firstStored, err := s.Get(ctx, first.Subject)
	if err != nil {
		t.Fatalf("Get first: %v", err)
	}
	second := totpContractRecord()
	second.Version = math.MaxInt64
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
	if second.Version != math.MaxInt64 {
		t.Fatalf("Put mutated caller Version = %d", second.Version)
	}
	assertTOTPVersionChanged(t, firstStored.Version, got.Version)
	second.Version = got.Version
	assertTOTPEqual(t, got, second)
}

func totpCASApplies(t *testing.T, b TOTPBackend) {
	t.Helper()
	s := b.Store
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
	next.Version = previous.Version
	next.FailedCount = previous.FailedCount + 1
	next.FirstFailureAt = Reference.Add(-time.Minute)
	previousBefore, nextBefore := cloneContractTOTP(previous), cloneContractTOTP(&next)
	if err := s.CompareAndSwap(ctx, previous, &next); err != nil {
		t.Fatalf("CompareAndSwap: %v", err)
	}
	assertContractTOTPUnchanged(t, "CAS previous", previous, previousBefore)
	assertContractTOTPUnchanged(t, "CAS next", &next, nextBefore)

	got, err := s.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get after swap: %v", err)
	}
	expected := next
	expected.Version = got.Version
	assertTOTPVersionChanged(t, previous.Version, got.Version)
	assertTOTPEqual(t, got, &expected)
}

func totpCASStale(t *testing.T, b TOTPBackend) {
	t.Helper()
	s := b.Store
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
	winner.Version = stale.Version
	winner.FailedCount = stale.FailedCount + 1
	staleBefore, winnerBefore := cloneContractTOTP(stale), cloneContractTOTP(&winner)
	if err := s.CompareAndSwap(ctx, stale, &winner); err != nil {
		t.Fatalf("CompareAndSwap winner: %v", err)
	}
	assertContractTOTPUnchanged(t, "winner previous", stale, staleBefore)
	assertContractTOTPUnchanged(t, "winner next", &winner, winnerBefore)

	// The stale snapshot no longer describes the stored record, so the
	// second transition must be refused rather than rolling the counter
	// back over the winner.
	loser := *stale
	loser.FailedCount = 99
	loser.LockedUntil = Reference.Add(24 * time.Hour)
	loserBefore := cloneContractTOTP(&loser)
	if err := s.CompareAndSwap(ctx, stale, &loser); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("CompareAndSwap stale error = %v, want ErrAlreadyConsumed", err)
	}
	assertContractTOTPUnchanged(t, "rejected next", &loser, loserBefore)

	got, err := s.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get after rejected swap: %v", err)
	}
	expected := winner
	expected.Version = got.Version
	assertTOTPVersionChanged(t, stale.Version, got.Version)
	assertTOTPEqual(t, got, &expected)
}

// totpCASDiverged pins the precondition [store.TOTPStore.CompareAndSwap]
// states: the stored enrolment has to equal previous field for field, not
// merely carry the same Version.
//
// Every other case here is blind to the difference, because the store's
// own writes stamp a fresh Version whenever they move a value, so
// "Version matches" and "the record matches" agree on all of them. They
// disagree only where a writer outside the store moved a value and left
// the Version behind, which is what [TOTPBackend.Diverge] produces. A
// backend that gated on Version alone would apply the swap there,
// overwriting an enrolment the caller never read — erasing, on its next
// read, whatever failure counter or lock its own write buried.
func totpCASDiverged(t *testing.T, b TOTPBackend) {
	t.Helper()
	if b.Diverge == nil {
		t.Skip("backend supplies no Diverge hook: the Version-equal, value-different record needs an out-of-band write")
	}
	s := b.Store
	ctx := context.Background()
	seed := totpContractRecord()
	if err := s.Put(ctx, seed); err != nil {
		t.Fatalf("Put: %v", err)
	}
	previous, err := s.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get seed: %v", err)
	}

	b.Diverge(t, seed.Subject)
	diverged, err := s.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get after the out-of-band write: %v", err)
	}
	if diverged.Version != previous.Version {
		t.Fatalf("Diverge moved Version to %d; it has to stay at %d for this case to exist",
			diverged.Version, previous.Version)
	}
	if reflect.DeepEqual(diverged, previous) {
		t.Fatalf("Diverge left the record unchanged: %+v", diverged)
	}

	next := *previous
	next.LockedUntil = Reference.Add(24 * time.Hour)
	if err := s.CompareAndSwap(ctx, previous, &next); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("CompareAndSwap on a Version-equal, value-different record = %v, want ErrAlreadyConsumed", err)
	}

	after, err := s.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get after the refused swap: %v", err)
	}
	assertTOTPEqual(t, after, diverged)
}

func totpCASInvalidVersion(t *testing.T, b TOTPBackend) {
	t.Helper()
	s := b.Store
	ctx := context.Background()
	seed := totpContractRecord()
	if err := s.Put(ctx, seed); err != nil {
		t.Fatalf("Put: %v", err)
	}
	previous, err := s.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get seed: %v", err)
	}

	unequal := *previous
	unequal.Version++
	if err := s.CompareAndSwap(ctx, previous, &unequal); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("CompareAndSwap unequal Version = %v, want ErrAlreadyConsumed", err)
	}

	maxed := *previous
	maxed.Version = math.MaxInt64
	if err := s.CompareAndSwap(ctx, &maxed, &maxed); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("CompareAndSwap signed-max Version = %v, want ErrAlreadyConsumed", err)
	}
}

func totpCASIdentical(t *testing.T, b TOTPBackend) {
	t.Helper()
	s := b.Store
	ctx := context.Background()
	seed := totpContractRecord()
	if err := s.Put(ctx, seed); err != nil {
		t.Fatalf("Put: %v", err)
	}
	previous, err := s.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get seed: %v", err)
	}

	ready := make(chan struct{}, 2)
	release := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		next := *previous
		next.SecretCiphertext = bytes.Clone(previous.SecretCiphertext)
		wg.Add(1)
		go func() {
			defer wg.Done()
			ready <- struct{}{}
			<-release
			errs <- s.CompareAndSwap(ctx, previous, &next)
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
	got, err := s.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get after identical CAS: %v", err)
	}
	assertTOTPVersionChanged(t, previous.Version, got.Version)
}

func totpAcceptAdvances(t *testing.T, b TOTPBackend) {
	t.Helper()
	s := b.Store
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
	success.Version = current.Version
	success.LastAcceptedStep = current.LastAcceptedStep + 1
	success.FailedCount = 0
	success.FirstFailureAt = time.Time{}
	successBefore := cloneContractTOTP(&success)
	if err := s.Accept(ctx, &success); err != nil {
		t.Fatalf("Accept: %v", err)
	}
	assertContractTOTPUnchanged(t, "Accept input", &success, successBefore)

	got, err := s.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get after accept: %v", err)
	}
	expected := success
	expected.Version = got.Version
	assertTOTPVersionChanged(t, current.Version, got.Version)
	assertTOTPEqual(t, got, &expected)
}

func totpAcceptReplay(t *testing.T, b TOTPBackend) {
	t.Helper()
	s := b.Store
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
	first.Version = current.Version
	first.LastAcceptedStep = current.LastAcceptedStep + 1
	if err := s.Accept(ctx, &first); err != nil {
		t.Fatalf("Accept first: %v", err)
	}

	// Same step replayed inside the 30-second window: the second
	// redemption must lose.
	replay := first
	replay.FailedCount = 42
	replayBefore := cloneContractTOTP(&replay)
	if err := s.Accept(ctx, &replay); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("Accept replay error = %v, want ErrAlreadyConsumed", err)
	}
	assertContractTOTPUnchanged(t, "rejected Accept input", &replay, replayBefore)

	got, err := s.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get after replay: %v", err)
	}
	expected := first
	expected.Version = got.Version
	assertTOTPVersionChanged(t, current.Version, got.Version)
	assertTOTPEqual(t, got, &expected)
}

func totpAcceptEarlier(t *testing.T, b TOTPBackend) {
	t.Helper()
	s := b.Store
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
	if got.LastAcceptedStep != 100 || got.Version != current.Version {
		t.Fatalf("rejected Accept changed state: %+v", got)
	}
}

func totpAcceptStaleEnrollment(t *testing.T, b TOTPBackend) {
	t.Helper()
	s := b.Store
	ctx := context.Background()
	old := totpContractRecord()
	old.Subject = "enrollment-subject"
	if err := s.Put(ctx, old); err != nil {
		t.Fatalf("Put old enrollment: %v", err)
	}
	stale, err := s.Get(ctx, old.Subject)
	if err != nil {
		t.Fatalf("Get stale enrollment: %v", err)
	}

	newer := *old
	newer.SecretCiphertext = []byte{0xa1, 0xb2, 0xc3, 0xd4}
	newer.ConfirmedAt = old.ConfirmedAt.Add(time.Minute)
	newer.LastAcceptedStep = 7
	if err := s.Put(ctx, &newer); err != nil {
		t.Fatalf("Put newer enrollment: %v", err)
	}
	newerStored, err := s.Get(ctx, newer.Subject)
	if err != nil {
		t.Fatalf("Get newer enrollment: %v", err)
	}

	stale.LastAcceptedStep = newer.LastAcceptedStep + 100
	if err := s.Accept(ctx, stale); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("Accept stale enrollment = %v, want ErrAlreadyConsumed", err)
	}
	got, err := s.Get(ctx, newer.Subject)
	if err != nil {
		t.Fatalf("Get after stale Accept: %v", err)
	}
	assertTOTPEqual(t, got, newerStored)
}

func totpAcceptInvalidVersion(t *testing.T, b TOTPBackend) {
	t.Helper()
	s := b.Store
	ctx := context.Background()
	seed := totpContractRecord()
	if err := s.Put(ctx, seed); err != nil {
		t.Fatalf("Put: %v", err)
	}
	current, err := s.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get seed: %v", err)
	}
	current.Version = math.MaxInt64
	current.LastAcceptedStep++
	currentBefore := cloneContractTOTP(current)
	if err := s.Accept(ctx, current); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("Accept signed-max Version = %v, want ErrAlreadyConsumed", err)
	}
	assertContractTOTPUnchanged(t, "invalid Accept input", current, currentBefore)
}

func totpDelete(t *testing.T, b TOTPBackend) {
	t.Helper()
	s := b.Store
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

func totpDeleteMissing(t *testing.T, b TOTPBackend) {
	t.Helper()
	s := b.Store
	if err := s.Delete(context.Background(), "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Delete(missing) error = %v, want ErrNotFound", err)
	}
}

func totpDefensiveCopies(t *testing.T, b TOTPBackend) {
	t.Helper()
	s := b.Store
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

func totpConcurrentCAS(t *testing.T, b TOTPBackend) {
	t.Helper()
	s := b.Store
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
		t.Fatalf("final record = %+v, want one candidate count", got)
	}
	assertTOTPVersionChanged(t, current.Version, got.Version)
}

func totpDeleteRecreateRejectsStaleSnapshot(t *testing.T, b TOTPBackend) {
	t.Helper()
	s := b.Store
	ctx := context.Background()
	seed := totpContractRecord()
	if err := s.Put(ctx, seed); err != nil {
		t.Fatalf("Put seed: %v", err)
	}
	stale, err := s.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get stale: %v", err)
	}
	if err := s.Delete(ctx, seed.Subject); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	// Keep the document byte-for-byte equivalent to exercise the opaque
	// token, not merely a document mismatch, as the ABA defence.
	fresh := *seed
	fresh.SecretCiphertext = bytes.Clone(seed.SecretCiphertext)
	if err := s.Put(ctx, &fresh); err != nil {
		t.Fatalf("Put recreated record: %v", err)
	}
	recreated, err := s.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get recreated record: %v", err)
	}
	assertTOTPVersionChanged(t, stale.Version, recreated.Version)

	staleNext := *stale
	staleNext.FailedCount++
	if err := s.CompareAndSwap(ctx, stale, &staleNext); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("stale CAS after same-value recreate = %v, want ErrAlreadyConsumed", err)
	}
	staleAccept := *stale
	staleAccept.LastAcceptedStep = recreated.LastAcceptedStep + 1
	if err := s.Accept(ctx, &staleAccept); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("stale Accept after same-value recreate = %v, want ErrAlreadyConsumed", err)
	}
	got, err := s.Get(ctx, seed.Subject)
	if err != nil {
		t.Fatalf("Get after stale transitions: %v", err)
	}
	assertTOTPEqual(t, got, recreated)
}

func assertTOTPVersionChanged(t *testing.T, previous, current uint64) {
	t.Helper()
	if !validTOTPVersion(current) || (previous != 0 && previous == current) {
		t.Fatalf("Version did not change to a valid opaque token: previous=%d current=%d", previous, current)
	}
}

func validTOTPVersion(version uint64) bool {
	return version > 0 && version < uint64(math.MaxInt64)
}

func cloneContractTOTP(r *store.TOTPRecord) *store.TOTPRecord {
	if r == nil {
		return nil
	}
	out := *r
	out.SecretCiphertext = bytes.Clone(r.SecretCiphertext)
	return &out
}

func assertContractTOTPUnchanged(t *testing.T, label string, got, want *store.TOTPRecord) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s mutated caller record: got=%+v want=%+v", label, got, want)
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
	if got.Version != want.Version {
		t.Fatalf("Version = %d, want %d", got.Version, want.Version)
	}
}
