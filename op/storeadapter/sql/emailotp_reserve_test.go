package oidcsql_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

// emailOTPRacers is how many first sends contend for the reservation.
// The property under test is what the table holds afterwards, not how
// much contention the engine absorbs, so the number stays small.
//
// It is a byte because each racer's index doubles as the first byte of
// the material it presents, which keeps the contenders distinguishable
// without a conversion that could wrap.
const emailOTPRacers byte = 4

// reserveFirstSend drives the nil-previous compare-and-swap the send
// step uses to reserve a subject's first challenge.
func reserveFirstSend(ctx context.Context, otps store.EmailOTPStore, subject string, material []byte, now time.Time) error {
	return otps.CompareAndSwap(ctx, nil, &store.EmailOTPRecord{
		Subject:           subject,
		CodeSalt:          material,
		CodeHash:          material,
		SentAt:            now,
		ExpiresAt:         now.Add(5 * time.Minute),
		RetainUntil:       now.Add(24 * time.Hour),
		SendCount:         1,
		SendWindowStart:   now,
		LastSendAttemptAt: now,
	})
}

// TestSQLite_EmailOTPFirstSendReservesOnce pins the reservation the
// email-OTP send step makes before it hands a code to the mailer.
//
// The reservation is the ceiling on how many messages a subject can be
// sent: every later send compares against the stored challenge and is
// refused while it is live. If two first sends can both land, both
// deliver a message and the winner's counters replace the loser's, so
// the ceiling counts one send where two happened. A read followed by an
// upsert cannot hold that line; the write has to carry the condition.
func TestSQLite_EmailOTPFirstSendReservesOnce(t *testing.T) {
	t.Parallel()

	b := newSQLiteFactory(t)(t)
	s, ok := b.Store.(*oidcsql.Store)
	if !ok {
		t.Fatalf("factory produced %T, want *oidcsql.Store", b.Store)
	}
	otps := s.EmailOTPs()
	ctx := context.Background()
	now := b.Now()

	const subject = "sub-otp-race"
	// Indexed by racer so each contender presents distinct material;
	// the parameter is a byte so the identity cannot silently collide
	// past 255 if the racer count ever grows.
	material := func(i byte) []byte { return []byte{i, 0xAB} }

	errs := make([]error, emailOTPRacers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range emailOTPRacers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = reserveFirstSend(ctx, otps, subject, material(i), now)
		}()
	}
	close(start)
	wg.Wait()

	var (
		winner byte
		found  bool
	)
	for i, err := range errs {
		racer := byte(i)
		switch {
		case err == nil:
			if found {
				t.Fatalf("two first sends both reserved the challenge: racer %d and racer %d", winner, racer)
			}
			winner, found = racer, true
		case errors.Is(err, store.ErrAlreadyConsumed):
		default:
			t.Fatalf("CompareAndSwap racer %d: want ErrAlreadyConsumed, got %v", racer, err)
		}
	}
	if !found {
		t.Fatalf("no send reserved the challenge: %v", errs)
	}

	// The stored challenge is the winner's, so the code the user was
	// sent is the code the verify step will check.
	stored, err := otps.Get(ctx, subject)
	if err != nil {
		t.Fatalf("Get after the race: %v", err)
	}
	if !slices.Equal(stored.CodeHash, material(winner)) {
		t.Errorf("stored CodeHash = %v, want the material racer %d reserved with", stored.CodeHash, winner)
	}
	if stored.SendCount != 1 {
		t.Errorf("stored SendCount = %d, want 1: a losing send left its bookkeeping behind", stored.SendCount)
	}
}

// TestSQLite_EmailOTPReservationYieldsAfterRetention pins the other
// half of the conditional write: once the retained record has fallen
// out of its window the key is free again, so a subject who returns
// tomorrow can still be sent a code. Refusing there would lock the
// factor out for good.
func TestSQLite_EmailOTPReservationYieldsAfterRetention(t *testing.T) {
	t.Parallel()

	b := newSQLiteFactory(t)(t)
	s, ok := b.Store.(*oidcsql.Store)
	if !ok {
		t.Fatalf("factory produced %T, want *oidcsql.Store", b.Store)
	}
	otps := s.EmailOTPs()
	ctx := context.Background()

	const subject = "sub-otp-retention"
	first := []byte{0x01, 0xAB}
	if err := reserveFirstSend(ctx, otps, subject, first, b.Now()); err != nil {
		t.Fatalf("first reservation: %v", err)
	}
	// While the record is retained the key is held.
	if err := reserveFirstSend(ctx, otps, subject, []byte{0x02, 0xAB}, b.Now()); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("reservation against a live record: err=%v want ErrAlreadyConsumed", err)
	}

	b.Advance(25 * time.Hour)
	second := []byte{0x03, 0xAB}
	if err := reserveFirstSend(ctx, otps, subject, second, b.Now()); err != nil {
		t.Fatalf("reservation after the retention horizon: %v", err)
	}
	stored, err := otps.Get(ctx, subject)
	if err != nil {
		t.Fatalf("Get after the replacement: %v", err)
	}
	if !slices.Equal(stored.CodeHash, second) {
		t.Errorf("stored CodeHash = %v, want the replacement's material", stored.CodeHash)
	}
}
