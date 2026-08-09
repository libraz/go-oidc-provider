//go:build testcontainers

package oidcdynamo_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
	oidcdynamo "github.com/libraz/go-oidc-provider/op/storeadapter/dynamodb"
)

// The contract harness pins the concurrency guarantees every backend
// owes. The cases here pin the ones that only exist because DynamoDB has
// neither a row lock nor a unique index, so a lost update or a duplicate
// identifier would be an adapter defect rather than a contract gap.

// raceAttempts is the number of goroutines these cases drive an operation
// from. Each attempt is a transaction against one item, so the number is
// kept modest: the property under test is what the table holds
// afterwards, not how much contention the emulator absorbs.
const raceAttempts = 6

// race runs attempt from every racer and returns the errors in launch
// order.
func race(attempt func(i int) error) []error {
	errs := make([]error, raceAttempts)
	var wg sync.WaitGroup
	wg.Add(raceAttempts)
	for i := range raceAttempts {
		go func() {
			defer wg.Done()
			errs[i] = attempt(i)
		}()
	}
	wg.Wait()
	return errs
}

// TestGrant_ConcurrentTransactionsKeepEveryAmendment pins the version
// guard grant writes carry.
//
// A grant is amended rather than replaced: a repeat authorization for
// the same (subject, client) pair adds scopes, authorization details,
// and a fresh authentication context to what the grant already holds. A
// relational backend holds a row lock from the read to the write;
// DynamoDB has none, so the staged write asserts instead that the
// version it amended is still stored.
//
// Without the guard two authorizations completing together would each
// write what they read, and the later commit would silently drop the
// scope the earlier one had just granted — the user would consent, see
// success, and hold a grant that never records it.
func TestGrant_ConcurrentTransactionsKeepEveryAmendment(t *testing.T) {
	t.Parallel()

	s := newIsolatedStore(t, "grantamend_")
	ctx := t.Context()
	if err := s.Grants().Save(ctx, &store.Grant{
		ID:        "g-amend",
		Subject:   "sub-amend",
		ClientID:  "client-amend",
		Scope:     []string{"openid"},
		CreatedAt: contract.Reference,
		UpdatedAt: contract.Reference,
	}); err != nil {
		t.Fatalf("Save base grant: %v", err)
	}

	added := func(i int) string { return fmt.Sprintf("scope-%d", i) }
	errs := race(func(i int) error { return amendGrant(ctx, s, "g-amend", added(i)) })

	// A rejected amendment reports a conflict; its shape is the backend's
	// business. What matters is that it left no trace, so the surviving
	// grant carries the scopes of the amendments that succeeded and
	// nothing else.
	want := []string{"openid"}
	for i, err := range errs {
		if err == nil {
			want = append(want, added(i))
		}
	}
	if len(want) == 1 {
		t.Fatalf("every concurrent amendment was rejected, none made progress: %v", errs)
	}

	got, err := s.Grants().Find(ctx, "g-amend")
	if err != nil {
		t.Fatalf("Find after the race: %v", err)
	}
	slices.Sort(want)
	scope := slices.Clone(got.Scope)
	slices.Sort(scope)
	if !slices.Equal(scope, want) {
		t.Errorf("grant scope = %v, want %v (%d of %d amendments committed)",
			scope, want, len(want)-1, raceAttempts)
	}
}

// amendGrant runs one read-amend-write cycle the way the authorize
// endpoint does: inside a transaction the caller owns.
func amendGrant(ctx context.Context, s *oidcdynamo.Store, id, scope string) error {
	tx, err := s.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	g, err := tx.Grants().Find(ctx, id)
	if err != nil {
		return err
	}
	g.Scope = append(g.Scope, scope)
	g.UpdatedAt = contract.Reference
	if err := tx.Grants().Save(ctx, g); err != nil {
		return err
	}
	return tx.Commit()
}

// TestDeviceCode_ConcurrentSaveClaimsOneUserCode pins the user_code
// reservation.
//
// The user_code is what the human reads aloud on the verification page,
// so two live records carrying one code would make approval
// non-deterministic: the page would approve whichever record it
// resolved, and the other device would poll until it expired. DynamoDB
// cannot express the constraint on an index, so the code is claimed as
// an item and the claim is what two simultaneous device authorization
// requests contend for.
func TestDeviceCode_ConcurrentSaveClaimsOneUserCode(t *testing.T) {
	t.Parallel()

	s := newIsolatedStore(t, "dcclaim_")
	ctx := t.Context()
	codes := s.DeviceCodes()

	const userCode = "CCCC-0001"
	deviceCode := func(i int) string { return fmt.Sprintf("dc-claim-%d", i) }
	errs := race(func(i int) error {
		return codes.Save(ctx, &store.DeviceCode{
			ID:        deviceCode(i),
			ClientID:  "client-claim",
			UserCode:  userCode,
			Scope:     []string{"openid"},
			Interval:  5 * time.Second,
			Status:    store.DeviceCodeStatusPending,
			IssuedAt:  contract.Reference,
			ExpiresAt: contract.Reference.Add(time.Hour),
		})
	})

	winner := -1
	for i, err := range errs {
		switch {
		case err == nil:
			if winner >= 0 {
				t.Fatalf("user_code %q was claimed twice: by %s and %s",
					userCode, deviceCode(winner), deviceCode(i))
			}
			winner = i
		case errors.Is(err, store.ErrAlreadyExists):
		default:
			t.Fatalf("Save %s: want ErrAlreadyExists, got %v", deviceCode(i), err)
		}
	}
	if winner < 0 {
		t.Fatalf("no request claimed the user_code: %v", errs)
	}

	// A rejected Save leaves nothing behind: its record is absent, so the
	// device that lost is told to stop rather than polling a row nobody
	// can approve.
	for i := range raceAttempts {
		if i == winner {
			continue
		}
		if _, err := codes.FindByDeviceCode(ctx, deviceCode(i)); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("FindByDeviceCode(%s) after a rejected Save = %v, want ErrNotFound", deviceCode(i), err)
		}
	}

	// The verification page resolves the code, and the approval lands on
	// the record that claimed it.
	if err := codes.ApproveByUserCode(ctx, userCode, "sub-claim", contract.Reference); err != nil {
		t.Fatalf("ApproveByUserCode: %v", err)
	}
	got, err := codes.FindByDeviceCode(ctx, deviceCode(winner))
	if err != nil {
		t.Fatalf("FindByDeviceCode(%s): %v", deviceCode(winner), err)
	}
	if got.Status != store.DeviceCodeStatusApproved || got.Subject != "sub-claim" {
		t.Errorf("winning record after ApproveByUserCode = %+v, want an approved record for sub-claim", got)
	}
}

// TestEmailOTP_ConcurrentFirstSendReservesOnce pins the reservation the
// email-OTP send step makes before it hands a code to the mailer.
//
// The reservation is the ceiling on how many messages a subject can be
// sent: every send after the first compares against the stored
// challenge and is refused while it is live. If two first sends can
// both land, both deliver a message and the winner's counters replace
// the loser's, so the ceiling counts one send where two happened. The
// nil-previous compare-and-swap therefore has to be a conditional write
// rather than a read followed by a put.
func TestEmailOTP_ConcurrentFirstSendReservesOnce(t *testing.T) {
	t.Parallel()

	s := newIsolatedStore(t, "otpreserve_")
	ctx := t.Context()
	otps := s.EmailOTPs()

	const subject = "sub-otp-race"
	material := func(i int) []byte { return []byte{byte(i), 0xAB} }
	errs := race(func(i int) error {
		return otps.CompareAndSwap(ctx, nil, &store.EmailOTPRecord{
			Subject:           subject,
			CodeSalt:          material(i),
			CodeHash:          material(i),
			SentAt:            contract.Reference,
			ExpiresAt:         contract.Reference.Add(5 * time.Minute),
			RetainUntil:       contract.Reference.Add(24 * time.Hour),
			SendCount:         1,
			SendWindowStart:   contract.Reference,
			LastSendAttemptAt: contract.Reference,
		})
	})

	winner := -1
	for i, err := range errs {
		switch {
		case err == nil:
			if winner >= 0 {
				t.Fatalf("two first sends both reserved the challenge: racer %d and racer %d", winner, i)
			}
			winner = i
		case errors.Is(err, store.ErrAlreadyConsumed):
		default:
			t.Fatalf("CompareAndSwap racer %d: want ErrAlreadyConsumed, got %v", i, err)
		}
	}
	if winner < 0 {
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

// TestUser_ConcurrentSeedClaimsOneUsername pins the username
// reservation the directory seed helper writes. Two entries sharing a
// username would make the password ceremony resolve to whichever the
// index surfaced, so one enrolment must win and the other must leave no
// directory entry at all.
func TestUser_ConcurrentSeedClaimsOneUsername(t *testing.T) {
	t.Parallel()

	s := newIsolatedStore(t, "userclaim_")
	ctx := t.Context()

	const username = "shared@example.com"
	subject := func(i int) string { return fmt.Sprintf("sub-claim-%d", i) }
	errs := race(func(i int) error {
		return s.PutUserWithPassword(ctx,
			&store.User{
				Subject:   subject(i),
				Claims:    map[string]any{"name": subject(i)},
				UpdatedAt: contract.Reference,
			},
			username,
			[]byte(fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$hash%d", i)),
		)
	})

	winner := -1
	for i, err := range errs {
		switch {
		case err == nil:
			if winner >= 0 {
				t.Fatalf("username %q was claimed twice: by %s and %s", username, subject(winner), subject(i))
			}
			winner = i
		case errors.Is(err, store.ErrAlreadyExists):
		default:
			t.Fatalf("PutUserWithPassword %s: want ErrAlreadyExists, got %v", subject(i), err)
		}
	}
	if winner < 0 {
		t.Fatalf("no enrolment claimed the username: %v", errs)
	}

	found, err := s.UserPasswords().FindByUsername(ctx, username)
	if err != nil {
		t.Fatalf("FindByUsername: %v", err)
	}
	if found.Subject != subject(winner) {
		t.Errorf("FindByUsername resolved to %q, want the subject that claimed it (%q)",
			found.Subject, subject(winner))
	}
	for i := range raceAttempts {
		if i == winner {
			continue
		}
		if _, err := s.Users().FindBySubject(ctx, subject(i)); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("FindBySubject(%s) after a rejected enrolment = %v, want ErrNotFound", subject(i), err)
		}
	}
}
