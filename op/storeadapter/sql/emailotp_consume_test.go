package oidcsql_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

// The e-mail OTP challenge is single-use on the same terms a recovery
// slot is, and its redemption statement carries the same "consumed_at =
// 0" predicate. The row-version rotation the statement also performs
// hides the engine disagreement — the row always changes, so every
// engine counts it — but it does not supply the stamp: a Consume handed
// a record with a zero ConsumedAt still writes zero back and still
// reports success, leaving the challenge consumable by anyone who
// re-reads it.
//
// Fixing one substore and not the other is how this shape comes back,
// so the post-condition is pinned on both.

// assertEmailOTPConsumeStampsRecord pins the post-condition: a nil
// Consume leaves the stored record with a non-zero ConsumedAt, whether
// or not the presented record carried one.
func assertEmailOTPConsumeStampsRecord(t *testing.T, otp store.EmailOTPStore) {
	ctx := context.Background()
	const subject = "emailotp-unstamped-subject"
	if err := otp.Put(ctx, &store.EmailOTPRecord{
		Subject:     subject,
		CodeSalt:    []byte{0x11, 0x22},
		CodeHash:    []byte{0x33, 0x44},
		SentAt:      contract.Reference,
		ExpiresAt:   contract.Reference.Add(time.Hour),
		RetainUntil: contract.Reference.Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	held, err := otp.Get(ctx, subject)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !held.ConsumedAt.IsZero() {
		t.Fatalf("fixture arrived pre-stamped (%v); the unstamped path is not under test", held.ConsumedAt)
	}
	// Redeem the challenge exactly as it arrived. The library's verifier
	// stamps it first, but the interface does not require a caller to,
	// and this is the path that decides whether the code survives its
	// own redemption.
	if err := otp.Consume(ctx, held); err != nil {
		t.Fatalf("Consume of an unstamped record: %v", err)
	}

	stored, err := otp.Get(ctx, subject)
	if err != nil {
		t.Fatalf("Get after Consume: %v", err)
	}
	if stored.ConsumedAt.IsZero() {
		t.Errorf("Consume returned nil but the stored record is still unconsumed; " +
			"the challenge remains redeemable and the caller was told it was spent")
	}

	// The property a user cares about: nobody can redeem it again, even
	// after re-reading the record to pick up the rotated version.
	replay, err := otp.Get(ctx, subject)
	if err != nil {
		t.Fatalf("Get for replay: %v", err)
	}
	replay.ConsumedAt = time.Time{}
	if err := otp.Consume(ctx, replay); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Errorf("second Consume of the same challenge = %v, want ErrAlreadyConsumed", err)
	}
}

// assertEmailOTPConsumeKeepsCallerStamp pins the other half: a record
// the caller stamped keeps that exact instant.
func assertEmailOTPConsumeKeepsCallerStamp(t *testing.T, otp store.EmailOTPStore) {
	ctx := context.Background()
	const subject = "emailotp-stamped-subject"
	stamp := contract.Reference.Add(30 * time.Minute)
	if err := otp.Put(ctx, &store.EmailOTPRecord{
		Subject:     subject,
		CodeSalt:    []byte{0x55},
		CodeHash:    []byte{0x66},
		SentAt:      contract.Reference,
		ExpiresAt:   contract.Reference.Add(time.Hour),
		RetainUntil: contract.Reference.Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	held, err := otp.Get(ctx, subject)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	held.ConsumedAt = stamp
	if err := otp.Consume(ctx, held); err != nil {
		t.Fatalf("Consume of a stamped record: %v", err)
	}
	stored, err := otp.Get(ctx, subject)
	if err != nil {
		t.Fatalf("Get after Consume: %v", err)
	}
	if !stored.ConsumedAt.Equal(stamp) {
		t.Errorf("stored ConsumedAt = %v, want the caller's %v", stored.ConsumedAt, stamp)
	}
}

// runEmailOTPConsumeStampContracts is the per-engine entry point.
func runEmailOTPConsumeStampContracts(t *testing.T, f contract.Factory) {
	t.Helper()

	otps := func(t *testing.T) store.EmailOTPStore {
		t.Helper()
		s, ok := f(t).Store.(*oidcsql.Store)
		if !ok {
			t.Fatal("factory produced a store that is not the SQL adapter")
		}
		return s.EmailOTPs()
	}

	t.Run("UnstampedRecordIsStamped", func(t *testing.T) {
		t.Parallel()
		assertEmailOTPConsumeStampsRecord(t, otps(t))
	})
	t.Run("CallerStampIsKept", func(t *testing.T) {
		t.Parallel()
		assertEmailOTPConsumeKeepsCallerStamp(t, otps(t))
	})
}

func TestSQLite_EmailOTPConsumeStamp(t *testing.T) {
	t.Parallel()
	runEmailOTPConsumeStampContracts(t, newSQLiteFactory(t))
}
