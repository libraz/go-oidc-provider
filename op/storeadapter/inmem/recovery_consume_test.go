package inmem_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// consumeStampClock pins the store to a known instant so the stamp the
// reference implementation applies is checkable rather than merely
// non-zero.
type consumeStampClock struct{ now time.Time }

func (c consumeStampClock) Now() time.Time { return c.now }

// TestRecoveryStore_ConsumeStampsUnstampedSlot pins the single-use
// post-condition on the reference implementation: a nil Consume leaves
// the stored slot with a non-zero ConsumedAt whether or not the caller
// stamped it, so the code cannot be redeemed twice.
//
// Copying the presented value through would report success while
// leaving the slot exactly as available as before. Every backend is
// read against this implementation, so the shape it takes here is the
// shape the SQL and DynamoDB adapters are expected to match.
func TestRecoveryStore_ConsumeStampsUnstampedSlot(t *testing.T) {
	t.Parallel()

	clock := consumeStampClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	s := inmem.New(inmem.WithClock(clock))
	recovery := s.RecoveryCodes()
	ctx := context.Background()
	const subject = "recovery-unstamped-subject"

	if err := recovery.Put(ctx, &store.RecoveryBatch{
		Subject:     subject,
		GeneratedAt: clock.now,
		Codes: []store.RecoveryCode{
			{Hash: "$argon2id$v=19$m=65536,t=3,p=2$c2FsdC1vbmU$aGFzaC1vbmU"},
			{Hash: "$argon2id$v=19$m=65536,t=3,p=2$c2FsdC10d28$aGFzaC10d28"},
		},
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	held, err := recovery.Get(ctx, subject)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !held.Codes[0].ConsumedAt.IsZero() {
		t.Fatalf("fixture slot arrived pre-stamped (%v); the unstamped path is not under test",
			held.Codes[0].ConsumedAt)
	}
	if err := recovery.Consume(ctx, held, 0); err != nil {
		t.Fatalf("Consume of an unstamped slot: %v", err)
	}

	stored, err := recovery.Get(ctx, subject)
	if err != nil {
		t.Fatalf("Get after Consume: %v", err)
	}
	if !stored.Codes[0].ConsumedAt.Equal(clock.now) {
		t.Errorf("stored ConsumedAt = %v, want the store's clock reading %v; "+
			"an unstamped slot that stays unstamped is a code the caller was told it had spent",
			stored.Codes[0].ConsumedAt, clock.now)
	}

	replay, err := recovery.Get(ctx, subject)
	if err != nil {
		t.Fatalf("Get for replay: %v", err)
	}
	replay.Codes[0].ConsumedAt = time.Time{}
	if err := recovery.Consume(ctx, replay, 0); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Errorf("second Consume of the same slot = %v, want ErrAlreadyConsumed", err)
	}

	// The sibling slot is untouched: stamping slot 0 must not spend the
	// rest of the batch.
	if !stored.Codes[1].ConsumedAt.IsZero() {
		t.Errorf("slot 1 ConsumedAt = %v, want it left available", stored.Codes[1].ConsumedAt)
	}
}

// TestRecoveryStore_ConsumeKeepsCallerStamp pins the other half: a slot
// the caller stamped keeps that exact instant, because it is the OP's
// clock reading for the verification that just succeeded.
func TestRecoveryStore_ConsumeKeepsCallerStamp(t *testing.T) {
	t.Parallel()

	clock := consumeStampClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	s := inmem.New(inmem.WithClock(clock))
	recovery := s.RecoveryCodes()
	ctx := context.Background()
	const subject = "recovery-stamped-subject"
	stamp := clock.now.Add(90 * time.Minute)

	if err := recovery.Put(ctx, &store.RecoveryBatch{
		Subject:     subject,
		GeneratedAt: clock.now,
		Codes: []store.RecoveryCode{
			{Hash: "$argon2id$v=19$m=65536,t=3,p=2$c2FsdC10aHI$aGFzaC10aHI"},
		},
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	held, err := recovery.Get(ctx, subject)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	held.Codes[0].ConsumedAt = stamp
	if err := recovery.Consume(ctx, held, 0); err != nil {
		t.Fatalf("Consume of a stamped slot: %v", err)
	}
	stored, err := recovery.Get(ctx, subject)
	if err != nil {
		t.Fatalf("Get after Consume: %v", err)
	}
	if !stored.Codes[0].ConsumedAt.Equal(stamp) {
		t.Errorf("stored ConsumedAt = %v, want the caller's %v", stored.Codes[0].ConsumedAt, stamp)
	}
}

// TestEmailOTPStore_ConsumeStampsUnstampedRecord is the sibling pin.
// The e-mail OTP challenge is single-use on the same terms a recovery
// slot is, and the reference implementation owns the stamp for the same
// reason: a record written back unstamped is a challenge the caller was
// told it had spent.
func TestEmailOTPStore_ConsumeStampsUnstampedRecord(t *testing.T) {
	t.Parallel()

	clock := consumeStampClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	s := inmem.New(inmem.WithClock(clock))
	otp := s.EmailOTPs()
	ctx := context.Background()
	const subject = "emailotp-unstamped-subject"

	if err := otp.Put(ctx, &store.EmailOTPRecord{
		Subject:     subject,
		CodeSalt:    []byte{0x11, 0x22},
		CodeHash:    []byte{0x33, 0x44},
		SentAt:      clock.now,
		ExpiresAt:   clock.now.Add(time.Hour),
		RetainUntil: clock.now.Add(24 * time.Hour),
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
	if err := otp.Consume(ctx, held); err != nil {
		t.Fatalf("Consume of an unstamped record: %v", err)
	}

	stored, err := otp.Get(ctx, subject)
	if err != nil {
		t.Fatalf("Get after Consume: %v", err)
	}
	if !stored.ConsumedAt.Equal(clock.now) {
		t.Errorf("stored ConsumedAt = %v, want the store's clock reading %v", stored.ConsumedAt, clock.now)
	}

	replay, err := otp.Get(ctx, subject)
	if err != nil {
		t.Fatalf("Get for replay: %v", err)
	}
	replay.ConsumedAt = time.Time{}
	if err := otp.Consume(ctx, replay); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Errorf("second Consume of the same challenge = %v, want ErrAlreadyConsumed", err)
	}
}
