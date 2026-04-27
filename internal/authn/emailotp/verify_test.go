package emailotp_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn/emailotp"
	"github.com/libraz/go-oidc-provider/op/store"
)

func newRecord(t *testing.T, subject, code string, sentAt, expiresAt time.Time) *store.EmailOTPRecord {
	t.Helper()
	salt, err := emailotp.GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt: %v", err)
	}
	return &store.EmailOTPRecord{
		Subject:   subject,
		CodeSalt:  salt,
		CodeHash:  emailotp.HashCode(salt, subject, code),
		SentAt:    sentAt,
		ExpiresAt: expiresAt,
	}
}

func TestVerifySuccessClearsCounters(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	rec := newRecord(t, "sub", "123456", now.Add(-1*time.Minute), now.Add(4*time.Minute))
	rec.FailedCount = 5
	rec.FirstFailureAt = now.Add(-30 * time.Minute)

	v := &emailotp.Verifier{Clock: &emailotp.FakeClock{T: now}}
	res, err := v.Verify(context.Background(), rec, "123456")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Outcome != emailotp.OutcomeSuccess {
		t.Errorf("Outcome = %d, want OutcomeSuccess", res.Outcome)
	}
	if rec.FailedCount != 0 || !rec.FirstFailureAt.IsZero() || !rec.LockedUntil.IsZero() {
		t.Errorf("counters not cleared: %+v", rec)
	}
}

func TestVerifyWrongCodeIncrementsCounter(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	rec := newRecord(t, "sub", "123456", now.Add(-1*time.Minute), now.Add(4*time.Minute))

	v := &emailotp.Verifier{Clock: &emailotp.FakeClock{T: now}}
	res, err := v.Verify(context.Background(), rec, "999999")
	if !errors.Is(err, emailotp.ErrWrongCode) {
		t.Fatalf("Verify err = %v, want ErrWrongCode", err)
	}
	if res.Outcome != emailotp.OutcomeWrongCode {
		t.Errorf("Outcome = %d, want OutcomeWrongCode", res.Outcome)
	}
	if rec.FailedCount != 1 {
		t.Errorf("FailedCount = %d, want 1", rec.FailedCount)
	}
	if !rec.FirstFailureAt.Equal(now) {
		t.Errorf("FirstFailureAt = %v, want %v", rec.FirstFailureAt, now)
	}
}

func TestVerifyShortLockAtThreshold(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	rec := newRecord(t, "sub", "123456", now.Add(-1*time.Minute), now.Add(4*time.Minute))
	rec.FailedCount = emailotp.LockThresholdShort - 1
	rec.FirstFailureAt = now.Add(-30 * time.Minute)

	v := &emailotp.Verifier{Clock: &emailotp.FakeClock{T: now}}
	if _, err := v.Verify(context.Background(), rec, "999999"); !errors.Is(err, emailotp.ErrWrongCode) {
		t.Fatalf("Verify err = %v, want ErrWrongCode", err)
	}
	if rec.FailedCount != emailotp.LockThresholdShort {
		t.Fatalf("FailedCount = %d, want %d", rec.FailedCount, emailotp.LockThresholdShort)
	}
	if rec.LockedUntil.IsZero() || !rec.LockedUntil.Equal(now.Add(emailotp.LockDurationShort)) {
		t.Errorf("LockedUntil = %v, want %v", rec.LockedUntil, now.Add(emailotp.LockDurationShort))
	}
}

func TestVerifyLongLockReturnsResetRequired(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	rec := newRecord(t, "sub", "123456", now.Add(-1*time.Minute), now.Add(4*time.Minute))
	rec.FailedCount = emailotp.LockThresholdLong - 1
	rec.FirstFailureAt = now.Add(-30 * time.Minute)

	v := &emailotp.Verifier{Clock: &emailotp.FakeClock{T: now}}
	res, err := v.Verify(context.Background(), rec, "999999")
	if !errors.Is(err, emailotp.ErrResetRequired) {
		t.Fatalf("Verify err = %v, want ErrResetRequired", err)
	}
	if res.Outcome != emailotp.OutcomeResetRequired {
		t.Errorf("Outcome = %d, want OutcomeResetRequired", res.Outcome)
	}
	if !rec.LockedUntil.Equal(now.Add(emailotp.LockDurationLong)) {
		t.Errorf("LockedUntil = %v, want %v", rec.LockedUntil, now.Add(emailotp.LockDurationLong))
	}
}

func TestVerifyLockedShortCircuits(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	rec := newRecord(t, "sub", "123456", now.Add(-1*time.Minute), now.Add(4*time.Minute))
	rec.LockedUntil = now.Add(10 * time.Minute)

	v := &emailotp.Verifier{Clock: &emailotp.FakeClock{T: now}}
	res, err := v.Verify(context.Background(), rec, "123456")
	if !errors.Is(err, emailotp.ErrLocked) {
		t.Fatalf("Verify err = %v, want ErrLocked", err)
	}
	if res.Outcome != emailotp.OutcomeLocked {
		t.Errorf("Outcome = %d, want OutcomeLocked", res.Outcome)
	}
	if rec.FailedCount != 0 {
		t.Errorf("FailedCount mutated under lock: %d", rec.FailedCount)
	}
}

func TestVerifyExpiredReturnsErrExpired(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	rec := newRecord(t, "sub", "123456", now.Add(-10*time.Minute), now.Add(-5*time.Minute))

	v := &emailotp.Verifier{Clock: &emailotp.FakeClock{T: now}}
	if _, err := v.Verify(context.Background(), rec, "123456"); !errors.Is(err, emailotp.ErrExpired) {
		t.Fatalf("Verify err = %v, want ErrExpired", err)
	}
}

func TestVerifyZeroSentAtAlwaysFails(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	rec := newRecord(t, "sub", "123456", time.Time{}, now.Add(4*time.Minute))

	v := &emailotp.Verifier{Clock: &emailotp.FakeClock{T: now}}
	res, err := v.Verify(context.Background(), rec, "123456")
	if !errors.Is(err, emailotp.ErrWrongCode) {
		t.Fatalf("Verify err = %v, want ErrWrongCode", err)
	}
	if res.Outcome != emailotp.OutcomeWrongCode {
		t.Errorf("Outcome = %d, want OutcomeWrongCode", res.Outcome)
	}
}

func TestVerifyNilRecord(t *testing.T) {
	t.Parallel()
	v := &emailotp.Verifier{}
	if _, err := v.Verify(context.Background(), nil, "123456"); !errors.Is(err, emailotp.ErrNoChallenge) {
		t.Fatalf("Verify err = %v, want ErrNoChallenge", err)
	}
}

func TestVerifyCounterRolloverResets(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	rec := newRecord(t, "sub", "123456", now.Add(-1*time.Minute), now.Add(4*time.Minute))
	rec.FailedCount = 25
	rec.FirstFailureAt = now.Add(-25 * time.Hour)

	v := &emailotp.Verifier{Clock: &emailotp.FakeClock{T: now}}
	if _, err := v.Verify(context.Background(), rec, "999999"); !errors.Is(err, emailotp.ErrWrongCode) {
		t.Fatalf("Verify err = %v, want ErrWrongCode", err)
	}
	if rec.FailedCount != 1 {
		t.Errorf("FailedCount = %d, want 1 (window rollover)", rec.FailedCount)
	}
	if !rec.FirstFailureAt.Equal(now) {
		t.Errorf("FirstFailureAt = %v, want %v (window rollover)", rec.FirstFailureAt, now)
	}
}
