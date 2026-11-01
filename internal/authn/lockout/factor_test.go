package lockout_test

import (
	"context"
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authn/lockout"
)

var (
	errFactorLocked  = errors.New("factor: locked")
	errFactorReset   = errors.New("factor: reset required")
	errFactorEngaged = errors.New("factor: lock engaged")

	testFactor = lockout.FactorErrors{
		Name:          "factor",
		Locked:        errFactorLocked,
		ResetRequired: errFactorReset,
		LockEngaged:   errFactorEngaged,
	}
)

func TestCounter_StatusFromOneRead(t *testing.T) {
	t.Parallel()
	c, _ := newFixture(t)
	ctx := context.Background()

	st, err := c.Status(ctx, "alice")
	if err != nil || st.Locked || st.Remaining != lockout.ThresholdShort {
		t.Fatalf("fresh Status = %+v, %v", st, err)
	}
	if _, err := c.RecordFailure(ctx, "alice"); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}
	st, err = c.Status(ctx, "alice")
	if err != nil || st.Locked || st.Remaining != lockout.ThresholdShort-1 {
		t.Fatalf("Status after one failure = %+v, %v", st, err)
	}
	for range lockout.ThresholdShort {
		if _, err := c.RecordFailure(ctx, "alice"); err != nil {
			t.Fatalf("RecordFailure: %v", err)
		}
	}
	st, err = c.Status(ctx, "alice")
	if err != nil || !st.Locked || st.LockedUntil.IsZero() || st.Remaining != 0 {
		t.Fatalf("locked Status = %+v, %v", st, err)
	}
}

func TestCounter_NilReceiverIsInert(t *testing.T) {
	t.Parallel()
	var c *lockout.Counter
	ctx := context.Background()

	if st, err := c.Status(ctx, "alice"); err != nil || st.Locked || st.Remaining != lockout.ThresholdShort {
		t.Errorf("nil Status = %+v, %v", st, err)
	}
	if err := c.Guard(ctx, "alice", testFactor); err != nil {
		t.Errorf("nil Guard = %v", err)
	}
	if err := c.RecordWrong(ctx, "alice", testFactor); err != nil {
		t.Errorf("nil RecordWrong = %v", err)
	}
	if err := c.ResetOnSuccess(ctx, "alice", testFactor); err != nil {
		t.Errorf("nil ResetOnSuccess = %v", err)
	}
}

func TestCounter_FactorHelpersMapToFactorSentinels(t *testing.T) {
	t.Parallel()
	c, _ := newFixture(t)
	ctx := context.Background()

	var got error
	for range lockout.ThresholdShort {
		got = c.RecordWrong(ctx, "alice", testFactor)
	}
	if !errors.Is(got, errFactorEngaged) {
		t.Fatalf("threshold failure = %v, want the lock-engaged sentinel", got)
	}
	if err := c.Guard(ctx, "alice", testFactor); !errors.Is(err, errFactorLocked) {
		t.Fatalf("Guard while locked = %v, want the factor's Locked sentinel", err)
	}
	if err := c.ResetOnSuccess(ctx, "alice", testFactor); err != nil {
		t.Fatalf("ResetOnSuccess: %v", err)
	}
	if err := c.Guard(ctx, "alice", testFactor); err != nil {
		t.Fatalf("Guard after reset = %v", err)
	}
	if err := c.RecordWrong(ctx, "alice", testFactor); err != nil {
		t.Fatalf("first failure after reset = %v, want nil", err)
	}
}

func TestCounter_RecordWrongReportsResetRequired(t *testing.T) {
	t.Parallel()
	c, _ := newFixture(t)
	ctx := context.Background()

	var got error
	for range lockout.ThresholdLong {
		got = c.RecordWrong(ctx, "bob", testFactor)
	}
	if !errors.Is(got, errFactorReset) {
		t.Fatalf("long-threshold failure = %v, want the reset-required sentinel", got)
	}
}
