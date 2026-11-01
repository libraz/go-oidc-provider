package lockout

import (
	"context"
	"errors"
	"fmt"
)

// FactorErrors carries the sentinels a per-factor adapter surfaces for
// the cross-factor verdicts. Each factor keeps its own values so
// errors.Is identity stays per factor.
type FactorErrors struct {
	// Name prefixes wrapped error text, for example "totp".
	Name string

	// Locked is returned when the cross-factor lock is already in force.
	Locked error

	// ResetRequired is returned when a failure crossed the long threshold.
	ResetRequired error

	// LockEngaged is returned when a failure newly engaged the short lock.
	LockEngaged error
}

// Guard maps [Counter.GuardBegin] onto the factor's sentinels. A nil
// receiver means no shared counter is wired and never blocks.
func (c *Counter) Guard(ctx context.Context, subject string, fe FactorErrors) error {
	if c == nil {
		return nil
	}
	if err := c.GuardBegin(ctx, subject); err != nil {
		if errors.Is(err, ErrLocked) {
			return fe.Locked
		}
		return fmt.Errorf("%s: lockout guard: %w", fe.Name, err)
	}
	return nil
}

// RecordWrong records one wrong guess and returns the factor's terminal
// sentinel when it crossed a threshold, or nil when the guess is a
// recoverable retry. A nil receiver records nothing and returns nil.
func (c *Counter) RecordWrong(ctx context.Context, subject string, fe FactorErrors) error {
	if c == nil {
		return nil
	}
	out, err := c.RecordFailure(ctx, subject)
	if err != nil {
		return fmt.Errorf("%s: lockout record failure: %w", fe.Name, err)
	}
	if out.ResetRequired {
		return fe.ResetRequired
	}
	// A non-zero stamp is a lock in force: the counter reports an expired
	// one as zero, so no clock reading is needed here.
	if !out.LockedUntil.IsZero() {
		return fe.LockEngaged
	}
	return nil
}

// ResetOnSuccess clears the counter after a successful verification. A
// nil receiver clears nothing.
func (c *Counter) ResetOnSuccess(ctx context.Context, subject string, fe FactorErrors) error {
	if c == nil {
		return nil
	}
	if err := c.Reset(ctx, subject); err != nil {
		return fmt.Errorf("%s: lockout reset: %w", fe.Name, err)
	}
	return nil
}
