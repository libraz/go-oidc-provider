// Package lockout exposes a small helper that aggregates per-subject
// authentication failures across factor types (TOTP, email-OTP, ...) so
// an attacker cannot pivot between factors to double their brute-force
// budget. The helper sits in front of the per-factor verifiers; each
// factor's adapter consults [Counter.IsLocked] before driving its own
// verifier and [Counter.RecordFailure] after a recoverable wrong-code
// outcome.
//
// The thresholds match the per-factor counter (24-hour rolling window,
// 1-hour lockout at FailedCount >= 30, 24-hour lockout + reset signal at
// FailedCount >= 90) so the cross-factor row reads identically to the
// per-factor record. The values are intentionally not exposed as
// configuration: tuning them per-deployment would silently weaken the
// defence and make incident response harder to reason about.
package lockout

import (
	"context"
	"errors"
	"time"

	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Threshold values. The constants are package-private so embedders
// cannot tune them per-deployment; the defence is tuned once for the
// entire library. The values match the per-factor TOTP / email-OTP
// thresholds (02-product-design.md §M.6).
const (
	// thresholdShort triggers a 1-hour LockedUntil stamp.
	thresholdShort = 30

	// thresholdLong triggers a 24-hour LockedUntil stamp AND the
	// [Outcome] reports a reset is required so the orchestrator can
	// route the user through the recovery flow.
	thresholdLong = 90

	// durationShort is the LockedUntil offset applied at thresholdShort.
	durationShort = 1 * time.Hour

	// durationLong is the LockedUntil offset applied at thresholdLong.
	durationLong = 24 * time.Hour

	// counterWindow is the rolling window over which FailedCount
	// accumulates. A failure recorded more than counterWindow ago is
	// dropped: the next failure resets FirstFailureAt to "now" and the
	// counter to 1.
	counterWindow = 24 * time.Hour
)

// Sentinel errors. Returned values are wrapped through [errors.Is] so
// the per-factor adapter can dispatch on them without string matching.
var (
	// ErrLocked is returned by [Counter.GuardBegin] / [Counter.RecordFailure]
	// when the cross-factor LockedUntil stamp is in the future. The
	// per-factor adapter surfaces it to the orchestrator; legacy
	// per-factor lock errors continue to flow alongside (a record
	// locked by either gate is locked).
	ErrLocked = errors.New("lockout: cross-factor brute-force lock active")

	// ErrResetRequired is returned by [Counter.RecordFailure] when the
	// post-increment count crosses [thresholdLong]. The 24-hour
	// LockedUntil stamp has been persisted; the orchestrator MUST
	// route the user to the recovery / step-up reset flow.
	ErrResetRequired = errors.New("lockout: factor reset required")
)

// Outcome reports the cross-factor counter's verdict on a single failed
// attempt. The per-factor adapter reads the fields to decide whether to
// surface a soft retry, a lockout, or a reset-required signal upstream.
type Outcome struct {
	// FailedCount is the post-increment cumulative count across every
	// factor in the rolling window.
	FailedCount int

	// LockedUntil is the wall-clock time the cross-factor lock expires.
	// Zero when the count has not crossed any threshold.
	LockedUntil time.Time

	// ResetRequired reports whether the count crossed the long
	// threshold. The per-factor adapter MUST surface this to the
	// orchestrator so the chain terminates and the user is routed
	// through the recovery flow.
	ResetRequired bool
}

// Counter is the cross-factor brute-force gate. The struct is
// immutable after construction; every method is safe for concurrent
// use and delegates persistence to [store.AuthnLockoutStore].
//
// The zero value is not usable: callers MUST go through [New].
type Counter struct {
	store store.AuthnLockoutStore
	clock timex.Clock
}

// New constructs a [Counter] backed by lockoutStore. clock supplies the
// wall-clock reading used to evaluate window rollover and stamp
// LockedUntil; nil falls back to [timex.SystemClock]. The function
// returns an error when lockoutStore is nil so a misconfigured
// deployment fails at op.New time rather than on the first verify.
func New(lockoutStore store.AuthnLockoutStore, clock timex.Clock) (*Counter, error) {
	if lockoutStore == nil {
		return nil, errors.New("lockout: store is required")
	}
	if clock == nil {
		clock = timex.SystemClock
	}
	return &Counter{store: lockoutStore, clock: clock}, nil
}

// GuardBegin returns [ErrLocked] when the cross-factor LockedUntil
// stamp is in the future. The per-factor adapter calls it on every
// Begin (and at the top of Continue) so a locked subject sees a
// uniform lockout response across factors. A missing record returns
// nil — a first-time-ever subject has no lock.
func (c *Counter) GuardBegin(ctx context.Context, subject string) error {
	if subject == "" {
		return nil
	}
	rec, err := c.store.Get(ctx, subject)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		return err
	}
	now := c.clock.Now()
	if !rec.LockedUntil.IsZero() && rec.LockedUntil.After(now) {
		return ErrLocked
	}
	return nil
}

// IsLocked reports whether the cross-factor LockedUntil stamp is in
// the future. A missing record is treated as "not locked".
func (c *Counter) IsLocked(ctx context.Context, subject string) (bool, time.Time, error) {
	if subject == "" {
		return false, time.Time{}, nil
	}
	rec, err := c.store.Get(ctx, subject)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return false, time.Time{}, nil
		}
		return false, time.Time{}, err
	}
	now := c.clock.Now()
	if !rec.LockedUntil.IsZero() && rec.LockedUntil.After(now) {
		return true, rec.LockedUntil, nil
	}
	return false, time.Time{}, nil
}

// RecordFailure atomically increments the cross-factor failure counter
// for subject and returns the [Outcome] reflecting the post-increment
// state. The function performs the window rollover (FirstFailureAt
// older than counterWindow → reset to 1) and stamps LockedUntil when
// the count crosses a threshold; both effects are persisted before
// the function returns so a concurrent verify cannot observe a stale
// counter.
//
// The atomic-increment contract on [store.AuthnLockoutStore.Increment]
// (M-AUTHN-4) closes the lost-update race the verifier-local counter
// otherwise had: two concurrent verify calls each see the result of
// their own increment, not a snapshot of the count before either ran.
func (c *Counter) RecordFailure(ctx context.Context, subject string) (Outcome, error) {
	if subject == "" {
		return Outcome{}, errors.New("lockout: subject required")
	}
	now := c.clock.Now()

	// Window rollover: if the existing FirstFailureAt is older than
	// the configured window, the counter is treated as expired and
	// the next failure starts a fresh window. The rollover write goes
	// through Put (not Increment) so the row reads "FailedCount=0,
	// FirstFailureAt=now" right before the atomic increment lands the
	// post-rollover counter at 1.
	prior, err := c.store.Get(ctx, subject)
	switch {
	case err == nil && prior != nil:
		if !prior.FirstFailureAt.IsZero() && now.Sub(prior.FirstFailureAt) > counterWindow {
			reset := &store.AuthnLockoutRecord{
				Subject:        subject,
				FailedCount:    0,
				FirstFailureAt: time.Time{},
				// Keep the prior LockedUntil if it has not yet expired
				// — the rollover affects only the failure counter, not
				// an outstanding lock.
				LockedUntil: prior.LockedUntil,
			}
			if perr := c.store.Put(ctx, reset); perr != nil {
				return Outcome{}, perr
			}
		}
	case errors.Is(err, store.ErrNotFound):
		// First failure ever; Increment will create the row.
	default:
		return Outcome{}, err
	}

	count, err := c.store.Increment(ctx, subject, now)
	if err != nil {
		return Outcome{}, err
	}

	out := Outcome{FailedCount: count}
	switch {
	case count >= thresholdLong:
		out.LockedUntil = now.Add(durationLong)
		out.ResetRequired = true
	case count >= thresholdShort:
		out.LockedUntil = now.Add(durationShort)
	}
	if !out.LockedUntil.IsZero() {
		if err := c.stampLock(ctx, subject, out.LockedUntil); err != nil {
			return out, err
		}
	}
	return out, nil
}

// stampLock persists the LockedUntil stamp computed by RecordFailure. When
// the store implements [store.AuthnLockoutStamper] the stamp is a targeted
// atomic write that cannot lose a concurrent Increment (M-AUTHN-4). A store
// without the extension falls back to a read-modify-write Get+Put: the Get
// recovers the FirstFailureAt the Increment wrote so the row stays
// internally consistent, but the Put replaces the whole row and may drop an
// increment that lands between the Get and the Put under concurrency — which
// is why the extension exists and the reference store implements it.
func (c *Counter) stampLock(ctx context.Context, subject string, lockedUntil time.Time) error {
	if stamper, ok := c.store.(store.AuthnLockoutStamper); ok {
		return stamper.StampLock(ctx, subject, lockedUntil)
	}
	current, err := c.store.Get(ctx, subject)
	if err != nil {
		return err
	}
	current.LockedUntil = lockedUntil
	return c.store.Put(ctx, current)
}

// Reset clears the cross-factor counter for subject. The per-factor
// adapter calls it after a successful Continue so the legitimate user
// is not punished by accumulated attempts when their authentication
// finally succeeds.
//
// A missing record is treated as "nothing to clear" and returns nil.
func (c *Counter) Reset(ctx context.Context, subject string) error {
	if subject == "" {
		return nil
	}
	rec, err := c.store.Get(ctx, subject)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		return err
	}
	rec.FailedCount = 0
	rec.FirstFailureAt = time.Time{}
	rec.LockedUntil = time.Time{}
	return c.store.Put(ctx, rec)
}
