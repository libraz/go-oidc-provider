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
	"math"
	"time"

	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Threshold values. The constants are package-private so embedders
// cannot tune them per-deployment; the defence is tuned once for the
// entire library. The values match the per-factor TOTP / email-OTP
// thresholds.
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

	// maxSwapAttempts bounds the compare-and-swap loop in
	// [Counter.RecordFailure]. Losing the swap is a normal outcome, so
	// without a bound a burst of concurrent failed logins against one
	// subject keeps re-reading and re-swapping: the brute-force gate
	// would amplify the attack into store round trips instead of
	// damping it. The bound sits above the per-factor verifiers' own
	// retry cap because the cross-factor row is a single hot row shared
	// by every factor of one subject, so it sees more concurrent
	// writers than any per-factor record.
	maxSwapAttempts = 32
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

	// ErrSwapContention is returned by [Counter.RecordFailure] when the
	// versioned compare-and-swap lost [maxSwapAttempts] times in a row.
	// The failure has NOT been counted, so the caller MUST fail the
	// attempt closed rather than treat it as a soft retry: a counter
	// that cannot commit is a counter that cannot defend, and sustained
	// contention on one subject's row is itself an attack signal worth
	// surfacing.
	ErrSwapContention = errors.New("lockout: failure counter contended, attempt not recorded")
)

// Store contract violations. A store that answers a Get with a nil
// record and a nil error, with another subject's row, or with an
// unversioned row breaks the [store.AuthnLockoutStore] contract; every
// read path fails closed on it instead of dereferencing nil or trusting
// the row.
var (
	errNilRecord       = errors.New("lockout: store returned nil record without error")
	errSubjectMismatch = errors.New("lockout: store returned record for a different subject")
	errZeroVersion     = errors.New("lockout: persisted record has zero version")
)

// checkRecord validates a record the store returned alongside a nil
// error. version reports whether the caller needs a usable CAS version
// (the read-only paths do not).
func checkRecord(rec *store.AuthnLockoutRecord, subject string, version bool) error {
	if rec == nil {
		return errNilRecord
	}
	if rec.Subject != subject {
		return errSubjectMismatch
	}
	if version && rec.Version == 0 {
		return errZeroVersion
	}
	return nil
}

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
// nil — a first-time-ever subject has no lock. A record that breaks the
// store contract surfaces as an error rather than as an implicit
// "unlocked".
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
	if err := checkRecord(rec, subject, false); err != nil {
		return err
	}
	now := c.clock.Now()
	if !rec.LockedUntil.IsZero() && rec.LockedUntil.After(now) {
		return ErrLocked
	}
	return nil
}

// IsLocked reports whether the cross-factor LockedUntil stamp is in
// the future. A missing record is treated as "not locked"; a record
// that breaks the store contract returns the error alongside the zero
// verdict.
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
	if err := checkRecord(rec, subject, false); err != nil {
		return false, time.Time{}, err
	}
	now := c.clock.Now()
	if !rec.LockedUntil.IsZero() && rec.LockedUntil.After(now) {
		return true, rec.LockedUntil, nil
	}
	return false, time.Time{}, nil
}

// RecordFailure advances the complete cross-factor lockout state with
// a versioned compare-and-swap. Increment, window rollover, and lock
// stamping are one transition, so none can overwrite a concurrently
// committed failure. A stale transition is recomputed from the latest
// record and retried up to [maxSwapAttempts] times; past that the
// attempt is abandoned with [ErrSwapContention] rather than spinning,
// and a cancelled ctx aborts between attempts.
func (c *Counter) RecordFailure(ctx context.Context, subject string) (Outcome, error) {
	if subject == "" {
		return Outcome{}, errors.New("lockout: subject required")
	}
	now := c.clock.Now()

	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return Outcome{}, err
		}
		if attempt == maxSwapAttempts {
			return Outcome{}, ErrSwapContention
		}
		expectedVersion, next, err := c.failureBase(ctx, subject)
		if err != nil {
			return Outcome{}, err
		}
		out := applyFailure(next, now)
		swapped, err := c.store.CompareAndSwap(ctx, expectedVersion, next)
		if err != nil {
			return Outcome{}, err
		}
		if swapped {
			return out, nil
		}
	}
}

func (c *Counter) failureBase(ctx context.Context, subject string) (uint64, *store.AuthnLockoutRecord, error) {
	prior, err := c.store.Get(ctx, subject)
	if errors.Is(err, store.ErrNotFound) {
		return 0, &store.AuthnLockoutRecord{Subject: subject}, nil
	}
	if err != nil {
		return 0, nil, err
	}
	if err := checkRecord(prior, subject, true); err != nil {
		return 0, nil, err
	}
	return prior.Version, prior, nil
}

func applyFailure(next *store.AuthnLockoutRecord, now time.Time) Outcome {
	windowExpired := !next.FirstFailureAt.IsZero() &&
		now.Sub(next.FirstFailureAt) > counterWindow
	if windowExpired {
		next.FailedCount = 1
		next.FirstFailureAt = now
	} else {
		if next.FailedCount < math.MaxInt {
			next.FailedCount++
		}
		if next.FirstFailureAt.IsZero() {
			next.FirstFailureAt = now
		}
	}

	out := Outcome{FailedCount: next.FailedCount}
	switch {
	case next.FailedCount >= thresholdLong:
		out.LockedUntil = now.Add(durationLong)
		out.ResetRequired = true
	case next.FailedCount >= thresholdShort:
		out.LockedUntil = now.Add(durationShort)
	}
	if next.LockedUntil.After(out.LockedUntil) {
		out.LockedUntil = next.LockedUntil
	}
	next.LockedUntil = out.LockedUntil
	return out
}

// Reset clears the cross-factor counter for subject. The per-factor
// adapter calls it after a successful Continue so the legitimate user
// is not punished by accumulated attempts when their authentication
// finally succeeds.
//
// A missing record is treated as "nothing to clear" and returns nil. Reset
// deliberately attempts its compare-and-swap only once: if a failure commits
// after Reset's read, the stale reset is discarded instead of retrying and
// erasing that failure. Conversely, if Reset commits first, RecordFailure
// retries against the cleared state.
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
	if err := checkRecord(rec, subject, true); err != nil {
		return err
	}
	if rec.FailedCount == 0 && rec.FirstFailureAt.IsZero() && rec.LockedUntil.IsZero() {
		return nil
	}
	rec.FailedCount = 0
	rec.FirstFailureAt = time.Time{}
	rec.LockedUntil = time.Time{}
	_, err = c.store.CompareAndSwap(ctx, rec.Version, rec)
	return err
}
