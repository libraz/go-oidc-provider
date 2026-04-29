package emailotp

import (
	"context"
	"errors"
	"time"

	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Brute-force defence thresholds. The values match the TOTP adapter
// ; the two factors share a
// rolling 24-hour window so an attacker who pivots between them
// cannot reset the counter.
const (
	// lockThresholdShort triggers a 1-hour LockedUntil stamp once the
	// 24-hour cumulative FailedCount reaches this value.
	lockThresholdShort = 30

	// lockThresholdLong triggers a 24-hour LockedUntil stamp AND
	// returns [ErrResetRequired] so the orchestrator can force the
	// user through the recovery flow.
	lockThresholdLong = 90

	// lockDurationShort is the LockedUntil offset applied at
	// lockThresholdShort.
	lockDurationShort = 1 * time.Hour

	// lockDurationLong is the LockedUntil offset applied at
	// lockThresholdLong.
	lockDurationLong = 24 * time.Hour

	// counterWindow is the rolling window over which FailedCount
	// accumulates. A failure recorded more than counterWindow ago is
	// dropped: the next failure resets FirstFailureAt to "now" and
	// the counter to 1.
	counterWindow = 24 * time.Hour
)

// DefaultCodeTTL is the acceptance window from issuance to
// verification when [Config.CodeTTL] is zero. Five minutes is long
// enough for a user to fetch the code from an inbox while staying
// short enough that a leaked record window is small.
const DefaultCodeTTL = 5 * time.Minute

// Outcome enumerates the verdicts [Verifier.Verify] returns alongside
// the (possibly mutated) record.
type Outcome int

const (
	// OutcomeSuccess means the supplied code matched and the
	// brute-force counters have been cleared.
	OutcomeSuccess Outcome = iota + 1

	// OutcomeWrongCode means the code did not match. The Record's
	// FailedCount has been incremented and FirstFailureAt has been
	// stamped if it was zero or older than counterWindow.
	OutcomeWrongCode

	// OutcomeExpired means rec.ExpiresAt was before the verifier's
	// clock at the time of the call. The record is unchanged so
	// callers can drop it without a Put round-trip.
	OutcomeExpired

	// OutcomeLocked means rec.LockedUntil is in the future. The
	// record is unchanged.
	OutcomeLocked

	// OutcomeResetRequired is returned alongside [ErrResetRequired]
	// when FailedCount has crossed lockThresholdLong. The Record
	// carries the stamped 24-hour LockedUntil; the orchestrator MUST
	// persist it before the user is redirected to the recovery flow.
	OutcomeResetRequired

	// OutcomeConsumed means the persisted record carries a non-zero
	// ConsumedAt stamp: the code was already redeemed in a prior
	// successful verify and is no longer eligible. The record is
	// unchanged. Returned alongside [ErrConsumed].
	OutcomeConsumed
)

// Sentinel errors. Returned values are wrapped through [errors.Is]
// so the orchestrator can dispatch on them without string matching.
var (
	// ErrNoChallenge is returned when [Verifier.Verify] receives a
	// nil record. The Authenticator routes a missing record into
	// [ErrExpired] before reaching the verifier, but library code
	// outside the adapter may still observe this error.
	ErrNoChallenge = errors.New("emailotp: no pending challenge")

	// ErrExpired is returned when the persisted record's ExpiresAt
	// is before the verifier's clock.
	ErrExpired = errors.New("emailotp: code expired")

	// ErrLocked is returned when rec.LockedUntil is in the future.
	ErrLocked = errors.New("emailotp: factor is locked")

	// ErrWrongCode is returned when the supplied code does not
	// match the persisted hash. This is the only recoverable verify
	// error — the adapter re-emits the verify prompt and the
	// orchestrator advances the StateRef counter.
	ErrWrongCode = errors.New("emailotp: code did not match")

	// ErrResetRequired is returned when FailedCount has crossed
	// lockThresholdLong. The orchestrator MUST treat this as a
	// terminal state and route the user to the recovery / step-up
	// reset flow.
	ErrResetRequired = errors.New("emailotp: factor reset required")

	// ErrConsumed is returned when the persisted record's ConsumedAt
	// is non-zero. The caller MUST NOT advance the chain on this
	// signal: the code has already been redeemed and a replay against
	// the same record is rejected as if the code did not exist.
	ErrConsumed = errors.New("emailotp: code already consumed")
)

// Result is the verdict bundle [Verifier.Verify] returns. The Record
// pointer is the same pointer the caller supplied, mutated in place,
// so the caller may pass it straight to [store.EmailOTPStore.Put].
type Result struct {
	// Outcome is the high-level verdict. See the [Outcome] constants.
	Outcome Outcome

	// Record is the (possibly mutated) record the caller passed in.
	Record *store.EmailOTPRecord
}

// Verifier verifies email-OTP codes against a persisted
// [store.EmailOTPRecord] and maintains the 24-hour brute-force
// counter.
// The zero value uses [timex.SystemClock]; callers that need a
// deterministic clock for tests inject one through [Verifier.Clock].
type Verifier struct {
	// Clock supplies the wall-clock reading used for the expiry
	// check, the LockedUntil comparison, and the FirstFailureAt
	// rollover. A nil value falls back to [timex.SystemClock].
	Clock timex.Clock
}

// Verify checks code against rec and returns a [Result] reporting
// the outcome alongside the mutated record. The caller is
// responsible for persisting the record through
// [store.EmailOTPStore.Put] when the outcome is OutcomeSuccess,
// OutcomeWrongCode, or OutcomeResetRequired; on OutcomeLocked /
// OutcomeExpired the record is unchanged and Put is unnecessary.
// A record with a zero [store.EmailOTPRecord.SentAt] is treated as a
// sentinel that always fails verify: the authenticator persists such
// records when the user-typed email did not match the bound claim,
// and the constant-shape contract requires verification to proceed
// to the failure path identically.
func (v *Verifier) Verify(_ context.Context, rec *store.EmailOTPRecord, code string) (*Result, error) {
	if rec == nil {
		return nil, ErrNoChallenge
	}
	now := v.now()
	if !rec.ConsumedAt.IsZero() {
		// The code has already been redeemed. Reject without mutating
		// the record so a transient retry cannot reset the counter.
		// The caller's brute-force counter (the orchestrator)
		// observes the failure independently of this record's state.
		return &Result{Outcome: OutcomeConsumed, Record: rec}, ErrConsumed
	}
	if !rec.LockedUntil.IsZero() && rec.LockedUntil.After(now) {
		return &Result{Outcome: OutcomeLocked, Record: rec}, ErrLocked
	}
	if !rec.ExpiresAt.IsZero() && rec.ExpiresAt.Before(now) {
		return &Result{Outcome: OutcomeExpired, Record: rec}, ErrExpired
	}
	candidate := hashCode(rec.CodeSalt, rec.Subject, code)
	matched := !rec.SentAt.IsZero() && constantTimeEqualHashes(candidate, rec.CodeHash)
	if matched {
		rec.FailedCount = 0
		rec.FirstFailureAt = time.Time{}
		rec.LockedUntil = time.Time{}
		rec.ConsumedAt = now
		return &Result{Outcome: OutcomeSuccess, Record: rec}, nil
	}
	if rec.FirstFailureAt.IsZero() || now.Sub(rec.FirstFailureAt) > counterWindow {
		rec.FirstFailureAt = now
		rec.FailedCount = 0
	}
	rec.FailedCount++
	switch {
	case rec.FailedCount >= lockThresholdLong:
		rec.LockedUntil = now.Add(lockDurationLong)
		return &Result{Outcome: OutcomeResetRequired, Record: rec}, ErrResetRequired
	case rec.FailedCount >= lockThresholdShort:
		rec.LockedUntil = now.Add(lockDurationShort)
	}
	return &Result{Outcome: OutcomeWrongCode, Record: rec}, ErrWrongCode
}

func (v *Verifier) now() time.Time {
	if v.Clock == nil {
		return timex.SystemClock.Now()
	}
	return v.Clock.Now()
}
