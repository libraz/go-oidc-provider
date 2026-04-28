package totp

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Brute-force defence thresholds. The values come straight from
// 02-product-design.md §M.6 and are intentionally not
// exposed as configuration: tuning them per-deployment would silently
// weaken the defence and make incident response harder to reason about.
const (
	// lockThresholdShort triggers a 1-hour LockedUntil stamp once the
	// 24-hour cumulative FailedCount reaches this value.
	lockThresholdShort = 30

	// lockThresholdLong triggers a 24-hour LockedUntil stamp AND
	// returns [ErrResetRequired] so the orchestrator can force a
	// step-up reset of the factor.
	lockThresholdLong = 90

	// lockDurationShort is the LockedUntil offset applied at
	// lockThresholdShort.
	lockDurationShort = 1 * time.Hour

	// lockDurationLong is the LockedUntil offset applied at
	// lockThresholdLong.
	lockDurationLong = 24 * time.Hour

	// counterWindow is the rolling window over which FailedCount
	// accumulates. A failure recorded more than counterWindow ago is
	// dropped: the next failure resets FirstFailureAt to "now" and the
	// counter to 1.
	counterWindow = 24 * time.Hour
)

// defaultSkew is the ±step window the verifier accepts. RFC 6238 §5.2
// example uses one step; widening it doubles the brute-force surface for
// every additional step and is therefore not recommended.
const defaultSkew = 1

// Outcome enumerates the verdicts [Verifier.Verify] returns alongside
// the mutated record. The orchestrator branches on it to decide whether
// to advance the authenticator chain, prompt the user to retry, or
// trigger a step-up reset.
type Outcome int

const (
	// OutcomeSuccess means the supplied code matched within the skew
	// window and the brute-force counters have been cleared.
	OutcomeSuccess Outcome = iota + 1

	// OutcomeWrongCode means the code did not match. The Record's
	// FailedCount has been incremented and FirstFailureAt has been
	// stamped if it was zero or older than counterWindow.
	OutcomeWrongCode

	// OutcomeLocked means LockedUntil is in the future at the time of
	// the call. The Record is unchanged so callers can re-Put it
	// idempotently without overwriting a concurrent update.
	OutcomeLocked

	// OutcomeResetRequired is returned alongside [ErrResetRequired]
	// when FailedCount has crossed lockThresholdLong. The Record
	// carries the stamped 24-hour LockedUntil; the orchestrator MUST
	// persist it before redirecting the user to the recovery flow so
	// that a concurrent attacker cannot keep guessing.
	OutcomeResetRequired
)

// Sentinel errors. Returned values are wrapped through [errors.Is] so
// the orchestrator can dispatch on them without string matching.
var (
	// ErrLocked is returned when [Verifier.Verify] is called while
	// LockedUntil is in the future. The Result.Outcome equals
	// OutcomeLocked.
	ErrLocked = errors.New("totp: factor is locked")

	// ErrWrongCode is returned when the supplied code does not match
	// any step in the skew window. The Result.Outcome equals
	// OutcomeWrongCode and the Record carries the bumped counters.
	ErrWrongCode = errors.New("totp: code did not match")

	// ErrResetRequired is returned when FailedCount has crossed
	// lockThresholdLong. The orchestrator MUST treat this as a
	// terminal state and route the user to the recovery / step-up
	// reset flow; the verifier intentionally never disables the
	// factor on its own.
	ErrResetRequired = errors.New("totp: factor reset required")

	// ErrNotConfirmed is returned when the supplied record has a zero
	// ConfirmedAt timestamp. The library refuses to verify against an
	// enrolment that has never been confirmed.
	ErrNotConfirmed = errors.New("totp: enrolment not confirmed")
)

// Result is the verdict bundle [Verifier.Verify] returns. The Record
// pointer is the same pointer the caller supplied, mutated in place, so
// the caller may pass it straight to [store.TOTPStore.Put]. The
// Outcome / Err pair lets the orchestrator branch without re-checking
// the record fields.
type Result struct {
	// Outcome is the high-level verdict. See the [Outcome] constants.
	Outcome Outcome

	// Record is the (possibly mutated) record the caller passed in.
	// On OutcomeSuccess, FailedCount has been cleared and LockedUntil
	// has been zeroed; on OutcomeWrongCode the counters have been
	// updated; on OutcomeResetRequired LockedUntil carries the 24-hour
	// stamp the caller MUST persist.
	Record *store.TOTPRecord
}

// Verifier verifies RFC 6238 codes against a persisted [store.TOTPRecord]
// and maintains the 24-hour brute-force counter described in
// 02-product-design.md §M.6.
// The zero value is not usable: callers MUST set Codec at minimum.
// Clock falls back to [timex.SystemClock] and Skew falls back to
// [defaultSkew] (one step on each side) when zero.
// Verifier is immutable after construction and safe for concurrent use.
type Verifier struct {
	// Clock supplies the wall-clock reading used for the step
	// computation, the LockedUntil comparison, and the FirstFailureAt
	// rollover. A nil value falls back to [timex.SystemClock].
	Clock timex.Clock

	// Codec opens the SecretCiphertext blob on the record. Required.
	Codec *Codec

	// Skew is the number of additional steps accepted on each side of
	// the current step. A zero value falls back to [defaultSkew]; the
	// effective acceptance window is therefore (2*Skew + 1) steps.
	// Callers SHOULD NOT exceed 1 in production.
	Skew int
}

// Verify checks code against rec and returns a [Result] reporting the
// outcome alongside the mutated record. The caller is responsible for
// persisting the record through [store.TOTPStore.Put] when the outcome
// is OutcomeSuccess, OutcomeWrongCode, or OutcomeResetRequired; on
// OutcomeLocked the record is unchanged and Put is unnecessary.
// Verify performs the following sequence:
//  1. Reject the call if rec.ConfirmedAt is zero (ErrNotConfirmed).
//  2. Reject the call with ErrLocked if rec.LockedUntil is in the
//     future.
//  3. Decrypt rec.SecretCiphertext through the codec, binding rec.Subject
//     as AAD.
//  4. Compute the TOTP for the current step and Skew steps on each
//     side, and compare each in constant time against code.
//  5. On match, clear FailedCount / FirstFailureAt / LockedUntil and
//     return OutcomeSuccess.
//  6. On miss, increment FailedCount (resetting the window if the
//     previous FirstFailureAt is older than counterWindow) and stamp
//     LockedUntil per the threshold table. Return OutcomeWrongCode or
//     OutcomeResetRequired.
//
// The function never panics on a nil rec; it returns a non-nil error.
// The ctx parameter is accepted for symmetry with the storage API and
// future cancellation but is not consulted today.
func (v *Verifier) Verify(_ context.Context, rec *store.TOTPRecord, code string) (*Result, error) {
	if rec == nil {
		return nil, errors.New("totp: nil record")
	}
	if v.Codec == nil {
		return nil, errors.New("totp: verifier missing codec")
	}
	if rec.ConfirmedAt.IsZero() {
		return nil, ErrNotConfirmed
	}

	clock := v.clock()
	now := clock.Now()

	if !rec.LockedUntil.IsZero() && rec.LockedUntil.After(now) {
		return &Result{Outcome: OutcomeLocked, Record: rec}, ErrLocked
	}

	secret, err := v.Codec.Open(rec.SecretCiphertext, []byte(rec.Subject))
	if err != nil {
		return nil, fmt.Errorf("totp: open secret: %w", err)
	}

	if v.match(secret, code, now) {
		rec.FailedCount = 0
		rec.FirstFailureAt = time.Time{}
		rec.LockedUntil = time.Time{}
		return &Result{Outcome: OutcomeSuccess, Record: rec}, nil
	}

	// Wrong code: roll the counter window forward if necessary, then
	// increment and stamp lockouts.
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

// match reports whether code equals the TOTP value at any step within
// the configured skew window. The comparison is byte-wise constant-time
// per match attempt; the loop itself short-circuits on success, which
// leaks at most one bit of timing about which neighbouring step matched.
// That is acceptable: the attacker already knows the window size, and
// the bit does not narrow the secret search space.
func (v *Verifier) match(secret []byte, code string, now time.Time) bool {
	skew := v.skew()
	if len(code) != digits {
		return false
	}
	codeBytes := []byte(code)
	current := step(now)
	// Iterate from the centre outward so the common-case (no drift)
	// terminates fastest. The current-offset branch is guarded against
	// underflow; step already clamps negative Unix time to zero.
	for i := range skew + 1 {
		offset := uint64(i)
		if v.matchStep(secret, codeBytes, current+offset) {
			return true
		}
		if offset == 0 {
			continue
		}
		if current >= offset && v.matchStep(secret, codeBytes, current-offset) {
			return true
		}
	}
	return false
}

// matchStep computes the TOTP at counter and reports whether it equals
// code. The comparison is constant-time so a partial match cannot leak
// the prefix length through timing.
func (v *Verifier) matchStep(secret, code []byte, counter uint64) bool {
	candidate := codeAtStep(secret, counter)
	return subtle.ConstantTimeCompare(code, []byte(candidate)) == 1
}

func (v *Verifier) clock() timex.Clock {
	if v.Clock == nil {
		return timex.SystemClock
	}
	return v.Clock
}

func (v *Verifier) skew() int {
	if v.Skew <= 0 {
		return defaultSkew
	}
	return v.Skew
}
