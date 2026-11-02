package totp

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authn/lockout"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
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
	// stamped if it was zero or older than [lockout.CounterWindow].
	OutcomeWrongCode

	// OutcomeLocked means LockedUntil is in the future at the time of
	// the call. The Record is unchanged so callers can re-Put it
	// idempotently without overwriting a concurrent update.
	OutcomeLocked

	// OutcomeResetRequired is returned alongside [ErrResetRequired]
	// when FailedCount has crossed [lockout.ThresholdLong]. The Record
	// carries the stamped 24-hour LockedUntil; the orchestrator MUST
	// persist it before redirecting the user to the recovery flow so
	// that a concurrent attacker cannot keep guessing.
	OutcomeResetRequired

	// OutcomeReplayed means the code matched a step the record has
	// already accepted. It is a distinct outcome from OutcomeWrongCode
	// because it is not a guess: the caller MUST NOT advance any
	// brute-force counter on it. The Record is unchanged.
	OutcomeReplayed
)

// Sentinel errors. Returned values are wrapped through [errors.Is] so
// the orchestrator can dispatch on them without string matching.
var (
	// ErrLocked is returned when [Verifier.Verify] is called while
	// LockedUntil is in the future. The Result.Outcome equals
	// OutcomeLocked. It wraps [authn.ErrFactorLocked] (itself an
	// [authn.ErrFactorAbort]) so the orchestrator reports the attempt
	// to the observer feed as a lockout rather than as an unclassified
	// abort.
	ErrLocked = fmt.Errorf("totp: factor is locked: %w", authn.ErrFactorLocked)

	// errLockEngaged is [ErrLocked] for the wrong guess that engaged the
	// lock: the code was evaluated and refused, so it also wraps
	// [authn.ErrCredentialRejected].
	errLockEngaged = fmt.Errorf("%w: %w", ErrLocked, authn.ErrCredentialRejected)

	// ErrWrongCode is returned when the supplied code does not match
	// any step in the skew window. The Result.Outcome equals
	// OutcomeWrongCode and the Record carries the bumped counters.
	ErrWrongCode = errors.New("totp: code did not match")

	// ErrReplayed is returned when the supplied code matches a step the
	// record has already accepted. It wraps [ErrWrongCode] so a caller
	// that only cares about "this submission does not let the user in"
	// keeps dispatching on the one sentinel, while a caller that owns a
	// brute-force counter can tell a replay from a guess and leave the
	// counter alone. The Result.Outcome equals OutcomeReplayed and the
	// Record is unchanged.
	ErrReplayed = fmt.Errorf("totp: code already accepted: %w", ErrWrongCode)

	// ErrResetRequired is returned when FailedCount has crossed
	// [lockout.ThresholdLong]. The orchestrator MUST treat this as a
	// terminal state and route the user to the recovery / step-up
	// reset flow; the verifier intentionally never disables the
	// factor on its own.
	// It always follows a counted wrong guess, so it also wraps
	// [authn.ErrCredentialRejected].
	ErrResetRequired = fmt.Errorf("totp: factor reset required: %w: %w", authn.ErrFactorAbort, authn.ErrCredentialRejected)

	// ErrNotConfirmed is returned when the supplied record has a zero
	// ConfirmedAt timestamp. The library refuses to verify against an
	// enrolment that has never been confirmed.
	ErrNotConfirmed = fmt.Errorf("totp: enrolment not confirmed: %w", authn.ErrFactorAbort)
)

// lockoutErrs maps the cross-factor counter's verdicts onto this
// package's sentinels.
//
//nolint:gochecknoglobals // immutable sentinel mapping.
var lockoutErrs = lockout.FactorErrors{
	Name:          "totp",
	Locked:        ErrLocked,
	ResetRequired: ErrResetRequired,
	LockEngaged:   errLockEngaged,
}

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
// and maintains the 24-hour brute-force counter.
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
//     previous FirstFailureAt is older than [lockout.CounterWindow]) and stamp
//     LockedUntil per the threshold table. Return OutcomeWrongCode or
//     OutcomeResetRequired.
//
// Replay defence: the [store.TOTPRecord.LastAcceptedStep] guard rejects
// a code whose step value has already been accepted with [ErrReplayed],
// leaving every counter on the record untouched. The defence is
// only effective when every OP replica that handles a TOTP submission
// observes the same record — i.e. when the configured [store.TOTPStore]
// is shared across replicas (a transactional row in a relational
// engine, a Redis HSET, …). A process-local store leaves each replica
// with its own LastAcceptedStep, so a code accepted on replica A can
// be replayed against replica B inside the same step window. Multi-
// replica deployments MUST route TOTPStore to a shared backend; the
// library does not detect the misconfiguration at runtime.
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

	if rec.LockedUntil.After(now) {
		return &Result{Outcome: OutcomeLocked, Record: rec}, ErrLocked
	}

	secret, err := v.Codec.Open(rec.SecretCiphertext, []byte(rec.Subject))
	if err != nil {
		return nil, fmt.Errorf("totp: open secret: %w", err)
	}

	if matched, ok := MatchStep(secret, code, now, v.skew()); ok {
		// Reject a code whose step value has already been accepted by a
		// prior successful verify. Without this guard a network-level
		// replay (or a leaked code from the SPA buffer) could redeem twice
		// within the same 30-second window. The check runs before mutating
		// counters so a replay does not advance the brute-force counter
		// either; the orchestrator's own attempt counter still observes the
		// failure through the surfacing ErrWrongCode.
		if rec.LastAcceptedStep != 0 && matched <= rec.LastAcceptedStep {
			// Treat as a wrong-code outcome WITHOUT incrementing the
			// brute-force counter (a replay should not punish the
			// legitimate user) but emit a sentinel wrapping ErrWrongCode
			// so the orchestrator dispatches identically. The dedicated
			// outcome is what lets the adapter leave the cross-factor
			// counter alone too: a form double-submit is not a guess, and
			// the promise made here only holds if every counter the
			// submission can reach honours it.
			return &Result{Outcome: OutcomeReplayed, Record: rec}, ErrReplayed
		}
		rec.FailedCount = 0
		rec.FirstFailureAt = time.Time{}
		rec.LockedUntil = time.Time{}
		rec.LastAcceptedStep = matched
		return &Result{Outcome: OutcomeSuccess, Record: rec}, nil
	}

	// Wrong code: roll the counter window forward if necessary, then
	// increment and stamp lockouts.
	resetRequired := lockout.Advance(&rec.FailedCount, &rec.FirstFailureAt, &rec.LockedUntil, now)
	if resetRequired {
		return &Result{Outcome: OutcomeResetRequired, Record: rec}, ErrResetRequired
	}
	return &Result{Outcome: OutcomeWrongCode, Record: rec}, ErrWrongCode
}

// MatchStep reports whether code equals the TOTP value at any step
// within skew steps of the step containing now, and returns the matched
// step counter in the signed form stored on
// [store.TOTPRecord.LastAcceptedStep]. The int64 is meaningful only when
// the boolean is true.
//
// The comparison is byte-wise constant-time per match attempt; the
// loop itself short-circuits on success, which leaks at most one bit
// of timing about which neighbouring step matched. That is
// acceptable: the attacker already knows the window size, and the
// bit does not narrow the secret search space.
func MatchStep(secret []byte, code string, now time.Time, skew int) (int64, bool) {
	if len(code) != digits {
		return 0, false
	}
	codeBytes := []byte(code)
	current := step(now)
	for i := range skew + 1 {
		offset := uint64(i)
		if matchStep(secret, codeBytes, current+offset) {
			return safeStep(current + offset), true
		}
		if offset == 0 {
			continue
		}
		if current >= offset && matchStep(secret, codeBytes, current-offset) {
			return safeStep(current - offset), true
		}
	}
	return 0, false
}

// safeStep converts the unsigned step counter into the signed form
// stored on the record. The cast is safe in practice because the step
// counter cannot exceed 2^53 within any human-relevant horizon (year
// 9000+); the explicit int64 conversion keeps the cmp expression in
// [Verifier.Verify] clean.
func safeStep(s uint64) int64 {
	if s > uint64(1<<62) {
		return 1 << 62
	}
	return int64(s)
}

// matchStep computes the TOTP at counter and reports whether it equals
// code. The comparison is constant-time so a partial match cannot leak
// the prefix length through timing.
func matchStep(secret, code []byte, counter uint64) bool {
	candidate := codeAtStep(secret, counter)
	return subtle.ConstantTimeCompare(code, []byte(candidate)) == 1
}

func (v *Verifier) clock() timex.Clock {
	return timex.OrSystem(v.Clock)
}

func (v *Verifier) skew() int {
	if v.Skew <= 0 {
		return defaultSkew
	}
	return v.Skew
}
