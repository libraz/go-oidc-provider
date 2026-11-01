package totp

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authn/lockout"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
)

// PromptType is the [interaction.Prompt.Type] the adapter emits. The string is
// fixed and matches the constant set [op.Authenticator.Prompts] returns.
const PromptType = "auth.totp"

// CodeFieldName is the [interaction.FieldSpec.Name] the adapter expects in
// [interaction.FormSubmission.Values]. It is exported so SPA documentation can
// reference the canonical key without a stringly-typed copy.
const CodeFieldName = "code"

// ErrSubjectRequired is returned by [Authenticator.Begin] /
// [Authenticator.Continue] when the orchestrator passes an empty
// [op.BeginInput.Subject] / [op.ContinueInput.Subject]. TOTP is always
// a second factor: the chain is mis-wired if it reaches the adapter
// without a subject bound.
var ErrSubjectRequired = errors.New("totp: subject is required")

// ErrCodeMissing is returned by [Authenticator.Continue] when the
// submission omits the code field. The orchestrator's [interaction.FieldSpec]
// validation should already have caught this; the adapter re-checks
// to keep the error path explicit at the trust boundary.
var ErrCodeMissing = fmt.Errorf("totp: code field is missing: %w", authn.ErrFactorAbort)

// ErrRetry is returned by [Authenticator.Continue] on a recoverable
// wrong-code submission. It wraps [authn.ErrFactorRetry] so the
// orchestrator observes the failure through the
// [authn.LoginAttemptObserver] feed, advances the shared brute-force
// counter, and re-emits the prompt — the same path the password factor
// takes on a wrong guess. Returning a nil-error re-prompt here instead
// would leave 2FA guesses invisible to SIEM and the captcha step-up
// gate.
var ErrRetry = fmt.Errorf("totp: wrong code: %w", authn.ErrFactorRetry)

// Authenticator is the [op.Authenticator] adapter for the RFC 6238
// TOTP factor. It binds a [Verifier] (the primitive that does the
// TOTP math + brute-force counter) to a [store.TOTPStore] (the
// persisted record) so the orchestrator can drive the factor without
// knowing about either. The optional [lockout.Counter] adds the
// cross-factor brute-force counter so an attacker pivoting between
// TOTP and email-OTP cannot double their budget. Construct through
// [NewAuthenticator]; the zero value is not usable.
type Authenticator struct {
	verifier *Verifier
	store    store.TOTPStore
	lockout  *lockout.Counter
}

// ErrVerifierRequired / ErrStoreRequired are returned by
// [NewAuthenticator] when one of its arguments is nil. Surfacing the
// configuration error at construction is preferred to a runtime panic
// on the first Begin / Continue: the caller decides whether the
// missing dependency is a fatal startup condition or a graceful
// degradation.
var (
	ErrVerifierRequired = errors.New("totp: verifier is required")
	ErrStoreRequired    = errors.New("totp: store is required")
)

// NewAuthenticator constructs an [Authenticator]. Both arguments are
// required; a nil verifier or store would surface as a panic on the
// first Begin / Continue otherwise, which is harder to diagnose than
// the construction-time error returned here.
//
// The cross-factor brute-force counter is opt-in through
// [Authenticator.WithLockout]; the zero value here observes only the
// per-record FailedCount.
func NewAuthenticator(verifier *Verifier, totpStore store.TOTPStore) (*Authenticator, error) {
	if verifier == nil {
		return nil, ErrVerifierRequired
	}
	if totpStore == nil {
		return nil, ErrStoreRequired
	}
	return &Authenticator{verifier: verifier, store: totpStore}, nil
}

// WithLockout returns a copy of a with the supplied [lockout.Counter]
// wired so the authenticator consults the cross-factor brute-force
// counter on every Begin / Continue. A nil counter disables the
// cross-factor gate (the per-record FailedCount continues to apply).
// The receiver is not mutated; the caller MUST use the returned
// pointer.
func (a *Authenticator) WithLockout(c *lockout.Counter) *Authenticator {
	cp := *a
	cp.lockout = c
	return &cp
}

// Type implements [authn.Authenticator]. Always returns [authn.FactorTOTP].
func (*Authenticator) Type() authn.FactorType { return authn.FactorTOTP }

// AAL implements [authn.Authenticator]. TOTP contributes AAL2: the
// shared secret is a possession factor distinct from a password.
func (*Authenticator) AAL() authn.AAL { return authn.AAL2 }

// AMR implements [authn.Authenticator]. TOTP maps to RFC 8176 §2 "otp".
func (*Authenticator) AMR() string { return "otp" }

// Prompts implements [authn.Authenticator]. The adapter emits a single
// prompt type; the slice is read-only by contract.
func (*Authenticator) Prompts() []string { return []string{PromptType} }

// Begin implements [authn.Authenticator]. It reads the persisted record
// for [authn.BeginInput.Subject] and emits the [PromptType] prompt with
// the current [interaction.TOTPPromptData.AttemptsRemaining]. A locked record
// surfaces [ErrLocked] verbatim so the orchestrator can stop the
// chain instead of pretending the factor is available.
func (a *Authenticator) Begin(ctx context.Context, in authn.BeginInput) (interaction.Step, error) {
	if in.Subject == "" {
		return interaction.Step{}, ErrSubjectRequired
	}
	shared, err := a.lockout.Status(ctx, in.Subject)
	if err != nil {
		return interaction.Step{}, fmt.Errorf("totp: lockout guard: %w", err)
	}
	if shared.Locked {
		return interaction.Step{}, ErrLocked
	}
	rec, err := a.store.Get(ctx, in.Subject)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return interaction.Step{}, fmt.Errorf("totp: load record: %w", err)
	}
	if err != nil || rec == nil || rec.ConfirmedAt.IsZero() {
		return interaction.Step{}, authn.ErrFactorNotEnrolled
	}
	now := a.verifier.clock().Now()
	if !rec.LockedUntil.IsZero() && rec.LockedUntil.After(now) {
		return interaction.Step{}, ErrLocked
	}
	return interaction.Step{Prompt: a.prompt(attemptsRemaining(rec, shared.Remaining, now))}, nil
}

// Enrolled implements [authn.EnrollmentProber]: subject has a confirmed
// TOTP record.
func (a *Authenticator) Enrolled(ctx context.Context, subject string) (bool, error) {
	rec, err := a.store.Get(ctx, subject)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("totp: load record: %w", err)
	}
	return rec != nil && !rec.ConfirmedAt.IsZero(), nil
}

// attemptsRemaining is the number of wrong codes the subject may still
// submit before either counter that can lock this factor does: the
// record's own, read with the same rolling window [Verifier.Verify]
// applies, and the cross-factor budget in shared.
func attemptsRemaining(rec *store.TOTPRecord, shared int, now time.Time) int {
	spent := rec.FailedCount
	if lockout.WindowExpired(rec.FirstFailureAt, now) {
		spent = 0
	}
	return min(max(lockout.ThresholdShort-spent, 0), shared)
}

// Continue implements [authn.Authenticator]. It reads the persisted
// record again (the adapter is stateless across Begin / Continue),
// verifies the submitted code through the [Verifier], and persists
// the (possibly mutated) record before returning.
// Outcomes:
//   - On [OutcomeSuccess]: [interaction.Step.Result] is populated with the
//     bound subject and the orchestrator's [authn.ContinueInput.AuthTime].
//   - On [OutcomeWrongCode] (recoverable): [interaction.Step.Prompt] is re-
//     emitted with [interaction.TOTPPromptData.AttemptsRemaining] decremented;
//     the orchestrator advances [State.StepCounter] so the previous
//     [interaction.Prompt.StateRef] is invalidated.
//   - On [OutcomeLocked] / [OutcomeResetRequired]: the matching error
//     is returned so the orchestrator stops the chain. The persisted
//     record carries the lockout stamp.
func (a *Authenticator) Continue(ctx context.Context, in authn.ContinueInput) (interaction.Step, error) {
	if in.Subject == "" {
		return interaction.Step{}, ErrSubjectRequired
	}
	code, ok := in.Submission.Values[CodeFieldName]
	if !ok || code == "" {
		return interaction.Step{}, ErrCodeMissing
	}
	if err := a.lockout.Guard(ctx, in.Subject, lockoutErrs); err != nil {
		return interaction.Step{}, err
	}
	_, verr := VerifyAndRecord(ctx, a.store, a.verifier, in.Subject, code)
	switch {
	case verr == nil:
		if rerr := a.lockout.ResetOnSuccess(ctx, in.Subject, lockoutErrs); rerr != nil {
			return interaction.Step{}, rerr
		}
		return interaction.Step{Result: &interaction.Result{Subject: in.Subject, AuthTime: in.AuthTime}}, nil
	case errors.Is(verr, ErrReplayed):
		// A replayed code is a form double-submit or a browser retry,
		// not a guess against the secret. The verifier already left
		// the record's own FailedCount alone; the cross-factor counter
		// is skipped here for the same reason, so a flaky connection
		// cannot push a legitimate user towards the shared lockout.
		// ErrRetry is still returned so the orchestrator records the
		// attempt and re-issues the prompt — a silently swallowed
		// replay would be an audit blind spot.
		return interaction.Step{}, ErrRetry
	case errors.Is(verr, ErrWrongCode):
		if lerr := a.lockout.RecordWrong(ctx, in.Subject, lockoutErrs); lerr != nil {
			return interaction.Step{}, lerr
		}
		// Recoverable wrong guess: surface ErrRetry so the orchestrator
		// records the failure and re-issues the prompt via Begin (which
		// reloads the persisted, failure-incremented record). The
		// AttemptsRemaining the SPA sees on the retry is therefore the
		// same value a.prompt would have shown here.
		return interaction.Step{}, ErrRetry
	default:
		// ErrLocked / ErrResetRequired / not-enrolled / store faults flow
		// through verbatim so the orchestrator can dispatch. The
		// cross-factor counter is intentionally NOT incremented for these
		// branches: they represent state, not a guess against the
		// credential.
		return interaction.Step{}, verr
	}
}

// prompt builds the [interaction.Prompt] the adapter emits for both Begin and
// the wrong-code re-emit branch of Continue. Centralising the shape
// here keeps the two call sites in sync; a SPA seeing two different
// prompt shapes for the same factor would be a contract bug.
func (*Authenticator) prompt(remaining int) *interaction.Prompt {
	return &interaction.Prompt{
		Type: PromptType,
		Data: interaction.TOTPPromptData{AttemptsRemaining: remaining},
		Inputs: []interaction.FieldSpec{{
			Name:     CodeFieldName,
			Kind:     interaction.FieldOTPCode,
			Label:    "auth.totp.code",
			Required: true,
			MinLen:   digits,
			MaxLen:   digits,
		}},
	}
}

// Compile-time confirmation that *Authenticator satisfies the
// public interface. The receiver is a pointer because the verifier
// and store fields are reference-typed; a value-receiver method set
// would force unnecessary copies when the orchestrator hands the
// adapter through interface boundaries.
var (
	_ authn.Authenticator    = (*Authenticator)(nil)
	_ authn.EnrollmentProber = (*Authenticator)(nil)
)
