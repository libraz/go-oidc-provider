package totp

import (
	"context"
	"errors"
	"fmt"
	"slices"

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

// digitCount is the RFC 6238 default code length the verifier expects
// (the same constant lives in the verifier internals as `digits`). The
// adapter pins MinLen / MaxLen on its [interaction.FieldSpec] to that length so
// a SPA cannot submit a partial code.
const digitCount = 6

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
var ErrCodeMissing = errors.New("totp: code field is missing")

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
	if a.lockout != nil {
		if err := a.lockout.GuardBegin(ctx, in.Subject); err != nil {
			if errors.Is(err, lockout.ErrLocked) {
				return interaction.Step{}, ErrLocked
			}
			return interaction.Step{}, fmt.Errorf("totp: lockout guard: %w", err)
		}
	}
	rec, err := a.store.Get(ctx, in.Subject)
	if err != nil {
		return interaction.Step{}, fmt.Errorf("totp: load record: %w", err)
	}
	if rec == nil {
		return interaction.Step{}, store.ErrNotFound
	}
	now := a.verifier.clock().Now()
	if !rec.ConfirmedAt.IsZero() && !rec.LockedUntil.IsZero() && rec.LockedUntil.After(now) {
		return interaction.Step{}, ErrLocked
	}
	return interaction.Step{Prompt: a.prompt(rec)}, nil
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
//
//nolint:gocognit,cyclop // verify path enumerates lockout / replay / window branches in flat shape; refactor would obscure spec mapping.
func (a *Authenticator) Continue(ctx context.Context, in authn.ContinueInput) (interaction.Step, error) {
	if in.Subject == "" {
		return interaction.Step{}, ErrSubjectRequired
	}
	code, ok := in.Submission.Values[CodeFieldName]
	if !ok || code == "" {
		return interaction.Step{}, ErrCodeMissing
	}
	if a.lockout != nil {
		if err := a.lockout.GuardBegin(ctx, in.Subject); err != nil {
			if errors.Is(err, lockout.ErrLocked) {
				return interaction.Step{}, ErrLocked
			}
			return interaction.Step{}, fmt.Errorf("totp: lockout guard: %w", err)
		}
	}
	for retries := 0; ; retries++ {
		if retries == 16 {
			return interaction.Step{}, ErrRetry
		}
		rec, err := a.store.Get(ctx, in.Subject)
		if err != nil {
			return interaction.Step{}, fmt.Errorf("totp: load record: %w", err)
		}
		if rec == nil {
			return interaction.Step{}, store.ErrNotFound
		}

		previous := cloneRecord(rec)
		res, verr := a.verifier.Verify(ctx, rec, code)
		if res != nil && res.Record != nil && res.Outcome != OutcomeLocked && res.Outcome != OutcomeSuccess {
			// OutcomeLocked leaves the record unchanged and OutcomeSuccess
			// is persisted through atomic Accept below. Wrong-code and
			// reset-required branches use CAS to retain every update.
			if perr := a.store.CompareAndSwap(ctx, previous, res.Record); perr != nil {
				if errors.Is(perr, store.ErrAlreadyConsumed) {
					// Re-read and re-verify against the latest record so a
					// finite set of concurrent wrong guesses increments the
					// counter once per request instead of losing updates.
					continue
				}
				return interaction.Step{}, fmt.Errorf("totp: persist record: %w", perr)
			}
		}

		switch {
		case verr == nil:
			if perr := a.store.Accept(ctx, res.Record); perr != nil {
				if errors.Is(perr, store.ErrAlreadyConsumed) {
					// A concurrent request already consumed this code (a
					// replay lost the CAS). Surface ErrRetry rather than a
					// silent nil re-prompt so the orchestrator emits the
					// LoginAttempt observer event and advances the counter —
					// the sibling email-OTP factor is non-silent in the same
					// case, and a swallowed replay is an audit blind spot.
					return interaction.Step{}, ErrRetry
				}
				return interaction.Step{}, fmt.Errorf("totp: accept record: %w", perr)
			}
			if a.lockout != nil {
				if rerr := a.lockout.Reset(ctx, in.Subject); rerr != nil {
					return interaction.Step{}, fmt.Errorf("totp: lockout reset: %w", rerr)
				}
			}
			return interaction.Step{Result: &interaction.Result{Subject: in.Subject, AuthTime: in.AuthTime}}, nil
		case errors.Is(verr, ErrWrongCode):
			if a.lockout != nil {
				out, lerr := a.lockout.RecordFailure(ctx, in.Subject)
				if lerr != nil {
					return interaction.Step{}, fmt.Errorf("totp: lockout record failure: %w", lerr)
				}
				if out.ResetRequired {
					return interaction.Step{}, ErrResetRequired
				}
				if !out.LockedUntil.IsZero() {
					return interaction.Step{}, ErrLocked
				}
			}
			// Recoverable wrong guess: surface ErrRetry so the orchestrator
			// records the failure and re-issues the prompt via Begin (which
			// reloads the persisted, failure-incremented record). The
			// AttemptsRemaining the SPA sees on the retry is therefore the
			// same value a.prompt would have shown here.
			return interaction.Step{}, ErrRetry
		default:
			// ErrLocked / ErrResetRequired / store-decryption failures
			// flow through verbatim so the orchestrator can dispatch.
			// The cross-factor counter is intentionally NOT incremented
			// for these branches: they represent state, not a guess
			// against the credential.
			return interaction.Step{}, verr
		}
	}
}

func cloneRecord(r *store.TOTPRecord) *store.TOTPRecord {
	if r == nil {
		return nil
	}
	out := *r
	out.SecretCiphertext = slices.Clone(r.SecretCiphertext)
	return &out
}

// prompt builds the [interaction.Prompt] the adapter emits for both Begin and
// the wrong-code re-emit branch of Continue. Centralising the shape
// here keeps the two call sites in sync; a SPA seeing two different
// prompt shapes for the same factor would be a contract bug.
func (*Authenticator) prompt(rec *store.TOTPRecord) *interaction.Prompt {
	remaining := lockThresholdShort - rec.FailedCount
	if remaining < 0 {
		remaining = 0
	}
	return &interaction.Prompt{
		Type: PromptType,
		Data: interaction.TOTPPromptData{AttemptsRemaining: remaining},
		Inputs: []interaction.FieldSpec{{
			Name:     CodeFieldName,
			Kind:     interaction.FieldOTPCode,
			Label:    "auth.totp.code",
			Required: true,
			MinLen:   digitCount,
			MaxLen:   digitCount,
		}},
	}
}

// Compile-time confirmation that *Authenticator satisfies the
// public interface. The receiver is a pointer because the verifier
// and store fields are reference-typed; a value-receiver method set
// would force unnecessary copies when the orchestrator hands the
// adapter through interface boundaries.
var _ authn.Authenticator = (*Authenticator)(nil)
