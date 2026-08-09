package recovery

import (
	"context"
	"errors"
	"fmt"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authn/lockout"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
)

// PromptType is the [interaction.Prompt.Type] the adapter emits. The
// value is fixed; SPAs dispatch on it to pick the recovery-code screen.
const PromptType = "auth.recovery_code"

// CodeFieldName is the [interaction.FieldSpec.Name] the adapter expects in
// [interaction.FormSubmission.Values]. Exported so SPA documentation can
// reference the canonical key without a stringly-typed copy.
const CodeFieldName = "code"

// codeMaxLen / codeMinLen are the byte-length bounds the adapter
// applies on the input. The plaintext format is XXXXX-XXXXX (11 bytes
// including the hyphen); we accept the no-hyphen short form as a
// usability concession (the hash check normalises). 32 bytes is well
// above any plausible code length and bounds the input against the
// orchestrator's per-field cap.
const (
	codeMinLen = 10
	codeMaxLen = 32
)

// ErrSubjectRequired is returned by [Authenticator.Begin] /
// [Authenticator.Continue] when the orchestrator passes an empty
// subject. Recovery codes are always a substitute factor: the chain
// is mis-wired if it reaches the adapter without a subject bound.
var ErrSubjectRequired = errors.New("recovery: subject is required")

// ErrCodeMissing is returned by [Authenticator.Continue] when the
// submission omits the code field. The orchestrator's [interaction.FieldSpec]
// validation should already have caught this; the adapter re-checks
// at the trust boundary.
var ErrCodeMissing = errors.New("recovery: code field is missing")

// ErrLocked is returned when the shared cross-factor brute-force gate
// is locked for the subject.
var ErrLocked = fmt.Errorf("recovery: factor is locked: %w", authn.ErrFactorAbort)

// ErrResetRequired is returned when the shared cross-factor counter
// crosses the long threshold and the user must reset/recover factors.
var ErrResetRequired = fmt.Errorf("recovery: factor reset required: %w", authn.ErrFactorAbort)

// ErrRetry is returned by [Authenticator.Continue] on a recoverable
// wrong-code submission. It wraps [authn.ErrFactorRetry] so the
// orchestrator observes the failure through the
// [authn.LoginAttemptObserver] feed, advances the shared brute-force
// counter, and re-emits the prompt — the same path the password factor
// takes on a wrong guess. Returning a nil-error re-prompt here instead
// would leave recovery-code guesses invisible to SIEM and the captcha
// step-up gate.
var ErrRetry = fmt.Errorf("recovery: invalid code: %w", authn.ErrFactorRetry)

// Authenticator is the [op.Authenticator] adapter for the single-use
// recovery-code factor. It binds a [Verifier] (the primitive that
// hashes / matches / consumes codes) to a [store.RecoveryStore] (the
// persisted batch) so the orchestrator can drive the factor without
// knowing about either.
// Construct through [NewAuthenticator]; the zero value is not usable.
type Authenticator struct {
	verifier *Verifier
	store    store.RecoveryStore
	lockout  *lockout.Counter
}

// ErrVerifierRequired / ErrStoreRequired are returned by
// [NewAuthenticator] when one of its arguments is nil. Surfacing the
// configuration error at construction is preferred to a runtime panic
// on the first Begin / Continue.
var (
	ErrVerifierRequired = errors.New("recovery: verifier is required")
	ErrStoreRequired    = errors.New("recovery: store is required")
)

// NewAuthenticator constructs an [Authenticator]. Both arguments are
// required; the function returns an error rather than panicking on a
// nil dependency so callers can surface the misconfiguration through
// their normal startup error path.
func NewAuthenticator(verifier *Verifier, recoveryStore store.RecoveryStore) (*Authenticator, error) {
	if verifier == nil {
		return nil, ErrVerifierRequired
	}
	if recoveryStore == nil {
		return nil, ErrStoreRequired
	}
	return &Authenticator{verifier: verifier, store: recoveryStore}, nil
}

// WithLockout returns a copy of a with the supplied cross-factor
// brute-force counter. A nil counter leaves the authenticator unchanged.
func (a *Authenticator) WithLockout(c *lockout.Counter) *Authenticator {
	cp := *a
	cp.lockout = c
	return &cp
}

// Type implements [authn.Authenticator]. Always returns
// [authn.FactorRecoveryCode].
func (*Authenticator) Type() authn.FactorType { return authn.FactorRecoveryCode }

// AAL implements [authn.Authenticator]. Recovery codes are a substitute
// for AAL2 — the primary MFA factor the user lost.
func (*Authenticator) AAL() authn.AAL { return authn.AAL2 }

// AMR implements [authn.Authenticator]. Recovery codes map to RFC 8176
// §2 "otp" (single-use shared-secret-derived code).
func (*Authenticator) AMR() string { return "otp" }

// Prompts implements [authn.Authenticator]. The adapter emits a single
// prompt type; the slice is read-only by contract.
func (*Authenticator) Prompts() []string { return []string{PromptType} }

// Begin implements [authn.Authenticator]. It reads the persisted batch
// to surface [interaction.RecoveryCodePromptData.AttemptsRemaining] (the count
// of unconsumed slots) and emits the [PromptType] prompt. Begin
// surfaces [store.ErrNotFound] when the user has no batch generated
// so the orchestrator can stop the chain rather than silently rolling
// over to the next factor.
func (a *Authenticator) Begin(ctx context.Context, in authn.BeginInput) (interaction.Step, error) {
	if in.Subject == "" {
		return interaction.Step{}, ErrSubjectRequired
	}
	if a.lockout != nil {
		if err := a.lockout.GuardBegin(ctx, in.Subject); err != nil {
			if errors.Is(err, lockout.ErrLocked) {
				return interaction.Step{}, ErrLocked
			}
			return interaction.Step{}, fmt.Errorf("recovery: lockout guard: %w", err)
		}
	}
	batch, err := a.store.Get(ctx, in.Subject)
	if err != nil {
		return interaction.Step{}, fmt.Errorf("recovery: load batch: %w", err)
	}
	if batch == nil {
		return interaction.Step{}, store.ErrNotFound
	}
	return interaction.Step{Prompt: a.prompt(batch)}, nil
}

// Continue implements [authn.Authenticator]. It loads the batch,
// verifies the submitted code through the [Verifier], persists the
// mutated batch on success, and returns the matching [interaction.Step]:
//   - On [OutcomeSuccess]: [interaction.Step.Result] is populated with the
//     bound subject and the orchestrator's
//     [authn.ContinueInput.AuthTime]. The persisted batch carries the
//     stamped ConsumedAt on the matched slot.
//   - On [OutcomeInvalid]: [interaction.Step.Prompt] is re-emitted with
//     [interaction.RecoveryCodePromptData.AttemptsRemaining] unchanged (no slot
//     was consumed).
//   - On [OutcomeAllConsumed] / [OutcomeNoCodes]: the matching error
//     is returned so the orchestrator stops the chain.
func (a *Authenticator) Continue(ctx context.Context, in authn.ContinueInput) (interaction.Step, error) { //nolint:gocognit,cyclop // Recovery-code verification branches mirror the factor state machine.
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
			return interaction.Step{}, fmt.Errorf("recovery: lockout guard: %w", err)
		}
	}
	batch, err := a.store.Get(ctx, in.Subject)
	if err != nil {
		return interaction.Step{}, fmt.Errorf("recovery: load batch: %w", err)
	}
	if batch == nil {
		return interaction.Step{}, store.ErrNotFound
	}

	res, verr := a.verifier.Verify(ctx, batch, code)
	switch {
	case verr == nil:
		if perr := a.store.Consume(ctx, res.Batch, res.Index); perr != nil {
			if errors.Is(perr, store.ErrAlreadyConsumed) {
				// A concurrent request already consumed this slot (a
				// replay lost the CAS). Surface ErrRetry rather than a
				// silent nil re-prompt so the orchestrator emits the
				// LoginAttempt observer event and advances the counter —
				// the sibling email-OTP factor is non-silent in the same
				// case, and a swallowed replay is an audit blind spot.
				return interaction.Step{}, ErrRetry
			}
			return interaction.Step{}, fmt.Errorf("recovery: consume batch: %w", perr)
		}
		if a.lockout != nil {
			if rerr := a.lockout.Reset(ctx, in.Subject); rerr != nil {
				return interaction.Step{}, fmt.Errorf("recovery: lockout reset: %w", rerr)
			}
		}
		return interaction.Step{Result: &interaction.Result{Subject: in.Subject, AuthTime: in.AuthTime}}, nil
	case errors.Is(verr, ErrCodeInvalid):
		if a.lockout != nil {
			out, lerr := a.lockout.RecordFailure(ctx, in.Subject)
			if lerr != nil {
				return interaction.Step{}, fmt.Errorf("recovery: lockout record failure: %w", lerr)
			}
			if out.ResetRequired {
				return interaction.Step{}, ErrResetRequired
			}
			if !out.LockedUntil.IsZero() {
				return interaction.Step{}, ErrLocked
			}
		}
		// Recoverable wrong guess: surface ErrRetry so the orchestrator
		// records the failure and advances the brute-force counter, then
		// re-issues the prompt via Begin.
		return interaction.Step{}, ErrRetry
	default:
		// ErrAllConsumed / ErrNoCodes / hash-format failures flow
		// through verbatim so the orchestrator can dispatch to the
		// out-of-band recovery branch.
		return interaction.Step{}, verr
	}
}

// prompt builds the [interaction.Prompt] the adapter emits on Begin and on
// the wrong-code re-emit branch of Continue. Centralising the shape
// here keeps the two call sites in sync.
func (*Authenticator) prompt(batch *store.RecoveryBatch) *interaction.Prompt {
	remaining := 0
	for _, slot := range batch.Codes {
		if slot.ConsumedAt.IsZero() {
			remaining++
		}
	}
	return &interaction.Prompt{
		Type: PromptType,
		Data: interaction.RecoveryCodePromptData{AttemptsRemaining: remaining},
		Inputs: []interaction.FieldSpec{{
			Name:     CodeFieldName,
			Kind:     interaction.FieldText,
			Label:    "auth.recovery_code.code",
			Required: true,
			MinLen:   codeMinLen,
			MaxLen:   codeMaxLen,
		}},
	}
}

// Compile-time confirmation that *Authenticator satisfies the public
// interface.
var _ authn.Authenticator = (*Authenticator)(nil)
