package totp

import (
	"context"
	"errors"
	"fmt"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
)

// PromptType is the [interaction.Prompt.Type] the adapter emits. The string is
// fixed by docs/plans/002-product-design.md §E.2 and matches the
// constant set [op.Authenticator.Prompts] returns.
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

// Authenticator is the [op.Authenticator] adapter for the RFC 6238
// TOTP factor. It binds a [Verifier] (the primitive that does the
// TOTP math + brute-force counter) to a [store.TOTPStore] (the
// persisted record) so the orchestrator can drive the factor without
// knowing about either.
//
// Construct through [NewAuthenticator]; the zero value is not usable.
type Authenticator struct {
	verifier *Verifier
	store    store.TOTPStore
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
func NewAuthenticator(verifier *Verifier, totpStore store.TOTPStore) (*Authenticator, error) {
	if verifier == nil {
		return nil, ErrVerifierRequired
	}
	if totpStore == nil {
		return nil, ErrStoreRequired
	}
	return &Authenticator{verifier: verifier, store: totpStore}, nil
}

// Type implements [authn.Authenticator]. Always returns [authn.FactorTOTP].
func (*Authenticator) Type() authn.FactorType { return authn.FactorTOTP }

// AAL implements [authn.Authenticator]. TOTP contributes AAL2 — the
// RFC 8176 §2 mapping in docs/plans/002-product-design.md §E.2.
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
	rec, err := a.store.Get(ctx, in.Subject)
	if err != nil {
		return interaction.Step{}, fmt.Errorf("totp: load record: %w", err)
	}
	if rec == nil {
		return interaction.Step{}, store.ErrNotFound
	}
	if !rec.ConfirmedAt.IsZero() && !rec.LockedUntil.IsZero() && rec.LockedUntil.After(in.AuthTime) {
		return interaction.Step{}, ErrLocked
	}
	return interaction.Step{Prompt: a.prompt(rec)}, nil
}

// Continue implements [authn.Authenticator]. It reads the persisted
// record again (the adapter is stateless across Begin / Continue),
// verifies the submitted code through the [Verifier], and persists
// the (possibly mutated) record before returning.
//
// Outcomes:
//
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
	rec, err := a.store.Get(ctx, in.Subject)
	if err != nil {
		return interaction.Step{}, fmt.Errorf("totp: load record: %w", err)
	}
	if rec == nil {
		return interaction.Step{}, store.ErrNotFound
	}

	res, verr := a.verifier.Verify(ctx, rec, code)
	if res != nil && res.Record != nil && res.Outcome != OutcomeLocked {
		// OutcomeLocked is the only branch that leaves the record
		// unchanged; everything else needs persisting (success
		// clears counters, wrong-code bumps them, reset-required
		// stamps the long lock).
		if perr := a.store.Put(ctx, res.Record); perr != nil {
			return interaction.Step{}, fmt.Errorf("totp: persist record: %w", perr)
		}
	}

	switch {
	case verr == nil:
		return interaction.Step{Result: &interaction.Result{Subject: in.Subject, AuthTime: in.AuthTime}}, nil
	case errors.Is(verr, ErrWrongCode):
		return interaction.Step{Prompt: a.prompt(res.Record)}, nil
	default:
		// ErrLocked / ErrResetRequired / store-decryption failures
		// flow through verbatim so the orchestrator can dispatch.
		return interaction.Step{}, verr
	}
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
