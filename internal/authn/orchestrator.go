package authn

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn/audit"
	"github.com/libraz/go-oidc-provider/internal/authn/risk"
	internallog "github.com/libraz/go-oidc-provider/internal/log"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

// captchaFailureThreshold is the number of consecutive
// [AttemptFailure] outcomes that triggers an interstitial
// [interaction.CaptchaPromptData] before the next factor begins. The
// default matches the library's brute-force gate; deployments that need
// a different threshold drive the same logic through their own
// [LoginAttemptObserver] and bump [State.LastFailures] externally.
// Captcha events themselves do NOT increment the counter — captcha is
// out-of-band from the brute-force feed.
const captchaFailureThreshold = 3

// stateRefTTL is how long an issued [interaction.Prompt.StateRef] stays valid
// from the orchestrator's perspective. The default is short enough to
// rule out long-tail replay attacks but long enough to outlast a
// reasonable user pause on the SPA. Embedders that want a different
// value will get an option in a follow-up; the constant is internal
// to the orchestrator state machine.
const stateRefTTL = 10 * time.Minute

// Config is the [Orchestrator] construction payload. It mirrors the
// public-API options the [op.Provider] accumulates; the HTTP layer
// wires the two together. Fields with comments marked "optional"
// may be nil; the orchestrator handles the missing dependency by
// skipping the corresponding phase.
type Config struct {
	// Authenticators is the registered factor list in
	// [op.WithAuthenticators] order. The orchestrator picks the
	// first candidate that meets the per-tick constraints; risk
	// directives reorder the choice without mutating the slice.
	Authenticators []Authenticator

	// Interactions is the registered interaction list. The
	// orchestrator inserts each entry per its
	// [InteractionTrigger]; intra-trigger ordering follows
	// registration order.
	Interactions []Interaction

	// Risk is the optional [RiskAssessor] consulted at every
	// [RiskStage] callsite. Nil means "always allow" (the
	// orchestrator skips the consult).
	Risk RiskAssessor

	// Captcha is the optional [CaptchaVerifier]. Nil disables
	// the captcha challenge: the orchestrator never emits the
	// CaptchaPromptData even when [State.LastFailures] reaches the
	// threshold (a deployment without a configured verifier would
	// otherwise loop on a token it cannot validate).
	Captcha CaptchaVerifier

	// Observers receives one [LoginAttempt] per factor outcome.
	// The slice is fanned out in registration order.
	Observers []LoginAttemptObserver

	// StateRefSigner signs every [interaction.Prompt.StateRef]. Required.
	StateRefSigner *StateRefSigner

	// Logger is the structured logger the orchestrator writes
	// warning records to (e.g., when an [Authenticator.AMR]
	// return is dropped because it is not RFC 8176-registered).
	// Nil means "discard"; the orchestrator never panics on a nil
	// logger.
	Logger *slog.Logger

	// LoginFlow is the optional compiled high-level flow. Mutually
	// exclusive with [Authenticators] at construction time: the public
	// option layer rejects the combination at op.New, and [New] here
	// re-asserts the invariant so the internal package surface is
	// also self-protecting.
	// When non-nil the orchestrator drives the chain through
	// [advanceLoginFlow] instead of the legacy [advanceAuthn] path.
	// Risk, Captcha, and Observers continue to work; the differences
	// are: factor selection follows [CompiledLoginFlow.primary] +
	// [CompiledLoginFlow.rules] / [CompiledLoginFlow.decider]
	// instead of the [Config.Authenticators] slice; Risk is invoked
	// at most once per chain (see [State.RiskScoreCached]); panic
	// recovery wraps every embedder predicate / decider.
	LoginFlow *CompiledLoginFlow
}

// Orchestrator runs the authenticator chain state machine. It is a
// pure value: every method is deterministic given its inputs, and the
// orchestrator owns no I/O of its own. The HTTP layer persists [State]
// between calls; the orchestrator returns updated state for the
// caller to write back.
type Orchestrator struct {
	cfg            Config
	logger         *slog.Logger
	auditObservers []audit.Observer
	riskAssessor   risk.Assessor
}

// New constructs an [Orchestrator] from cfg. It validates that the
// chain is non-empty, that authenticators have unique [FactorType]
// values, that interactions have unique [Interaction.Name] values,
// and that the StateRef signer is non-nil. Errors here surface at
// [op.New] construction time so deployment misconfigurations cannot
// reach the first request.
func New(cfg Config) (*Orchestrator, error) {
	if err := validateChainShape(cfg); err != nil {
		return nil, err
	}
	if cfg.StateRefSigner == nil {
		return nil, errors.New("authn: StateRefSigner required")
	}
	if err := validateAuthenticators(cfg.Authenticators); err != nil {
		return nil, err
	}
	seenName := make(map[string]struct{}, len(cfg.Interactions))
	deduped := make([]Interaction, 0, len(cfg.Interactions))
	for _, ix := range cfg.Interactions {
		if ix == nil {
			return nil, errors.New("authn: nil Interaction")
		}
		name := ix.Name()
		if name == "" {
			return nil, errors.New("authn: Interaction.Name must not be empty")
		}
		if _, dup := seenName[name]; dup {
			continue
		}
		seenName[name] = struct{}{}
		deduped = append(deduped, ix)
	}
	cfg.Interactions = deduped
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(internallog.DiscardHandler{})
	}
	return &Orchestrator{
		cfg:            cfg,
		logger:         logger,
		auditObservers: wrapAuditObservers(cfg.Observers),
		riskAssessor:   wrapRiskAssessor(cfg.Risk),
	}, nil
}

// validateChainShape enforces the LoginFlow / Authenticators
// either-or invariant: exactly one of the two must be supplied.
// Split out so [New] stays under the gocognit ceiling now that
// LoginFlow added a third construction-time precondition.
func validateChainShape(cfg Config) error {
	if cfg.LoginFlow != nil && len(cfg.Authenticators) > 0 {
		return errors.New("authn: LoginFlow and Authenticators are mutually exclusive")
	}
	if cfg.LoginFlow == nil && len(cfg.Authenticators) == 0 {
		return errors.New("authn: at least one Authenticator required")
	}
	return nil
}

// validateAuthenticators rejects nil entries and duplicate
// [FactorType] values in the legacy chain. The LoginFlow path does
// not flow through this helper — its primary / rule steps are
// validated by [CompileLoginFlow] at op.New time.
func validateAuthenticators(auths []Authenticator) error {
	seen := make(map[FactorType]struct{}, len(auths))
	for _, a := range auths {
		if a == nil {
			return errors.New("authn: nil Authenticator")
		}
		t := a.Type()
		if _, dup := seen[t]; dup {
			return fmt.Errorf("authn: duplicate Authenticator type %q", t)
		}
		seen[t] = struct{}{}
	}
	return nil
}

// Tick advances st by one orchestrator step. The method is pure: no
// goroutines, no [time.Now()], no network. Tick returns the updated
// [State] (always — even on error, so the HTTP layer can persist
// counters that did update before the failure) and the [interaction.Step] the
// SPA should render next, if any.
// The state machine, in order:
//  1. Reject ticks against a completed chain ([ErrChainComplete]).
//  2. If a submission is present, route it to the entity that issued
//     the StateRef (captcha verifier, active authenticator, or active
//     interaction) and advance.
//  3. Run the [PhaseBeforeAuthn] interaction queue.
//  4. Run [PhaseAuthn]: consult risk, pick a candidate, emit Begin.
//  5. Run the [PhaseAfterAuthn] interaction queue.
//  6. Emit the terminal [interaction.Step] from [PhaseDone].
func (o *Orchestrator) Tick(ctx context.Context, st State, in Input) (State, interaction.Step, error) {
	if st.Phase == PhaseDone {
		return st, interaction.Step{}, ErrChainComplete
	}
	if st.InteractionsRun == nil {
		st.InteractionsRun = map[string]bool{}
	}

	if in.Submission != nil {
		next, step, err := o.consumeSubmission(ctx, st, in)
		if err != nil {
			return next, interaction.Step{}, err
		}
		if step.Prompt != nil || step.Result != nil {
			return next, step, nil
		}
		st = next
	}

	return o.advance(ctx, st, in)
}

// consumeSubmission routes a non-nil submission to whichever entity
// issued the StateRef, returning either an emitted Prompt (factor
// continues, captcha re-emitted) or a zero Step that lets advance run
// the next phase from a clean state.
func (o *Orchestrator) consumeSubmission(ctx context.Context, st State, in Input) (State, interaction.Step, error) {
	payload, err := o.cfg.StateRefSigner.Verify(in.Submission.StateRef, st.InteractionUID, st.StepCounter, in.Now)
	if err != nil {
		return st, interaction.Step{}, ErrInvalidStateRef
	}
	switch {
	case payload.Tag == tagCaptcha:
		return o.handleCaptchaSubmission(ctx, st, in)
	case strings.HasPrefix(payload.Tag, tagAuthPrefix):
		return o.handleAuthSubmission(ctx, st, in)
	case strings.HasPrefix(payload.Tag, tagInteractionPrefix):
		return o.handleInteractionSubmission(ctx, st, in)
	case strings.HasPrefix(payload.Tag, tagLoginFlowPrefix):
		return o.handleLoginFlowSubmission(ctx, st, in, strings.TrimPrefix(payload.Tag, tagLoginFlowPrefix))
	default:
		return st, interaction.Step{}, ErrInvalidStateRef
	}
}

// handleCaptchaSubmission validates the captcha token; on success
// CaptchaPassed flips and the chain advances, on failure the captcha
// Prompt is re-emitted with a fresh nonce (the StepCounter still
// increments so the previous token cannot replay). Captcha events do
// NOT call observers — captcha is intentionally out-of-band from the
// brute-force feed.
func (o *Orchestrator) handleCaptchaSubmission(ctx context.Context, st State, in Input) (State, interaction.Step, error) {
	if o.cfg.Captcha == nil {
		return st, interaction.Step{}, ErrInvalidStateRef
	}
	captchaIn := CaptchaInput{
		Token:    in.CaptchaToken,
		RemoteIP: st.RemoteIP,
	}
	if err := o.cfg.Captcha.Verify(ctx, captchaIn); err != nil {
		next, step, err2 := o.emitCaptchaPrompt(st, in.Now)
		if err2 != nil {
			return st, interaction.Step{}, err2
		}
		return next, step, nil
	}
	st.CaptchaPassed = true
	st.LastFailures = 0
	return st, interaction.Step{}, nil
}

// handleAuthSubmission delegates the submission to the active
// authenticator, observes the outcome, and runs PostFactor risk if
// configured.
func (o *Orchestrator) handleAuthSubmission(ctx context.Context, st State, in Input) (State, interaction.Step, error) {
	if st.ActiveFactorIdx < 0 || st.ActiveFactorIdx >= len(o.cfg.Authenticators) {
		return st, interaction.Step{}, ErrInvalidStateRef
	}
	auth := o.cfg.Authenticators[st.ActiveFactorIdx]
	step, err := auth.Continue(ctx, ContinueInput{
		Subject:         st.Subject,
		ClientID:        st.ClientID,
		AuthTime:        st.AuthTime,
		Submission:      *in.Submission,
		Scratch:         st.FactorScratch,
		RequestedScopes: st.RequestedScopes,
		ChooserGroupID:  st.ChooserGroupID,
	})
	if err != nil {
		o.observeFailure(ctx, st, in.Now, auth.Type())
		// Soft failures wrap [ErrFactorRetry]; observe the failure
		// (already done), advance the brute-force counter, and
		// re-emit the factor's prompt so the SPA can offer a retry.
		// Hard failures bubble up so the HTTP layer can surface 5xx /
		// 4xx unchanged. Scratch is cleared only on the hard-failure
		// path; the retry helper decides whether to preserve it (a
		// multi-step factor re-showing its current sub-step) or reset
		// it (a single-step factor restarting via Begin).
		if errors.Is(err, ErrFactorRetry) {
			return o.softRetryAuthFactor(ctx, st, auth, step, in.Now, err)
		}
		st.FactorScratch = nil
		return st, interaction.Step{}, err
	}
	if step.Prompt != nil {
		next, emitted, ferr := o.emitFactorPrompt(st, auth, step, in.Now)
		if ferr != nil {
			return st, interaction.Step{}, ferr
		}
		return next, emitted, nil
	}
	if step.Result == nil {
		return st, interaction.Step{}, ErrInvalidStep
	}
	if rerr := guardAAL3RequiresUV(auth, *step.Result); rerr != nil {
		return st, interaction.Step{}, rerr
	}
	st.FactorScratch = nil
	st = o.appendFactor(st, auth, *step.Result)
	o.observeSuccess(ctx, st, in.Now, auth.Type())
	denied, derr := o.runRiskPostFactor(ctx, st, in.Now, auth.Type())
	if derr != nil {
		return st, interaction.Step{}, derr
	}
	if denied {
		return st, interaction.Step{}, ErrRiskDenied
	}
	st.ActiveFactorIdx = -1
	st.Phase = PhaseAfterAuthn
	return st, interaction.Step{}, nil
}

// softRetryAuthFactor advances the brute-force counter and re-emits
// the active factor's prompt after a soft credential failure. The
// helper is split out of [handleAuthSubmission] so the latter stays
// under the gocognit ceiling. origErr is the [ErrFactorRetry]-wrapped
// error from the authenticator's Continue; we surface it verbatim
// when Begin cannot produce a retry prompt so the HTTP layer renders
// the original auth-failure response rather than swallowing the
// failure into a generic 5xx.
func (o *Orchestrator) softRetryAuthFactor(ctx context.Context, st State, auth Authenticator, cont interaction.Step, now time.Time, origErr error) (State, interaction.Step, error) {
	st.LastFailures++
	// A multi-step factor (e.g. email-OTP on its verify screen) returns
	// the sub-prompt to re-show alongside ErrFactorRetry. Preserve its
	// scratch (emitFactorPrompt mirrors cont.Scratch into
	// [State.FactorScratch]) so the retry stays on the same sub-step
	// instead of restarting the factor at its first screen and
	// discarding any delivered challenge.
	if cont.Prompt != nil {
		next, emitted, perr := o.emitFactorPrompt(st, auth, cont, now)
		if perr != nil {
			return st, interaction.Step{}, perr
		}
		return next, emitted, nil
	}
	// Single-step factor: restart via Begin. Clear the scratch first so
	// the re-issued prompt starts from a clean slate.
	st.FactorScratch = nil
	retry, berr := auth.Begin(ctx, BeginInput{
		Subject:  st.Subject,
		ClientID: st.ClientID,
		AuthTime: st.AuthTime,
		Client:   st.Client,
	})
	if berr != nil || retry.Prompt == nil {
		return st, interaction.Step{}, origErr
	}
	next, emitted, perr := o.emitFactorPrompt(st, auth, retry, now)
	if perr != nil {
		return st, interaction.Step{}, perr
	}
	return next, emitted, nil
}

// handleInteractionSubmission dispatches to the active interaction;
// successful Result transitions to the next phase.
func (o *Orchestrator) handleInteractionSubmission(ctx context.Context, st State, in Input) (State, interaction.Step, error) {
	idx := o.findInteractionIndex(st.ActiveInteractionName)
	if idx < 0 {
		return st, interaction.Step{}, ErrInvalidStateRef
	}
	ix := o.cfg.Interactions[idx]
	step, err := ix.Continue(ctx, ContinueInput{
		Subject:         st.Subject,
		ClientID:        st.ClientID,
		AuthTime:        st.AuthTime,
		Submission:      *in.Submission,
		RequestedScopes: st.RequestedScopes,
		ChooserGroupID:  st.ChooserGroupID,
	})
	if err != nil {
		return st, interaction.Step{}, err
	}
	if step.Prompt != nil {
		next, emitted, ferr := o.emitInteractionPrompt(st, ix, *step.Prompt, in.Now)
		if ferr != nil {
			return st, interaction.Step{}, ferr
		}
		return next, emitted, nil
	}
	if step.Result == nil {
		return st, interaction.Step{}, ErrInvalidStep
	}
	st = recordInteractionResult(st, ix.Name(), *step.Result)
	if ix.Name() == BuiltinChooserName {
		// Capture the picked SessionID so the HTTP layer can call
		// sessions.Manager.Switch at terminal-tick time instead of
		// issuing a fresh chooser group. The chooser interaction
		// has already validated the value belongs to the active
		// chooser group.
		if in.Submission != nil {
			st.ChooserSelectedSessionID = in.Submission.Values[ChooserSessionIDField]
		}
	}
	st.InteractionsRun[ix.Name()] = true
	st.ActiveInteractionName = ""
	return st, interaction.Step{}, nil
}

// recordInteractionResult folds a non-authn [interaction.Result] into
// [State]. The function exists so the Begin-completes-immediately path
// (advanceInteractions) and the Continue-completes path
// (handleInteractionSubmission) record the same fields.
// Today two fields are folded: Result.Scope (consent) and
// Result.Subject (the singular built-in chooser exception).
// User-extension interactions MUST leave Subject empty; the
// orchestrator gates Subject propagation on the reserved chooser
// name to enforce this in code.
func recordInteractionResult(st State, name string, res interaction.Result) State {
	if len(res.Scope) > 0 {
		st.ApprovedScopes = append([]string(nil), res.Scope...)
	}
	if res.Subject != "" && name == BuiltinChooserName {
		st.Subject = res.Subject
		st.ChooserBoundSubject = true
	}
	return st
}

// BuiltinChooserName is the [Interaction.Name] reserved for the
// built-in account chooser. The orchestrator references the name
// to gate Subject propagation in [recordInteractionResult] and to
// short-circuit the factor chain in [Orchestrator.advanceOnce]
// when the chooser binds a subject. The constant lives in this
// package (rather than internal/authn/chooser) so the orchestrator
// can reference it without an import cycle.
const BuiltinChooserName = "chooser"

// ChooserSessionIDField is the [interaction.FormSubmission] field name
// the chooser screen submits the picked SessionID under. The orchestrator
// reads it directly so the HTTP layer can drive a session-cookie rebind
// at terminal-tick time without depending on the chooser package.
const ChooserSessionIDField = "session_id"

// ChooserPromptType is the [interaction.Prompt.Type] the built-in
// chooser emits. SPA dispatchers route on it to render the chooser
// screen.
const ChooserPromptType = "interaction.chooser"

// guardAAL3RequiresUV enforces the rule that an authenticator
// reporting [AAL3] MUST have completed user verification (the
// [interaction.Result.UserVerified] bit is true). NIST SP 800-63B
// AAL3 requires UV; a passkey assertion that did not perform UV
// cannot satisfy AAL3, and trusting the chain to "round up" through
// orchestrator policy would silently mint a session at a higher
// assurance level than the factor actually achieved.
//
// The gate fires only on authenticators that report AAL3. AAL2 and
// below pass unconditionally; foreign / out-of-range AAL values pass
// (the aggregator will treat them defensively). The check runs before
// [appendFactor] so a factor that fails the gate never lands in
// [State.Factors] and the chain-fatal error surfaces to the HTTP
// layer for an explicit reject.
func guardAAL3RequiresUV(auth Authenticator, result interaction.Result) error {
	if auth == nil || auth.AAL() != AAL3 {
		return nil
	}
	if result.UserVerified {
		return nil
	}
	return ErrAAL3RequiresUV
}

// appendFactor is the single point where the orchestrator records a
// successful authenticator run. It enforces the invariant that only
// RFC 8176-registered AMR values reach the session: an unregistered
// return is logged and dropped (the Factor still contributes through
// [Factor.AMRValue] which derives from [FactorType]).
func (o *Orchestrator) appendFactor(st State, auth Authenticator, result interaction.Result) State {
	if amr := auth.AMR(); amr != "" && !IsRegisteredAMR(amr) {
		o.logger.Warn("authn: dropping unregistered AMR value",
			slog.String("authenticator_type", string(auth.Type())),
			slog.String("amr", amr),
		)
	}
	uv := false
	if auth.Type() == FactorPasskey {
		uv = resolvePasskeyUV(auth, result)
	}
	st.Factors = append(st.Factors, Factor{
		Type:           auth.Type(),
		AssuranceLevel: auth.AAL(),
		UserVerified:   uv,
	})
	if result.Subject != "" {
		st.Subject = result.Subject
	}
	if !result.AuthTime.IsZero() {
		st.AuthTime = result.AuthTime
	}
	return st
}

// resolvePasskeyUV picks the UV bit to stamp on [Factor.UserVerified]
// using the precedence chain documented at [appendFactor]:
//
//  1. [interaction.Result.UserVerified] (request-scoped, replica-safe;
//     the built-in passkey adapter populates it).
//  2. The deprecated [UserVerificationReporter] interface (legacy
//     embedder-supplied adapters that have not migrated; the
//     orchestrator consults the hook only when the Result is silent).
//  3. Conservative default: false. The orchestrator deliberately
//     does NOT consult [Authenticator.AMR] here — the built-in
//     adapter returns "hwk" unconditionally, so a static AMR fall-
//     back would over-report UV when an assertion's real flag is
//     false. Legacy adapters that need to surface UV=false MUST
//     implement [UserVerificationReporter]; adapters that wire
//     neither path produce UV=false and the AMR derivation in
//     [Factor.AMRValue] picks "swk" (presence-only).
//
// Step 2 takes the reporter's verdict verbatim — including a "false"
// — so an embedder that explicitly downgrades a presence-only
// assertion through the reporter is honoured.
func resolvePasskeyUV(auth Authenticator, result interaction.Result) bool {
	if result.UserVerified {
		return true
	}
	if reporter, ok := auth.(UserVerificationReporter); ok {
		return reporter.LastUserVerified(result.Subject)
	}
	return false
}

// StateRef tag prefixes. The orchestrator inspects the prefix to
// route a submission to the correct verifier; the strings are part of
// the signed payload, so tampering is detected by the HMAC.
const (
	tagCaptcha           = "captcha"
	tagAuthPrefix        = "auth:"
	tagInteractionPrefix = "interaction:"
	// tagLoginFlowPrefix carries the active LoginFlow [StepKind] so
	// a submission against a LoginFlow-driven step routes back to the
	// per-step Authenticator. The kind is appended verbatim so two
	// Steps with different kinds emit distinguishable StateRef
	// payloads — the security invariant the per-Step tagging upholds.
	tagLoginFlowPrefix = "loginflow:"
)
