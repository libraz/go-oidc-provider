package authn

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/op/interaction"
)

// captchaFailureThreshold is the number of consecutive
// [AttemptFailure] outcomes that triggers an interstitial
// [interaction.CaptchaPromptData] before the next factor begins. The constant
// matches the §M.6.1 default; deployments that need a different
// threshold drive the same logic through their own
// [LoginAttemptObserver] and bump [State.LastFailures] externally.
// Captcha events themselves do NOT increment the counter — captcha is
// out-of-band from the brute-force feed (see §M.6.1).
const captchaFailureThreshold = 3

// stateRefTTL is how long an issued [interaction.Prompt.StateRef] stays valid
// from the orchestrator's perspective. The default is short enough to
// rule out long-tail replay attacks but long enough to outlast a
// reasonable user pause on the SPA. Embedders that want a different
// value will get an option in a follow-up; the constant is internal
// to the orchestrator state machine.
const stateRefTTL = 10 * time.Minute

// Phase enumerates the orchestrator's high-level chain stages. The
// values are stored only in [State] (not persisted) so they can move
// freely between releases; they exist to keep the [Orchestrator.Tick]
// dispatch table readable.
type Phase int

// Phase values. The chain runs strictly forward through these values:
// [Tick] never moves a [State] backwards.
const (
	// PhaseBeforeAuthn is the stage before any factor's
	// [Authenticator.Begin] runs. The orchestrator inserts every
	// pending [TriggerBeforeAuthn] / [TriggerAlways]
	// interaction here.
	PhaseBeforeAuthn Phase = iota

	// PhaseAuthn is the stage during which the orchestrator drives
	// authenticators. The active factor's index is held in
	// [State.ActiveFactorIdx].
	PhaseAuthn

	// PhaseAfterAuthn is the stage between the last factor and the
	// chain terminating. The orchestrator inserts every pending
	// [TriggerAfterAuthn] interaction here.
	PhaseAfterAuthn

	// PhaseDone is the terminal stage. [Tick] returns
	// [ErrChainComplete] when called with a [State] in this phase.
	PhaseDone
)

// State is the orchestrator's per-attempt state carrier. The struct is
// pure data: every field is the orchestrator's own representation of
// the in-flight chain. The HTTP layer (task C) persists [State] across
// requests using whatever encoding it picks; the orchestrator does no
// I/O of its own.
// Callers that need to copy a State (e.g., to journal it) MUST treat
// [State.Factors] and [State.InteractionsRun] as the values to deep-
// copy; mutating them after a [Tick] returns is undefined.
type State struct {
	// InteractionUID is the orchestrator-issued identifier for this
	// authorization attempt. The signer binds StateRef tokens to it
	// so a token cannot replay across two interactions.
	InteractionUID string

	// Subject is the OP-internal subject identifier the most recent
	// authenticator bound, or "" when no factor has identified the
	// user yet.
	Subject string

	// ClientID is the OAuth client_id of the relying party that
	// started the authorization request.
	ClientID string

	// RemoteIP is the client IP after trusted-proxy normalisation
	// (§F.5). The orchestrator never invents a value here; it must
	// have been written by the HTTP layer before the first [Tick].
	RemoteIP netip.Addr

	// UserAgent is the request's User-Agent header truncated to a
	// sane bound by the HTTP layer.
	UserAgent string

	// AuthTime is the wall-clock time the interaction was created.
	// The orchestrator passes it to every [BeginInput.AuthTime]
	// so [time.Now()] never has to be called from authenticator code.
	AuthTime time.Time

	// Factors is the per-step record of every successful
	// [Authenticator.Continue]. The slice is consumed by
	// [Aggregate] when the chain reaches [PhaseDone].
	Factors []Factor

	// CaptchaPassed records whether the SPA cleared the captcha
	// challenge during this attempt. The orchestrator emits at most
	// one captcha [interaction.Prompt] per attempt; once the bit is set it
	// stays set.
	CaptchaPassed bool

	// ActiveFactorIdx is the index of the active
	// [Authenticator] in the chain configuration, or -1 when no
	// factor is currently mid-ceremony. The orchestrator updates it
	// when it picks a candidate at [PhaseAuthn].
	ActiveFactorIdx int

	// ActiveInteractionName is the [Interaction.Name] of the
	// active interaction, or "" when none is mid-ceremony. The
	// orchestrator uses it to route [interaction.FormSubmission] back to the
	// originating Interaction.
	ActiveInteractionName string

	// StepCounter is a monotonic counter the orchestrator embeds
	// into every issued StateRef. Incrementing on every emitted
	// [interaction.Prompt] prevents a stale token from being replayed after
	// the chain advances.
	StepCounter int

	// Phase tracks the orchestrator's current chain stage. See
	// [Phase].
	Phase Phase

	// InteractionsRun records which [Interaction.Name] values
	// have already completed during this attempt. The orchestrator
	// does not insert the same Interaction twice.
	InteractionsRun map[string]bool

	// LastFailures is the running count of [AttemptFailure]
	// outcomes during the active [PhaseAuthn] window. The
	// orchestrator emits a captcha challenge once it reaches
	// [captchaFailureThreshold].
	LastFailures int

	// FactorScratch is the opaque byte slice the active factor's
	// most recent [interaction.Step.Scratch] return populated. The
	// orchestrator persists it across the Begin → Continue boundary
	// and feeds it back to [Authenticator.Continue] through
	// [ContinueInput.Scratch]. It is cleared automatically when the
	// active factor terminates (Result or hard error).
	FactorScratch []byte `json:"factor_scratch,omitempty"`

	// RequestedScopes is the scope list the relying party asked for
	// in the authorize request. The HTTP layer populates it when
	// initialising the chain; the orchestrator forwards it through
	// every [BeginInput.RequestedScopes] / [ContinueInput.RequestedScopes]
	// so the consent interaction (and any user extension that needs
	// the same surface) can read it without re-querying the request.
	RequestedScopes []string `json:"requested_scopes,omitempty"`

	// ChooserGroupID is the active session cookie's chooser-group
	// identifier. The HTTP layer populates it from the session
	// cookie when starting an interaction whose hint matrix routed
	// to the chooser; the orchestrator forwards it through
	// [BeginInput.ChooserGroupID] / [ContinueInput.ChooserGroupID]
	// so the built-in chooser interaction can enumerate live
	// accounts without re-reading the cookie. Empty for chains
	// that do not include the chooser interaction.
	ChooserGroupID string `json:"chooser_group_id,omitempty"`

	// ChooserSelectedSessionID is the SessionID the user picked at
	// the built-in account chooser screen. Populated by the
	// orchestrator from the chooser submission's "session_id"
	// field on a successful chooser Continue; the HTTP layer reads
	// it at terminal-tick time to call [sessions.Manager.Switch]
	// instead of [sessions.Manager.Issue] so the cookie rebinds
	// within the existing chooser group rather than starting a new
	// one. Empty for any chain that did not run the chooser.
	ChooserSelectedSessionID string `json:"chooser_selected_session_id,omitempty"`

	// ChooserBoundSubject reports whether the built-in chooser
	// interaction's most recent Result actively bound a subject. Set
	// only when [recordInteractionResult] observes a chooser result
	// with a non-empty Subject; the chooser self-skip path (no
	// active group) records a marker entry in
	// [State.InteractionsRun] without flipping this flag. The
	// orchestrator's PhaseBeforeAuthn dispatch reads it to decide
	// whether to skip the factor chain — a flag that is true only
	// after the chooser screen actually picked an account.
	ChooserBoundSubject bool `json:"chooser_bound_subject,omitempty"`

	// ApprovedScopes is the scope subset the user accepted at the
	// consent screen, recorded from the most recent
	// [interaction.Result.Scope] the orchestrator observed. The
	// terminal [Tick] result echoes the value so the HTTP layer can
	// mint the authorization code with the approved scope rather
	// than the full requested set.
	ApprovedScopes []string `json:"approved_scopes,omitempty"`

	// CompletedStepKinds records which [LoginFlow] step kinds have
	// run during this attempt. Empty when [Config.LoginFlow] is not
	// configured. The slice is the dedup unit for [LoginFlowRule]
	// re-evaluation: a rule whose Then.Kind is already present is
	// skipped on subsequent passes so the same step cannot run twice
	// in a chain. The dedup invariant defends against timing-oracle
	// attacks where an attacker repeatedly triggers the same Step to
	// extract per-attempt timing.
	CompletedStepKinds []string `json:"completed_step_kinds,omitempty"`

	// RiskScoreCached is the orchestrator's one-shot evaluation of
	// [Config.LoginFlow.Risk] at chain start. Zero means "no signal
	// available or no LoginFlow / no Risk configured"; the cached
	// value mirrors the numeric ordering of the public op.RiskScore
	// constants (None=0, Low=1, Medium=2, High=3) so a rule
	// predicate `score >= threshold` works uniformly across the
	// orchestrator-cached and embedder-supplied paths.
	// The orchestrator MUST NOT re-call [LoginFlow.Risk] once a
	// non-zero score is cached: external risk APIs are paid, and
	// plan 005 §3.1 makes this an explicit budget invariant.
	RiskScoreCached int `json:"risk_score_cached,omitempty"`

	// ActiveStepKind is the [LoginFlowStep.Kind] of the active
	// LoginFlow step, or "" when no LoginFlow step is mid-ceremony.
	// The orchestrator uses it to route a submission back through the
	// per-step authenticator and to append to [CompletedStepKinds]
	// once the step's Result lands.
	ActiveStepKind string `json:"active_step_kind,omitempty"`
}

// Input is the per-tick payload the HTTP layer hands to
// [Orchestrator.Tick]. The orchestrator does no clock reads of its
// own; [Input.Now()] is the single source of "current time" for a tick,
// so a deterministic [Clock] in tests yields a deterministic chain
// run.
type Input struct {
	// Submission carries the SPA's form post, or nil when the tick
	// is the first call of an attempt (no prompt outstanding).
	Submission *interaction.FormSubmission

	// CaptchaToken is the SPA's response to a captcha
	// [interaction.Prompt]. Populated only when the previous tick emitted a
	// captcha challenge; otherwise the orchestrator ignores it.
	CaptchaToken string

	// Now is the wall-clock time for this tick. The HTTP layer
	// reads it from the configured [Clock] and passes it through
	// so the orchestrator never calls [time.Now()] directly.
	Now time.Time
}

// Sentinel errors returned by [Orchestrator.Tick]. Callers compare
// against these via errors.Is; the orchestrator wraps them with
// %w-style context only when an upstream verifier emits a structured
// failure that the HTTP layer needs to surface.
var (
	// ErrChainComplete is returned by [Tick] when called with a
	// [State] already in [PhaseDone]. It signals a programming bug
	// in the caller: the HTTP layer is meant to stop driving the
	// orchestrator after the terminal step.
	ErrChainComplete = errors.New("authn: chain already complete")

	// ErrInvalidStateRef is returned when a [interaction.FormSubmission]
	// carries a StateRef that fails [StateRefSigner.Verify]. The
	// HTTP layer treats it as a hard error; the SPA is expected to
	// restart the attempt.
	ErrInvalidStateRef = errors.New("authn: invalid stateref")

	// ErrRiskDenied is returned when the configured
	// [RiskAssessor] returns [RiskDeny] at any stage. The
	// HTTP layer surfaces a fixed error response; the assessor's
	// reason flows to the audit log only.
	ErrRiskDenied = errors.New("authn: risk denied")

	// ErrNoEligibleAuthenticator is returned when, at
	// [PhaseAuthn], no registered [Authenticator] satisfies the
	// chain constraints (Subject already required by candidate set,
	// risk-required factor not registered...). The HTTP layer
	// surfaces a fixed error response.
	ErrNoEligibleAuthenticator = errors.New("authn: no eligible authenticator")

	// ErrInvalidStep is returned when an [Authenticator] or
	// [Interaction] returns a [interaction.Step] with neither Prompt nor
	// Result populated. The orchestrator rejects the bad return so
	// a misbehaving authenticator cannot stall the chain.
	ErrInvalidStep = errors.New("authn: invalid step")
)

// Config is the [Orchestrator] construction payload. It mirrors the
// public-API options the [op.Provider] accumulates; the HTTP layer
// (task C) wires the two together. Fields with comments marked
// "optional" may be nil; the orchestrator handles the missing
// dependency by skipping the corresponding phase.
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
	cfg    Config
	logger *slog.Logger
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
		logger = slog.New(discardHandler{})
	}
	return &Orchestrator{cfg: cfg, logger: logger}, nil
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
//
// 02-product-design.md §E.2 / §E.6.1 / §M.6 for the
// invariants this method preserves.
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
// brute-force feed (§M.6.1).
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

// advance executes the current phase. The per-phase helpers each
// return a Step (when something to render is ready) or signal a
// transition to the next phase. The dispatcher loops until a Step is
// produced or the chain reaches PhaseDone.
func (o *Orchestrator) advance(ctx context.Context, st State, in Input) (State, interaction.Step, error) {
	for {
		next, step, transition, err := o.advanceOnce(ctx, st, in)
		st = next
		if err != nil {
			return st, interaction.Step{}, err
		}
		if step.Prompt != nil || step.Result != nil {
			return st, step, nil
		}
		if !transition {
			return st, interaction.Step{}, ErrInvalidStep
		}
	}
}

// advanceOnce dispatches one phase tick. The transition bool is true
// when no Prompt was produced and the loop should re-enter advance with
// the updated phase; false-with-no-step indicates a stuck chain (the
// dispatcher surfaces ErrInvalidStep so the caller does not spin).
func (o *Orchestrator) advanceOnce(ctx context.Context, st State, in Input) (State, interaction.Step, bool, error) {
	switch st.Phase {
	case PhaseBeforeAuthn:
		next, step, transition, err := o.advancePhaseInteractions(ctx, st, in.Now, TriggerBeforeAuthn, PhaseAuthn)
		// When the built-in chooser ran during the BeforeAuthn
		// phase and actively bound a subject, skip the factor
		// chain entirely. The check reads [State.ChooserBoundSubject]
		// rather than [State.InteractionsRun]: the chooser self-skip
		// path (no active chooser group) marks the interaction as
		// run via an empty Result so subsequent ticks do not re-emit
		// the prompt, but it leaves ChooserBoundSubject false. The
		// flag is the unambiguous "factor chain has been replaced"
		// signal.
		if transition && next.Phase == PhaseAuthn && next.ChooserBoundSubject {
			next.Phase = PhaseAfterAuthn
		}
		return next, step, transition, err
	case PhaseAuthn:
		next, step, err := o.advanceAuthn(ctx, st, in.Now)
		// LoginFlow path may transition to PhaseAfterAuthn without
		// emitting a Prompt (Allow / no-rule-matched / decider-Pass
		// + empty rules). Detect the phase change so the dispatcher
		// re-enters with the updated phase rather than tripping the
		// stuck-chain guard.
		transition := next.Phase != PhaseAuthn
		return next, step, transition, err
	case PhaseAfterAuthn:
		return o.advancePhaseInteractions(ctx, st, in.Now, TriggerAfterAuthn, PhaseDone)
	case PhaseDone:
		next, step, err := o.emitTerminal(st)
		return next, step, false, err
	}
	return st, interaction.Step{}, false, ErrInvalidStep
}

// advancePhaseInteractions runs the BeforeAuthn / AfterAuthn interaction
// loop and signals a phase transition when the queue is drained.
func (o *Orchestrator) advancePhaseInteractions(ctx context.Context, st State, now time.Time, trigger InteractionTrigger, nextPhase Phase) (State, interaction.Step, bool, error) {
	next, step, done, err := o.advanceInteractions(ctx, st, now, trigger)
	if err != nil {
		return next, interaction.Step{}, false, err
	}
	if step.Prompt != nil {
		return next, step, false, nil
	}
	if done {
		next.Phase = nextPhase
		return next, interaction.Step{}, true, nil
	}
	return next, interaction.Step{}, false, nil
}

// advanceInteractions picks the next pending interaction matching
// trigger or [TriggerAlways] and emits its Begin Prompt. The bool
// return reports whether the queue is empty (the caller can advance to
// the next phase).
func (o *Orchestrator) advanceInteractions(ctx context.Context, st State, now time.Time, trigger InteractionTrigger) (State, interaction.Step, bool, error) {
	for _, ix := range o.cfg.Interactions {
		t := ix.Trigger()
		if t != trigger && t != TriggerAlways {
			continue
		}
		if st.InteractionsRun[ix.Name()] {
			continue
		}
		step, err := ix.Begin(ctx, BeginInput{
			Subject:         st.Subject,
			ClientID:        st.ClientID,
			AuthTime:        now,
			RequestedScopes: st.RequestedScopes,
			ChooserGroupID:  st.ChooserGroupID,
		})
		if err != nil {
			return st, interaction.Step{}, false, err
		}
		if step.Prompt != nil {
			next, emitted, perr := o.emitInteractionPrompt(st, ix, *step.Prompt, now)
			if perr != nil {
				return st, interaction.Step{}, false, perr
			}
			return next, emitted, false, nil
		}
		if step.Result == nil {
			return st, interaction.Step{}, false, ErrInvalidStep
		}
		st = recordInteractionResult(st, ix.Name(), *step.Result)
		st.InteractionsRun[ix.Name()] = true
	}
	return st, interaction.Step{}, true, nil
}

// advanceAuthn picks the next factor candidate. The branches handle
// the captcha-before-factor case, the risk consult, and the
// subject-required factor skip rule.
// When [Config.LoginFlow] is configured the function delegates to
// [advanceLoginFlow]; the legacy [Config.Authenticators] body below is
// used only when LoginFlow is nil.
func (o *Orchestrator) advanceAuthn(ctx context.Context, st State, now time.Time) (State, interaction.Step, error) {
	if o.cfg.LoginFlow != nil {
		return o.advanceLoginFlow(ctx, st, now)
	}
	required, denied, err := o.runRiskPreFactor(ctx, st, now)
	if err != nil {
		return st, interaction.Step{}, err
	}
	if denied {
		return st, interaction.Step{}, ErrRiskDenied
	}

	candidates := o.eligibleAuthenticators(st, required)
	if len(candidates) == 0 {
		return st, interaction.Step{}, ErrNoEligibleAuthenticator
	}

	if o.captchaRequired(st) {
		next, step, perr := o.emitCaptchaPrompt(st, now)
		if perr != nil {
			return st, interaction.Step{}, perr
		}
		return next, step, nil
	}

	idx, auth := candidates[0].idx, candidates[0].auth
	step, err := auth.Begin(ctx, BeginInput{
		Subject:         st.Subject,
		ClientID:        st.ClientID,
		AuthTime:        now,
		RequestedScopes: st.RequestedScopes,
		ChooserGroupID:  st.ChooserGroupID,
	})
	if err != nil {
		return st, interaction.Step{}, err
	}
	if step.Prompt != nil {
		st.ActiveFactorIdx = idx
		next, emitted, perr := o.emitFactorPrompt(st, auth, step, now)
		if perr != nil {
			return st, interaction.Step{}, perr
		}
		return next, emitted, nil
	}
	if step.Result == nil {
		return st, interaction.Step{}, ErrInvalidStep
	}
	st.ActiveFactorIdx = idx
	st.FactorScratch = nil
	st = o.appendFactor(st, auth, *step.Result)
	o.observeSuccess(ctx, st, now, auth.Type())
	denied2, derr := o.runRiskPostFactor(ctx, st, now, auth.Type())
	if derr != nil {
		return st, interaction.Step{}, derr
	}
	if denied2 {
		return st, interaction.Step{}, ErrRiskDenied
	}
	st.ActiveFactorIdx = -1
	st.Phase = PhaseAfterAuthn
	return st, interaction.Step{}, nil
}

// candidateAuthenticator pairs an authenticator with its index in the
// configuration slice so a re-ordered candidate list keeps the index
// reachable for [State.ActiveFactorIdx].
type candidateAuthenticator struct {
	idx  int
	auth Authenticator
}

// eligibleAuthenticators filters the registered chain by the
// risk-required FactorType set (when non-empty) and by the
// subject-required skip rule. The returned slice preserves the
// configuration order so the orchestrator's "first candidate wins"
// rule stays deterministic.
func (o *Orchestrator) eligibleAuthenticators(st State, required []FactorType) []candidateAuthenticator {
	out := make([]candidateAuthenticator, 0, len(o.cfg.Authenticators))
	for i, a := range o.cfg.Authenticators {
		if len(required) > 0 && !containsFactor(required, a.Type()) {
			continue
		}
		if requiresSubject(a.Type()) && st.Subject == "" {
			continue
		}
		out = append(out, candidateAuthenticator{idx: i, auth: a})
	}
	return out
}

// captchaRequired reports whether the orchestrator should emit a
// captcha challenge before the next factor. The trigger fires when
// the failure counter has reached the threshold AND a verifier is
// configured AND the SPA has not already cleared the challenge.
func (o *Orchestrator) captchaRequired(st State) bool {
	if o.cfg.Captcha == nil {
		return false
	}
	if st.CaptchaPassed {
		return false
	}
	return st.LastFailures >= captchaFailureThreshold
}

// emitCaptchaPrompt issues a fresh captcha prompt with a new
// StepCounter so a stale token cannot replay.
func (o *Orchestrator) emitCaptchaPrompt(st State, now time.Time) (State, interaction.Step, error) {
	st.StepCounter++
	ref, err := o.cfg.StateRefSigner.Issue(st.InteractionUID, tagCaptcha, st.StepCounter, now.Add(stateRefTTL))
	if err != nil {
		return st, interaction.Step{}, err
	}
	prompt := interaction.Prompt{
		Type:     "captcha",
		Data:     interaction.CaptchaPromptData{},
		StateRef: ref,
	}
	return st, interaction.Step{Prompt: &prompt}, nil
}

// emitFactorPrompt re-issues the prompt the authenticator returned
// with a freshly minted StateRef bound to the active factor's type.
// The factor's Scratch is mirrored into [State.FactorScratch] so the
// next [Authenticator.Continue] sees it via [ContinueInput.Scratch].
func (o *Orchestrator) emitFactorPrompt(st State, auth Authenticator, step interaction.Step, now time.Time) (State, interaction.Step, error) {
	st.StepCounter++
	ref, err := o.cfg.StateRefSigner.Issue(st.InteractionUID, tagAuthPrefix+string(auth.Type()), st.StepCounter, now.Add(stateRefTTL))
	if err != nil {
		return st, interaction.Step{}, err
	}
	prompt := *step.Prompt
	prompt.StateRef = ref
	st.FactorScratch = step.Scratch
	return st, interaction.Step{Prompt: &prompt}, nil
}

// emitInteractionPrompt mirrors emitFactorPrompt for non-authn
// interactions and stores the active interaction name on st so the
// next submission routes back here.
func (o *Orchestrator) emitInteractionPrompt(st State, ix Interaction, prompt interaction.Prompt, now time.Time) (State, interaction.Step, error) {
	st.StepCounter++
	ref, err := o.cfg.StateRefSigner.Issue(st.InteractionUID, tagInteractionPrefix+ix.Name(), st.StepCounter, now.Add(stateRefTTL))
	if err != nil {
		return st, interaction.Step{}, err
	}
	prompt.StateRef = ref
	st.ActiveInteractionName = ix.Name()
	return st, interaction.Step{Prompt: &prompt}, nil
}

// emitTerminal returns the chain-complete Step the HTTP layer hands
// back to the SPA. The Result carries the final Subject, the
// AuthTime of the last factor, and the consent-approved scope subset
// the orchestrator stamped onto [State.ApprovedScopes] (empty when no
// consent-shaped Interaction ran).
func (o *Orchestrator) emitTerminal(st State) (State, interaction.Step, error) {
	res := interaction.Result{
		Subject:  st.Subject,
		AuthTime: st.AuthTime,
		Scope:    append([]string(nil), st.ApprovedScopes...),
	}
	return st, interaction.Step{Result: &res}, nil
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

// appendFactor is the single point where the orchestrator records a
// successful authenticator run. It enforces the §E.6.1 invariant that
// only RFC 8176-registered AMR values reach the session: an
// unregistered return is logged and dropped (the Factor still
// contributes through [Factor.AMRValue] which derives from
// [FactorType]).
func (o *Orchestrator) appendFactor(st State, auth Authenticator, result interaction.Result) State {
	if amr := auth.AMR(); amr != "" && !IsRegisteredAMR(amr) {
		o.logger.Warn("authn: dropping unregistered AMR value",
			slog.String("authenticator_type", string(auth.Type())),
			slog.String("amr", amr),
		)
	}
	uv := false
	if auth.Type() == FactorPasskey {
		switch auth.AMR() {
		case "hwk":
			uv = true
		case "swk":
			uv = false
		}
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

// runRiskPreFactor consults the assessor at PreFactor and returns the
// factor-type filter the orchestrator should apply (empty = no
// filter), plus a denied flag.
func (o *Orchestrator) runRiskPreFactor(ctx context.Context, st State, now time.Time) ([]FactorType, bool, error) {
	if o.cfg.Risk == nil {
		return nil, false, nil
	}
	out, err := o.cfg.Risk.Assess(ctx, RiskInput{
		Stage:     RiskPreFactor,
		Subject:   st.Subject,
		ClientID:  st.ClientID,
		RemoteIP:  st.RemoteIP,
		UserAgent: st.UserAgent,
		AMRSoFar:  collectAMR(st.Factors),
		AuthTime:  now,
	})
	if err != nil {
		return nil, false, err
	}
	if out.Decision == RiskDeny {
		return nil, true, nil
	}
	if out.Decision == RiskRequire {
		return out.RequiredFactors, false, nil
	}
	return nil, false, nil
}

// runRiskPostFactor consults the assessor after a successful factor
// completion. The current implementation honours [RiskDeny] only;
// [RiskRequire] at PostFactor is queued by the next PreFactor pass
// (the orchestrator does not preempt the current factor).
func (o *Orchestrator) runRiskPostFactor(ctx context.Context, st State, now time.Time, last FactorType) (bool, error) {
	if o.cfg.Risk == nil {
		return false, nil
	}
	out, err := o.cfg.Risk.Assess(ctx, RiskInput{
		Stage:      RiskPostFactor,
		Subject:    st.Subject,
		ClientID:   st.ClientID,
		RemoteIP:   st.RemoteIP,
		UserAgent:  st.UserAgent,
		AMRSoFar:   collectAMR(st.Factors),
		LastFactor: last,
		AuthTime:   now,
	})
	if err != nil {
		return false, err
	}
	return out.Decision == RiskDeny, nil
}

// findInteractionIndex returns the index of the registered Interaction
// with the given name, or -1 when the name is unknown (in which case
// the active state is corrupt and the submission is rejected upstream).
// The index form keeps lookups under [ireturn] without exporting the
// Interaction concrete type from this package.
func (o *Orchestrator) findInteractionIndex(name string) int {
	if name == "" {
		return -1
	}
	for i, ix := range o.cfg.Interactions {
		if ix.Name() == name {
			return i
		}
	}
	return -1
}

// observeSuccess fans out an [AttemptSuccess] event to every
// observer. The orchestrator does not retry on observer panics; the
// public-API contract is "non-blocking" (§M.6.3).
func (o *Orchestrator) observeSuccess(ctx context.Context, st State, now time.Time, factor FactorType) {
	o.fanOut(ctx, LoginAttempt{
		Subject:   st.Subject,
		ClientID:  st.ClientID,
		RemoteIP:  st.RemoteIP,
		UserAgent: st.UserAgent,
		Outcome:   AttemptSuccess,
		Factor:    factor,
		At:        now,
	})
}

// observeFailure fans out an [AttemptFailure] event. Subject is
// intentionally blanked on the failure path to avoid enumeration via
// the observer feed (§M.6.3).
func (o *Orchestrator) observeFailure(ctx context.Context, st State, now time.Time, factor FactorType) {
	o.fanOut(ctx, LoginAttempt{
		ClientID:  st.ClientID,
		RemoteIP:  st.RemoteIP,
		UserAgent: st.UserAgent,
		Outcome:   AttemptFailure,
		Factor:    factor,
		Reason:    "attempt.invalid_credentials",
		At:        now,
	})
}

// fanOut delivers evt to every registered observer in registration
// order. The orchestrator does not block on observer errors.
func (o *Orchestrator) fanOut(ctx context.Context, evt LoginAttempt) {
	for _, obs := range o.cfg.Observers {
		if obs == nil {
			continue
		}
		obs.Observe(ctx, evt)
	}
}

// collectAMR returns the registered AMR values across the supplied
// factor slice. The orchestrator hands the result to the
// [RiskAssessor] so the assessor sees only the post-filter view.
func collectAMR(factors []Factor) []string {
	if len(factors) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(factors))
	out := make([]string, 0, len(factors))
	for _, f := range factors {
		v := f.AMRValue()
		if v == "" {
			continue
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// containsFactor reports whether t is in the supplied slice.
func containsFactor(slice []FactorType, t FactorType) bool {
	for _, v := range slice {
		if v == t {
			return true
		}
	}
	return false
}

// requiresSubject reports whether a factor type can only run after
// the chain has bound a subject. The set is closed: identifying
// factors (password, passkey discoverable assertion) MAY appear first;
// possession-style factors that key off the user record MUST NOT.
func requiresSubject(t FactorType) bool {
	switch t {
	case FactorTOTP, FactorRecoveryCode, FactorEmailOTP:
		return true
	default:
		return false
	}
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
	// payloads — the security invariant from plan 005 H1-D §1
	// ("StateRef per-Step tagging").
	tagLoginFlowPrefix = "loginflow:"
)

// discardHandler is the slog handler the orchestrator uses when the
// caller did not configure a logger. It mirrors the silent default in
// op/options.go so the orchestrator never panics on a nil logger.
type discardHandler struct{}

func (discardHandler) Enabled(_ context.Context, _ slog.Level) bool  { return false }
func (discardHandler) Handle(_ context.Context, _ slog.Record) error { return nil }
func (h discardHandler) WithAttrs(_ []slog.Attr) slog.Handler        { return h }
func (h discardHandler) WithGroup(_ string) slog.Handler             { return h }
