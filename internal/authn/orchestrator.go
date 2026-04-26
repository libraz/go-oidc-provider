package authn

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/op"
)

// captchaFailureThreshold is the number of consecutive
// [op.AttemptFailure] outcomes that triggers an interstitial
// [op.CaptchaPromptData] before the next factor begins. The constant
// matches the §M.6.1 default; deployments that need a different
// threshold drive the same logic through their own
// [op.LoginAttemptObserver] and bump [State.LastFailures] externally.
//
// Captcha events themselves do NOT increment the counter — captcha is
// out-of-band from the brute-force feed (see §M.6.1).
const captchaFailureThreshold = 3

// stateRefTTL is how long an issued [op.Prompt.StateRef] stays valid
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
	// [op.Authenticator.Begin] runs. The orchestrator inserts every
	// pending [op.TriggerBeforeAuthn] / [op.TriggerAlways]
	// interaction here.
	PhaseBeforeAuthn Phase = iota

	// PhaseAuthn is the stage during which the orchestrator drives
	// authenticators. The active factor's index is held in
	// [State.ActiveFactorIdx].
	PhaseAuthn

	// PhaseAfterAuthn is the stage between the last factor and the
	// chain terminating. The orchestrator inserts every pending
	// [op.TriggerAfterAuthn] interaction here.
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
//
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
	// The orchestrator passes it to every [op.BeginInput.AuthTime]
	// so [time.Now] never has to be called from authenticator code.
	AuthTime time.Time

	// Factors is the per-step record of every successful
	// [op.Authenticator.Continue]. The slice is consumed by
	// [Aggregate] when the chain reaches [PhaseDone].
	Factors []Factor

	// CaptchaPassed records whether the SPA cleared the captcha
	// challenge during this attempt. The orchestrator emits at most
	// one captcha [op.Prompt] per attempt; once the bit is set it
	// stays set.
	CaptchaPassed bool

	// ActiveFactorIdx is the index of the active
	// [op.Authenticator] in the chain configuration, or -1 when no
	// factor is currently mid-ceremony. The orchestrator updates it
	// when it picks a candidate at [PhaseAuthn].
	ActiveFactorIdx int

	// ActiveInteractionName is the [op.Interaction.Name] of the
	// active interaction, or "" when none is mid-ceremony. The
	// orchestrator uses it to route [op.FormSubmission] back to the
	// originating Interaction.
	ActiveInteractionName string

	// StepCounter is a monotonic counter the orchestrator embeds
	// into every issued StateRef. Incrementing on every emitted
	// [op.Prompt] prevents a stale token from being replayed after
	// the chain advances.
	StepCounter int

	// Phase tracks the orchestrator's current chain stage. See
	// [Phase].
	Phase Phase

	// InteractionsRun records which [op.Interaction.Name] values
	// have already completed during this attempt. The orchestrator
	// does not insert the same Interaction twice.
	InteractionsRun map[string]bool

	// LastFailures is the running count of [op.AttemptFailure]
	// outcomes during the active [PhaseAuthn] window. The
	// orchestrator emits a captcha challenge once it reaches
	// [captchaFailureThreshold].
	LastFailures int
}

// Input is the per-tick payload the HTTP layer hands to
// [Orchestrator.Tick]. The orchestrator does no clock reads of its
// own; [Input.Now] is the single source of "current time" for a tick,
// so a deterministic [op.Clock] in tests yields a deterministic chain
// run.
type Input struct {
	// Submission carries the SPA's form post, or nil when the tick
	// is the first call of an attempt (no prompt outstanding).
	Submission *op.FormSubmission

	// CaptchaToken is the SPA's response to a captcha
	// [op.Prompt]. Populated only when the previous tick emitted a
	// captcha challenge; otherwise the orchestrator ignores it.
	CaptchaToken string

	// Now is the wall-clock time for this tick. The HTTP layer
	// reads it from the configured [Clock] and passes it through
	// so the orchestrator never calls [time.Now] directly.
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

	// ErrInvalidStateRef is returned when a [op.FormSubmission]
	// carries a StateRef that fails [StateRefSigner.Verify]. The
	// HTTP layer treats it as a hard error; the SPA is expected to
	// restart the attempt.
	ErrInvalidStateRef = errors.New("authn: invalid stateref")

	// ErrRiskDenied is returned when the configured
	// [op.RiskAssessor] returns [op.RiskDeny] at any stage. The
	// HTTP layer surfaces a fixed error response; the assessor's
	// reason flows to the audit log only.
	ErrRiskDenied = errors.New("authn: risk denied")

	// ErrNoEligibleAuthenticator is returned when, at
	// [PhaseAuthn], no registered [op.Authenticator] satisfies the
	// chain constraints (Subject already required by candidate set,
	// risk-required factor not registered, ...). The HTTP layer
	// surfaces a fixed error response.
	ErrNoEligibleAuthenticator = errors.New("authn: no eligible authenticator")

	// ErrInvalidStep is returned when an [op.Authenticator] or
	// [op.Interaction] returns a [op.Step] with neither Prompt nor
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
	Authenticators []op.Authenticator

	// Interactions is the registered interaction list. The
	// orchestrator inserts each entry per its
	// [op.InteractionTrigger]; intra-trigger ordering follows
	// registration order.
	Interactions []op.Interaction

	// Risk is the optional [op.RiskAssessor] consulted at every
	// [op.RiskStage] callsite. Nil means "always allow" (the
	// orchestrator skips the consult).
	Risk op.RiskAssessor

	// Captcha is the optional [op.CaptchaVerifier]. Nil disables
	// the captcha challenge: the orchestrator never emits the
	// CaptchaPromptData even when [State.LastFailures] reaches the
	// threshold (a deployment without a configured verifier would
	// otherwise loop on a token it cannot validate).
	Captcha op.CaptchaVerifier

	// Observers receives one [op.LoginAttempt] per factor outcome.
	// The slice is fanned out in registration order.
	Observers []op.LoginAttemptObserver

	// StateRefSigner signs every [op.Prompt.StateRef]. Required.
	StateRefSigner *StateRefSigner

	// Logger is the structured logger the orchestrator writes
	// warning records to (e.g., when an [op.Authenticator.AMR]
	// return is dropped because it is not RFC 8176-registered).
	// Nil means "discard"; the orchestrator never panics on a nil
	// logger.
	Logger *slog.Logger
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
// chain is non-empty, that authenticators have unique [op.FactorType]
// values, that interactions have unique [op.Interaction.Name] values,
// and that the StateRef signer is non-nil. Errors here surface at
// [op.New] construction time so deployment misconfigurations cannot
// reach the first request.
func New(cfg Config) (*Orchestrator, error) {
	if len(cfg.Authenticators) == 0 {
		return nil, errors.New("authn: at least one Authenticator required")
	}
	if cfg.StateRefSigner == nil {
		return nil, errors.New("authn: StateRefSigner required")
	}
	seenType := make(map[op.FactorType]struct{}, len(cfg.Authenticators))
	for _, a := range cfg.Authenticators {
		if a == nil {
			return nil, errors.New("authn: nil Authenticator")
		}
		t := a.Type()
		if _, dup := seenType[t]; dup {
			return nil, fmt.Errorf("authn: duplicate Authenticator type %q", t)
		}
		seenType[t] = struct{}{}
	}
	seenName := make(map[string]struct{}, len(cfg.Interactions))
	deduped := make([]op.Interaction, 0, len(cfg.Interactions))
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

// Tick advances st by one orchestrator step. The method is pure: no
// goroutines, no [time.Now], no network. Tick returns the updated
// [State] (always — even on error, so the HTTP layer can persist
// counters that did update before the failure) and the [op.Step] the
// SPA should render next, if any.
//
// The state machine, in order:
//
//  1. Reject ticks against a completed chain ([ErrChainComplete]).
//  2. If a submission is present, route it to the entity that issued
//     the StateRef (captcha verifier, active authenticator, or active
//     interaction) and advance.
//  3. Run the [PhaseBeforeAuthn] interaction queue.
//  4. Run [PhaseAuthn]: consult risk, pick a candidate, emit Begin.
//  5. Run the [PhaseAfterAuthn] interaction queue.
//  6. Emit the terminal [op.Step] from [PhaseDone].
//
// See docs/plans/002-product-design.md §E.2 / §E.6.1 / §M.6 for the
// invariants this method preserves.
func (o *Orchestrator) Tick(ctx context.Context, st State, in Input) (State, op.Step, error) {
	if st.Phase == PhaseDone {
		return st, op.Step{}, ErrChainComplete
	}
	if st.InteractionsRun == nil {
		st.InteractionsRun = map[string]bool{}
	}

	if in.Submission != nil {
		next, step, err := o.consumeSubmission(ctx, st, in)
		if err != nil {
			return next, op.Step{}, err
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
func (o *Orchestrator) consumeSubmission(ctx context.Context, st State, in Input) (State, op.Step, error) {
	payload, err := o.cfg.StateRefSigner.Verify(in.Submission.StateRef, st.InteractionUID, st.StepCounter, in.Now)
	if err != nil {
		return st, op.Step{}, ErrInvalidStateRef
	}
	switch {
	case payload.Tag == tagCaptcha:
		return o.handleCaptchaSubmission(ctx, st, in)
	case strings.HasPrefix(payload.Tag, tagAuthPrefix):
		return o.handleAuthSubmission(ctx, st, in)
	case strings.HasPrefix(payload.Tag, tagInteractionPrefix):
		return o.handleInteractionSubmission(ctx, st, in)
	default:
		return st, op.Step{}, ErrInvalidStateRef
	}
}

// handleCaptchaSubmission validates the captcha token; on success
// CaptchaPassed flips and the chain advances, on failure the captcha
// Prompt is re-emitted with a fresh nonce (the StepCounter still
// increments so the previous token cannot replay). Captcha events do
// NOT call observers — captcha is intentionally out-of-band from the
// brute-force feed (§M.6.1).
func (o *Orchestrator) handleCaptchaSubmission(ctx context.Context, st State, in Input) (State, op.Step, error) {
	if o.cfg.Captcha == nil {
		return st, op.Step{}, ErrInvalidStateRef
	}
	captchaIn := op.CaptchaInput{
		Token:    in.CaptchaToken,
		RemoteIP: st.RemoteIP,
	}
	if err := o.cfg.Captcha.Verify(ctx, captchaIn); err != nil {
		next, step, err2 := o.emitCaptchaPrompt(st, in.Now)
		if err2 != nil {
			return st, op.Step{}, err2
		}
		return next, step, nil
	}
	st.CaptchaPassed = true
	st.LastFailures = 0
	return st, op.Step{}, nil
}

// handleAuthSubmission delegates the submission to the active
// authenticator, observes the outcome, and runs PostFactor risk if
// configured.
func (o *Orchestrator) handleAuthSubmission(ctx context.Context, st State, in Input) (State, op.Step, error) {
	if st.ActiveFactorIdx < 0 || st.ActiveFactorIdx >= len(o.cfg.Authenticators) {
		return st, op.Step{}, ErrInvalidStateRef
	}
	auth := o.cfg.Authenticators[st.ActiveFactorIdx]
	step, err := auth.Continue(ctx, *in.Submission)
	if err != nil {
		o.observeFailure(ctx, st, in.Now, auth.Type())
		return st, op.Step{}, err
	}
	if step.Prompt != nil {
		next, emitted, ferr := o.emitFactorPrompt(st, auth, *step.Prompt, in.Now)
		if ferr != nil {
			return st, op.Step{}, ferr
		}
		return next, emitted, nil
	}
	if step.Result == nil {
		return st, op.Step{}, ErrInvalidStep
	}
	st = o.appendFactor(st, auth, *step.Result)
	o.observeSuccess(ctx, st, in.Now, auth.Type())
	denied, derr := o.runRiskPostFactor(ctx, st, in.Now, auth.Type())
	if derr != nil {
		return st, op.Step{}, derr
	}
	if denied {
		return st, op.Step{}, ErrRiskDenied
	}
	st.ActiveFactorIdx = -1
	st.Phase = PhaseAfterAuthn
	return st, op.Step{}, nil
}

// handleInteractionSubmission dispatches to the active interaction;
// successful Result transitions to the next phase.
func (o *Orchestrator) handleInteractionSubmission(ctx context.Context, st State, in Input) (State, op.Step, error) {
	idx := o.findInteractionIndex(st.ActiveInteractionName)
	if idx < 0 {
		return st, op.Step{}, ErrInvalidStateRef
	}
	ix := o.cfg.Interactions[idx]
	step, err := ix.Continue(ctx, *in.Submission)
	if err != nil {
		return st, op.Step{}, err
	}
	if step.Prompt != nil {
		next, emitted, ferr := o.emitInteractionPrompt(st, ix, *step.Prompt, in.Now)
		if ferr != nil {
			return st, op.Step{}, ferr
		}
		return next, emitted, nil
	}
	if step.Result == nil {
		return st, op.Step{}, ErrInvalidStep
	}
	st.InteractionsRun[ix.Name()] = true
	st.ActiveInteractionName = ""
	return st, op.Step{}, nil
}

// advance executes the current phase. The per-phase helpers each
// return a Step (when something to render is ready) or signal a
// transition to the next phase. The dispatcher loops until a Step is
// produced or the chain reaches PhaseDone.
func (o *Orchestrator) advance(ctx context.Context, st State, in Input) (State, op.Step, error) {
	for {
		next, step, transition, err := o.advanceOnce(ctx, st, in)
		st = next
		if err != nil {
			return st, op.Step{}, err
		}
		if step.Prompt != nil || step.Result != nil {
			return st, step, nil
		}
		if !transition {
			return st, op.Step{}, ErrInvalidStep
		}
	}
}

// advanceOnce dispatches one phase tick. The transition bool is true
// when no Prompt was produced and the loop should re-enter advance with
// the updated phase; false-with-no-step indicates a stuck chain (the
// dispatcher surfaces ErrInvalidStep so the caller does not spin).
func (o *Orchestrator) advanceOnce(ctx context.Context, st State, in Input) (State, op.Step, bool, error) {
	switch st.Phase {
	case PhaseBeforeAuthn:
		return o.advancePhaseInteractions(ctx, st, in.Now, op.TriggerBeforeAuthn, PhaseAuthn)
	case PhaseAuthn:
		next, step, err := o.advanceAuthn(ctx, st, in.Now)
		return next, step, false, err
	case PhaseAfterAuthn:
		return o.advancePhaseInteractions(ctx, st, in.Now, op.TriggerAfterAuthn, PhaseDone)
	case PhaseDone:
		next, step, err := o.emitTerminal(st)
		return next, step, false, err
	}
	return st, op.Step{}, false, ErrInvalidStep
}

// advancePhaseInteractions runs the BeforeAuthn / AfterAuthn interaction
// loop and signals a phase transition when the queue is drained.
func (o *Orchestrator) advancePhaseInteractions(ctx context.Context, st State, now time.Time, trigger op.InteractionTrigger, nextPhase Phase) (State, op.Step, bool, error) {
	next, step, done, err := o.advanceInteractions(ctx, st, now, trigger)
	if err != nil {
		return next, op.Step{}, false, err
	}
	if step.Prompt != nil {
		return next, step, false, nil
	}
	if done {
		next.Phase = nextPhase
		return next, op.Step{}, true, nil
	}
	return next, op.Step{}, false, nil
}

// advanceInteractions picks the next pending interaction matching
// trigger or [op.TriggerAlways] and emits its Begin Prompt. The bool
// return reports whether the queue is empty (the caller can advance to
// the next phase).
func (o *Orchestrator) advanceInteractions(ctx context.Context, st State, now time.Time, trigger op.InteractionTrigger) (State, op.Step, bool, error) {
	for _, ix := range o.cfg.Interactions {
		t := ix.Trigger()
		if t != trigger && t != op.TriggerAlways {
			continue
		}
		if st.InteractionsRun[ix.Name()] {
			continue
		}
		step, err := ix.Begin(ctx, op.BeginInput{
			Subject:  st.Subject,
			ClientID: st.ClientID,
			AuthTime: now,
		})
		if err != nil {
			return st, op.Step{}, false, err
		}
		if step.Prompt != nil {
			next, emitted, perr := o.emitInteractionPrompt(st, ix, *step.Prompt, now)
			if perr != nil {
				return st, op.Step{}, false, perr
			}
			return next, emitted, false, nil
		}
		if step.Result == nil {
			return st, op.Step{}, false, ErrInvalidStep
		}
		st.InteractionsRun[ix.Name()] = true
	}
	return st, op.Step{}, true, nil
}

// advanceAuthn picks the next factor candidate. The branches handle
// the captcha-before-factor case, the risk consult, and the
// subject-required factor skip rule.
func (o *Orchestrator) advanceAuthn(ctx context.Context, st State, now time.Time) (State, op.Step, error) {
	required, denied, err := o.runRiskPreFactor(ctx, st, now)
	if err != nil {
		return st, op.Step{}, err
	}
	if denied {
		return st, op.Step{}, ErrRiskDenied
	}

	candidates := o.eligibleAuthenticators(st, required)
	if len(candidates) == 0 {
		return st, op.Step{}, ErrNoEligibleAuthenticator
	}

	if o.captchaRequired(st) {
		next, step, perr := o.emitCaptchaPrompt(st, now)
		if perr != nil {
			return st, op.Step{}, perr
		}
		return next, step, nil
	}

	idx, auth := candidates[0].idx, candidates[0].auth
	step, err := auth.Begin(ctx, op.BeginInput{
		Subject:  st.Subject,
		ClientID: st.ClientID,
		AuthTime: now,
	})
	if err != nil {
		return st, op.Step{}, err
	}
	if step.Prompt != nil {
		st.ActiveFactorIdx = idx
		next, emitted, perr := o.emitFactorPrompt(st, auth, *step.Prompt, now)
		if perr != nil {
			return st, op.Step{}, perr
		}
		return next, emitted, nil
	}
	if step.Result == nil {
		return st, op.Step{}, ErrInvalidStep
	}
	st.ActiveFactorIdx = idx
	st = o.appendFactor(st, auth, *step.Result)
	o.observeSuccess(ctx, st, now, auth.Type())
	denied2, derr := o.runRiskPostFactor(ctx, st, now, auth.Type())
	if derr != nil {
		return st, op.Step{}, derr
	}
	if denied2 {
		return st, op.Step{}, ErrRiskDenied
	}
	st.ActiveFactorIdx = -1
	st.Phase = PhaseAfterAuthn
	return st, op.Step{}, nil
}

// candidateAuthenticator pairs an authenticator with its index in the
// configuration slice so a re-ordered candidate list keeps the index
// reachable for [State.ActiveFactorIdx].
type candidateAuthenticator struct {
	idx  int
	auth op.Authenticator
}

// eligibleAuthenticators filters the registered chain by the
// risk-required FactorType set (when non-empty) and by the
// subject-required skip rule. The returned slice preserves the
// configuration order so the orchestrator's "first candidate wins"
// rule stays deterministic.
func (o *Orchestrator) eligibleAuthenticators(st State, required []op.FactorType) []candidateAuthenticator {
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
func (o *Orchestrator) emitCaptchaPrompt(st State, now time.Time) (State, op.Step, error) {
	st.StepCounter++
	ref, err := o.cfg.StateRefSigner.Issue(st.InteractionUID, tagCaptcha, st.StepCounter, now.Add(stateRefTTL))
	if err != nil {
		return st, op.Step{}, err
	}
	prompt := op.Prompt{
		Type:     "captcha",
		Data:     op.CaptchaPromptData{},
		StateRef: ref,
	}
	return st, op.Step{Prompt: &prompt}, nil
}

// emitFactorPrompt re-issues the prompt the authenticator returned
// with a freshly minted StateRef bound to the active factor's type.
func (o *Orchestrator) emitFactorPrompt(st State, auth op.Authenticator, prompt op.Prompt, now time.Time) (State, op.Step, error) {
	st.StepCounter++
	ref, err := o.cfg.StateRefSigner.Issue(st.InteractionUID, tagAuthPrefix+string(auth.Type()), st.StepCounter, now.Add(stateRefTTL))
	if err != nil {
		return st, op.Step{}, err
	}
	prompt.StateRef = ref
	return st, op.Step{Prompt: &prompt}, nil
}

// emitInteractionPrompt mirrors emitFactorPrompt for non-authn
// interactions and stores the active interaction name on st so the
// next submission routes back here.
func (o *Orchestrator) emitInteractionPrompt(st State, ix op.Interaction, prompt op.Prompt, now time.Time) (State, op.Step, error) {
	st.StepCounter++
	ref, err := o.cfg.StateRefSigner.Issue(st.InteractionUID, tagInteractionPrefix+ix.Name(), st.StepCounter, now.Add(stateRefTTL))
	if err != nil {
		return st, op.Step{}, err
	}
	prompt.StateRef = ref
	st.ActiveInteractionName = ix.Name()
	return st, op.Step{Prompt: &prompt}, nil
}

// emitTerminal returns the chain-complete Step the HTTP layer hands
// back to the SPA. The Result carries the final Subject and the
// AuthTime of the last factor (the orchestrator stores the latter on
// State while folding factors).
func (o *Orchestrator) emitTerminal(st State) (State, op.Step, error) {
	res := op.Result{
		Subject:  st.Subject,
		AuthTime: st.AuthTime,
	}
	return st, op.Step{Result: &res}, nil
}

// appendFactor is the single point where the orchestrator records a
// successful authenticator run. It enforces the §E.6.1 invariant that
// only RFC 8176-registered AMR values reach the session: an
// unregistered return is logged and dropped (the Factor still
// contributes through [Factor.AMRValue] which derives from
// [op.FactorType]).
func (o *Orchestrator) appendFactor(st State, auth op.Authenticator, result op.Result) State {
	if amr := auth.AMR(); amr != "" && !IsRegisteredAMR(amr) {
		o.logger.Warn("authn: dropping unregistered AMR value",
			slog.String("authenticator_type", string(auth.Type())),
			slog.String("amr", amr),
		)
	}
	uv := false
	if auth.Type() == op.FactorPasskey {
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
func (o *Orchestrator) runRiskPreFactor(ctx context.Context, st State, now time.Time) ([]op.FactorType, bool, error) {
	if o.cfg.Risk == nil {
		return nil, false, nil
	}
	out, err := o.cfg.Risk.Assess(ctx, op.RiskInput{
		Stage:     op.RiskPreFactor,
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
	if out.Decision == op.RiskDeny {
		return nil, true, nil
	}
	if out.Decision == op.RiskRequire {
		return out.RequiredFactors, false, nil
	}
	return nil, false, nil
}

// runRiskPostFactor consults the assessor after a successful factor
// completion. The current implementation honours [op.RiskDeny] only;
// [op.RiskRequire] at PostFactor is queued by the next PreFactor pass
// (the orchestrator does not preempt the current factor).
func (o *Orchestrator) runRiskPostFactor(ctx context.Context, st State, now time.Time, last op.FactorType) (bool, error) {
	if o.cfg.Risk == nil {
		return false, nil
	}
	out, err := o.cfg.Risk.Assess(ctx, op.RiskInput{
		Stage:      op.RiskPostFactor,
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
	return out.Decision == op.RiskDeny, nil
}

// findInteractionIndex returns the index of the registered Interaction
// with the given name, or -1 when the name is unknown (in which case
// the active state is corrupt and the submission is rejected upstream).
// The index form keeps lookups under [ireturn] without exporting the
// op.Interaction concrete type from this package.
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

// observeSuccess fans out an [op.AttemptSuccess] event to every
// observer. The orchestrator does not retry on observer panics; the
// public-API contract is "non-blocking" (§M.6.3).
func (o *Orchestrator) observeSuccess(ctx context.Context, st State, now time.Time, factor op.FactorType) {
	o.fanOut(ctx, op.LoginAttempt{
		Subject:   st.Subject,
		ClientID:  st.ClientID,
		RemoteIP:  st.RemoteIP,
		UserAgent: st.UserAgent,
		Outcome:   op.AttemptSuccess,
		Factor:    factor,
		At:        now,
	})
}

// observeFailure fans out an [op.AttemptFailure] event. Subject is
// intentionally blanked on the failure path to avoid enumeration via
// the observer feed (§M.6.3).
func (o *Orchestrator) observeFailure(ctx context.Context, st State, now time.Time, factor op.FactorType) {
	o.fanOut(ctx, op.LoginAttempt{
		ClientID:  st.ClientID,
		RemoteIP:  st.RemoteIP,
		UserAgent: st.UserAgent,
		Outcome:   op.AttemptFailure,
		Factor:    factor,
		Reason:    "attempt.invalid_credentials",
		At:        now,
	})
}

// fanOut delivers evt to every registered observer in registration
// order. The orchestrator does not block on observer errors.
func (o *Orchestrator) fanOut(ctx context.Context, evt op.LoginAttempt) {
	for _, obs := range o.cfg.Observers {
		if obs == nil {
			continue
		}
		obs.Observe(ctx, evt)
	}
}

// collectAMR returns the registered AMR values across the supplied
// factor slice. The orchestrator hands the result to the
// [op.RiskAssessor] so the assessor sees only the post-filter view.
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
func containsFactor(slice []op.FactorType, t op.FactorType) bool {
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
func requiresSubject(t op.FactorType) bool {
	switch t {
	case op.FactorTOTP, op.FactorRecoveryCode, op.FactorEmailOTP:
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
)

// discardHandler is the slog handler the orchestrator uses when the
// caller did not configure a logger. It mirrors the silent default in
// op/options.go so the orchestrator never panics on a nil logger.
type discardHandler struct{}

func (discardHandler) Enabled(_ context.Context, _ slog.Level) bool  { return false }
func (discardHandler) Handle(_ context.Context, _ slog.Record) error { return nil }
func (h discardHandler) WithAttrs(_ []slog.Attr) slog.Handler        { return h }
func (h discardHandler) WithGroup(_ string) slog.Handler             { return h }
