package authn

import (
	"context"
	"time"

	"github.com/libraz/go-oidc-provider/op/interaction"
)

// This file is the "phases" responsibility within the authn package:
// the chain dispatcher (advance / advanceOnce), the BeforeAuthn /
// AfterAuthn interaction queues (advancePhaseInteractions /
// advanceInteractions), and the legacy Authenticators-driven
// advanceAuthn that dispatches into [Orchestrator.advanceLoginFlow]
// when a [CompiledLoginFlow] is configured.
//
// The helpers were extracted from orchestrator.go in the v0.9.1
// readability pass. They share the [Orchestrator] receiver because the
// state machine is dense — every advance step reads cfg.Authenticators
// / cfg.Interactions / cfg.LoginFlow, dispatches to the per-step audit
// fan-out, and asks the StateRefSigner to mint a fresh token. The
// behaviour is identical to the pre-split version; only the
// physical layout has changed.

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
			Client:          st.Client,
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
	required, minAAL, denied, err := o.runRiskPreFactor(ctx, st, now)
	if err != nil {
		return st, interaction.Step{}, err
	}
	if denied {
		return st, interaction.Step{}, ErrRiskDenied
	}

	candidates := o.eligibleAuthenticators(st, required, minAAL)
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
		Client:          st.Client,
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
// risk-required FactorType set (when non-empty), by the risk-required
// minimum-assurance floor (when minAAL > AAL0), and by the
// subject-required skip rule. The returned slice preserves the
// configuration order so the orchestrator's "first candidate wins"
// rule stays deterministic.
//
// The two risk filters compose per the RiskOutcome contract: a
// non-empty required set narrows the chain to those factor types, and
// minAAL further excludes any candidate whose [Authenticator.AAL] is
// below the floor. When required is empty but minAAL > AAL0 the
// directive is "any registered factor that meets minAAL", so the AAL
// filter alone applies — the whole chain is never returned unfiltered.
func (o *Orchestrator) eligibleAuthenticators(st State, required []FactorType, minAAL AAL) []candidateAuthenticator {
	out := make([]candidateAuthenticator, 0, len(o.cfg.Authenticators))
	for i, a := range o.cfg.Authenticators {
		if len(required) > 0 && !containsFactor(required, a.Type()) {
			continue
		}
		if minAAL > AAL0 && a.AAL() < minAAL {
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
// StepCounter so a stale token cannot replay. The prompt declares the
// [CaptchaTokenField] input so every driver has somewhere to put the
// provider's token: the HTML driver renders the hidden field for the
// widget's JS to fill, and a SPA reads the same field name off the
// envelope. A prompt without the field would leave the SPA no way to
// answer the challenge and the chain no way to leave it.
func (o *Orchestrator) emitCaptchaPrompt(st State, now time.Time) (State, interaction.Step, error) {
	st.StepCounter++
	ref, err := o.cfg.StateRefSigner.Issue(st.InteractionUID, tagCaptcha, st.StepCounter, now.Add(stateRefTTL))
	if err != nil {
		return st, interaction.Step{}, err
	}
	prompt := interaction.Prompt{
		Type: "captcha",
		Data: interaction.CaptchaPromptData{},
		Inputs: []interaction.FieldSpec{{
			Name:     CaptchaTokenField,
			Kind:     interaction.FieldHidden,
			Label:    "auth.captcha.token",
			Required: true,
			MaxLen:   captchaTokenMaxLen,
		}},
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
