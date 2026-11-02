package authn

import (
	"context"
	"time"

	"github.com/libraz/go-oidc-provider/op/interaction"
)

// This file is the "phases" responsibility within the authn package:
// the chain dispatcher (advance / advanceOnce), which hands [PhaseAuthn]
// to [Orchestrator.advanceLoginFlow], and the BeforeAuthn / AfterAuthn /
// BeforeToken interaction queues (advancePhaseInteractions /
// advanceInteractions).
//
// They share the [Orchestrator] receiver because the state machine is
// dense — every advance step reads cfg.Interactions / cfg.LoginFlow,
// dispatches to the per-step audit fan-out, and asks the StateRefSigner
// to mint a fresh token.

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
		// A subject the chooser actively bound enters PhaseAuthn standing
		// on the picked session, so the LoginFlow plans it as it plans an
		// entry session. The self-skip path leaves ChooserBoundSubject false.
		if transition && next.Phase == PhaseAuthn && next.ChooserBoundSubject && !next.ReauthRequired {
			next = adoptChooserPick(ctx, next, in)
		}
		return next, step, transition, err
	case PhaseAuthn:
		next, step, err := o.advanceLoginFlow(ctx, st, in.Now)
		// The flow may transition to PhaseAfterAuthn without emitting
		// a Prompt (Allow / no-rule-matched / decider-Pass + empty
		// rules). Detect the phase change so the dispatcher re-enters
		// with the updated phase rather than tripping the stuck-chain
		// guard.
		transition := next.Phase != PhaseAuthn
		return next, step, transition, err
	case PhaseAfterAuthn:
		return o.advancePhaseInteractions(ctx, st, in.Now, TriggerAfterAuthn, PhaseBeforeToken)
	case PhaseBeforeToken:
		return o.advancePhaseInteractions(ctx, st, in.Now, TriggerBeforeToken, PhaseDone)
	case PhaseDone:
		next, step, err := o.emitTerminal(st)
		return next, step, false, err
	}
	return st, interaction.Step{}, false, ErrInvalidStep
}

// adoptChooserPick makes the session the account chooser bound the
// chain's entry session, so [Orchestrator.advanceLoginFlow] applies the
// Decider, the rules, risk and the inherited-step reading to it exactly
// as to the session a request arrived with. A pick that may not serve
// the request, or that the caller cannot vouch for, is re-authenticated
// for the bound subject instead ([requireReauth]).
func adoptChooserPick(ctx context.Context, st State, in Input) State {
	var entry *EntryAuthn
	if in.ChooserPick != nil {
		entry = in.ChooserPick(ctx, st)
	}
	if entry == nil || entry.Subject == "" || entry.Subject != st.Subject {
		return requireReauth(st)
	}
	st.EntryAuthn = entry
	return st
}

// advancePhaseInteractions runs the BeforeAuthn / AfterAuthn /
// BeforeToken interaction loop and signals a phase transition when the queue is drained.
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

// emitInteractionPrompt issues a fresh StateRef for a non-authn
// interaction's prompt and stores the active interaction name on st so
// the next submission routes back here.
func (o *Orchestrator) emitInteractionPrompt(st State, ix Interaction, prompt interaction.Prompt, now time.Time) (State, interaction.Step, error) {
	st.StepCounter++
	ref, err := o.cfg.StateRefSigner.Issue(st.InteractionUID, tagInteractionPrefix+ix.Name(), st.StepCounter, now.Add(stateRefTTL))
	if err != nil {
		return st, interaction.Step{}, err
	}
	prompt.StateRef = ref
	st.ActiveInteractionName = ix.Name()
	st = stampActiveInputs(st, prompt.Inputs)
	return st, interaction.Step{Prompt: &prompt}, nil
}

// emitTerminal returns the chain-complete Step the HTTP layer hands
// back to the SPA. The Result carries the final Subject, the
// AuthTime of the last factor, and the consent-approved scope subset
// the orchestrator stamped onto [State.ApprovedScopes] (empty when no
// consent-shaped Interaction ran).
//
// It is the single terminal exit of every surface (LoginFlow,
// chooser), which is why the
// [State.ReauthRequired] backstop lives here rather than in each
// dispatch branch: a request that demanded a fresh authentication
// never leaves with a factor-less Result.
func (o *Orchestrator) emitTerminal(st State) (State, interaction.Step, error) {
	if st.ReauthRequired && len(st.Factors) == 0 {
		return st, interaction.Step{}, ErrReauthNotPerformed
	}
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
