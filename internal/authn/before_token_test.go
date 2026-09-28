package authn_test

import (
	"context"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

// deviceTrustInteraction is a two-screen BeforeToken interaction: Begin
// asks for the device, the first Continue asks for confirmation, and
// the second Continue completes. calls records every Begin / Continue in
// order so a test can assert where the interaction ran in the chain.
func deviceTrustInteraction(calls *[]string) *stubInteraction {
	continued := 0
	return &stubInteraction{
		name:    "myorg.device.trust",
		trigger: op.TriggerBeforeToken,
		beginFn: func(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
			*calls = append(*calls, "device.begin")
			return interaction.Step{Prompt: &interaction.Prompt{Type: "myorg.device.pick"}}, nil
		},
		continueFn: func(_ context.Context, _ op.ContinueInput) (interaction.Step, error) {
			continued++
			*calls = append(*calls, "device.continue")
			if continued == 1 {
				return interaction.Step{Prompt: &interaction.Prompt{Type: "myorg.device.confirm"}}, nil
			}
			return interaction.Step{Result: &interaction.Result{}}, nil
		},
	}
}

func TestTickBeforeTokenRunsAfterConsentBeforeResult(t *testing.T) {
	t.Parallel()

	var calls []string
	pw := buildSuccessAuthenticator(op.FactorPassword, op.AAL1, "pwd")
	consent := &stubInteraction{
		name:    authn.BuiltinConsentName,
		trigger: op.TriggerAfterAuthn,
		beginFn: func(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
			calls = append(calls, "consent.begin")
			return interaction.Step{Prompt: &interaction.Prompt{Type: "consent.scope"}}, nil
		},
		continueFn: func(_ context.Context, _ op.ContinueInput) (interaction.Step, error) {
			calls = append(calls, "consent.continue")
			return interaction.Step{Result: &interaction.Result{Scope: []string{"openid"}}}, nil
		},
	}
	// Registered ahead of consent: the phase, not the slice order,
	// decides when it runs.
	device := deviceTrustInteraction(&calls)
	o, err := authn.New(authn.Config{
		Authenticators: []op.Authenticator{pw},
		Interactions:   []op.Interaction{device, consent},
		StateRefSigner: newSigner(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	wantPrompts := []string{"auth.password", "consent.scope", "myorg.device.pick", "myorg.device.confirm"}
	st, step, err := o.Tick(context.Background(), initialState(), authn.Input{Now: fakeNow()})
	for i, want := range wantPrompts {
		if err != nil {
			t.Fatalf("tick %d: %v", i, err)
		}
		if step.Result != nil {
			t.Fatalf("tick %d: terminal Result before %q was answered", i, want)
		}
		if step.Prompt == nil || step.Prompt.Type != want {
			t.Fatalf("tick %d: prompt = %+v, want %q", i, step.Prompt, want)
		}
		st, step, err = o.Tick(context.Background(), st, authn.Input{
			Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef},
			Now:        fakeNow(),
		})
	}
	if err != nil {
		t.Fatalf("final tick: %v", err)
	}
	if step.Result == nil {
		t.Fatalf("expected terminal Result once the device interaction completed, got %+v", step)
	}
	if st.Phase != authn.PhaseDone || !st.InteractionsRun["myorg.device.trust"] {
		t.Fatalf("phase = %v, run = %v; want PhaseDone with the device interaction recorded", st.Phase, st.InteractionsRun)
	}
	wantCalls := []string{"consent.begin", "consent.continue", "device.begin", "device.continue", "device.continue"}
	if len(calls) != len(wantCalls) {
		t.Fatalf("calls = %v, want %v", calls, wantCalls)
	}
	for i := range wantCalls {
		if calls[i] != wantCalls[i] {
			t.Fatalf("calls = %v, want %v", calls, wantCalls)
		}
	}
}

// A chain the HTTP layer starts at PhaseBeforeToken — a live session
// whose cached grant already covers consent — still stops at the
// BeforeToken interaction instead of emitting the terminal Result.
func TestTickBeforeTokenGatesSessionReuse(t *testing.T) {
	t.Parallel()

	var calls []string
	pw := buildSuccessAuthenticator(op.FactorPassword, op.AAL1, "pwd")
	o, err := authn.New(authn.Config{
		Authenticators: []op.Authenticator{pw},
		Interactions:   []op.Interaction{deviceTrustInteraction(&calls)},
		StateRefSigner: newSigner(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	st := initialState()
	st.Subject = "alice"
	st.Phase = authn.PhaseBeforeToken

	st, step, err := o.Tick(context.Background(), st, authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if step.Result != nil || step.Prompt == nil || step.Prompt.Type != "myorg.device.pick" {
		t.Fatalf("step = %+v, want the device prompt and no Result", step)
	}
	for _, want := range []string{"myorg.device.confirm", ""} {
		st, step, err = o.Tick(context.Background(), st, authn.Input{
			Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef},
			Now:        fakeNow(),
		})
		if err != nil {
			t.Fatalf("Tick: %v", err)
		}
		if want != "" && (step.Result != nil || step.Prompt == nil || step.Prompt.Type != want) {
			t.Fatalf("step = %+v, want prompt %q and no Result", step, want)
		}
	}
	if step.Result == nil || step.Result.Subject != "alice" {
		t.Fatalf("step = %+v, want terminal Result for the session subject", step)
	}
}

func TestHasInteractions(t *testing.T) {
	t.Parallel()

	var calls []string
	pw := buildSuccessAuthenticator(op.FactorPassword, op.AAL1, "pwd")
	o, err := authn.New(authn.Config{
		Authenticators: []op.Authenticator{pw},
		Interactions:   []op.Interaction{deviceTrustInteraction(&calls)},
		StateRefSigner: newSigner(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !o.HasInteractions(op.TriggerBeforeToken) {
		t.Error("HasInteractions(TriggerBeforeToken) = false with a BeforeToken interaction registered")
	}
	if o.HasInteractions(op.TriggerAfterAuthn) {
		t.Error("HasInteractions(TriggerAfterAuthn) = true with none registered")
	}
}
