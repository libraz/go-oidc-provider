package authn_test

import (
	"context"
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

// TestTick_AAL3WithoutUVRejected covers M-AUTHN-3: an authenticator
// that reports [op.AAL3] but completes a Continue with
// [interaction.Result.UserVerified] = false MUST be rejected by the
// orchestrator with [authn.ErrAAL3RequiresUV]. NIST SP 800-63B AAL3
// requires user verification; allowing the chain to advance under a
// presence-only assertion would silently mint a session at a higher
// assurance level than the factor achieved.
func TestTick_AAL3WithoutUVRejected(t *testing.T) {
	t.Parallel()

	auth := &stubAuthenticator{
		typeID:  op.FactorPasskey,
		aal:     op.AAL3,
		amr:     "hwk",
		prompts: []string{"auth.passkey"},
		beginFn: func(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
			return interaction.Step{Prompt: &interaction.Prompt{
				Type: "auth.passkey",
				Data: interaction.PasskeyPromptData{},
			}}, nil
		},
		continueFn: func(_ context.Context, in op.ContinueInput) (interaction.Step, error) {
			return interaction.Step{Result: &interaction.Result{
				Subject:      "user-aal3",
				AuthTime:     in.AuthTime,
				UserVerified: false,
			}}, nil
		},
	}
	o, err := authn.New(authn.Config{
		Authenticators: []op.Authenticator{auth},
		StateRefSigner: newSigner(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	st, step, err := o.Tick(context.Background(), initialState(), authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("first Tick: %v", err)
	}
	if step.Prompt == nil {
		t.Fatalf("expected prompt, got %+v", step)
	}

	_, _, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{
			StateRef: step.Prompt.StateRef,
			Values:   map[string]string{"assertion": "{}"},
		},
		Now: fakeNow(),
	})
	if !errors.Is(err, authn.ErrAAL3RequiresUV) {
		t.Fatalf("err=%v want ErrAAL3RequiresUV", err)
	}
}

// TestTick_AAL3WithUVAccepted is the symmetric happy path: an AAL3
// authenticator that reports UV=true completes the chain normally.
func TestTick_AAL3WithUVAccepted(t *testing.T) {
	t.Parallel()

	auth := &stubAuthenticator{
		typeID:  op.FactorPasskey,
		aal:     op.AAL3,
		amr:     "hwk",
		prompts: []string{"auth.passkey"},
		beginFn: func(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
			return interaction.Step{Prompt: &interaction.Prompt{
				Type: "auth.passkey",
				Data: interaction.PasskeyPromptData{},
			}}, nil
		},
		continueFn: func(_ context.Context, in op.ContinueInput) (interaction.Step, error) {
			return interaction.Step{Result: &interaction.Result{
				Subject:      "user-aal3",
				AuthTime:     in.AuthTime,
				UserVerified: true,
			}}, nil
		},
	}
	o, err := authn.New(authn.Config{
		Authenticators: []op.Authenticator{auth},
		StateRefSigner: newSigner(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	st, step, err := o.Tick(context.Background(), initialState(), authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("first Tick: %v", err)
	}
	if step.Prompt == nil {
		t.Fatalf("expected prompt, got %+v", step)
	}

	_, finalStep, err := o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{
			StateRef: step.Prompt.StateRef,
			Values:   map[string]string{"assertion": "{}"},
		},
		Now: fakeNow(),
	})
	if err != nil {
		t.Fatalf("second Tick: %v", err)
	}
	if finalStep.Result == nil {
		t.Fatalf("expected terminal Result, got %+v", finalStep)
	}
	if finalStep.Result.Subject != "user-aal3" {
		t.Errorf("Subject=%q want user-aal3", finalStep.Result.Subject)
	}
}

// TestTick_AAL2WithoutUVUnaffected confirms the gate fires only on
// AAL3. An AAL2 factor (e.g. presence-only passkey) completing
// Continue with UV=false must still be accepted; the gate is
// AAL3-specific.
func TestTick_AAL2WithoutUVUnaffected(t *testing.T) {
	t.Parallel()

	auth := &stubAuthenticator{
		typeID:  op.FactorPasskey,
		aal:     op.AAL2,
		amr:     "swk",
		prompts: []string{"auth.passkey"},
		beginFn: func(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
			return interaction.Step{Prompt: &interaction.Prompt{
				Type: "auth.passkey",
				Data: interaction.PasskeyPromptData{},
			}}, nil
		},
		continueFn: func(_ context.Context, in op.ContinueInput) (interaction.Step, error) {
			return interaction.Step{Result: &interaction.Result{
				Subject:      "user-aal2",
				AuthTime:     in.AuthTime,
				UserVerified: false,
			}}, nil
		},
	}
	o, err := authn.New(authn.Config{
		Authenticators: []op.Authenticator{auth},
		StateRefSigner: newSigner(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	st, step, err := o.Tick(context.Background(), initialState(), authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("first Tick: %v", err)
	}
	_, finalStep, err := o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{
			StateRef: step.Prompt.StateRef,
			Values:   map[string]string{"assertion": "{}"},
		},
		Now: fakeNow(),
	})
	if err != nil {
		t.Fatalf("second Tick: %v", err)
	}
	if finalStep.Result == nil {
		t.Fatalf("expected terminal Result, got %+v", finalStep)
	}
}
