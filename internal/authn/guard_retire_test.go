package authn_test

import (
	"context"
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

// guardedFactor emits a prompt carrying scratch and completes with
// result, so the orchestrator's result guards decide the outcome.
func guardedFactor(aal op.AAL, result interaction.Result) *stubAuthenticator {
	return &stubAuthenticator{
		typeID:  op.FactorPasskey,
		aal:     aal,
		amr:     "hwk",
		prompts: []string{"auth.passkey"},
		beginFn: func(context.Context, op.BeginInput) (interaction.Step, error) {
			return interaction.Step{
				Prompt:  &interaction.Prompt{Type: "auth.passkey"},
				Scratch: []byte("challenge"),
			}, nil
		},
		continueFn: func(context.Context, op.ContinueInput) (interaction.Step, error) {
			return interaction.Step{Result: &result}, nil
		},
	}
}

// TestTick_GuardRejectionRetiresFactorToken pins that a factor result the
// chain refuses to record — a different subject, or AAL3 without user
// verification — ends the attempt as an ErrFactorAbort and leaves neither
// the ceremony's scratch nor its StateRef usable, whether the factor runs
// as Primary or as a rule step.
func TestTick_GuardRejectionRetiresFactorToken(t *testing.T) {
	t.Parallel()

	bound := initialState()
	bound.Subject = "user-1"
	bound.ChooserBoundSubject = true
	bound.ReauthRequired = true

	guards := []struct {
		name string
		st   authn.State
		auth *stubAuthenticator
		want error
	}{
		{
			name: "subject mismatch",
			st:   bound,
			auth: guardedFactor(op.AAL2, interaction.Result{Subject: "user-2", AuthTime: fakeNow(), UserVerified: true}),
			want: authn.ErrSubjectMismatch,
		},
		{
			name: "AAL3 without UV",
			st:   initialState(),
			auth: guardedFactor(op.AAL3, interaction.Result{Subject: "user-1", AuthTime: fakeNow()}),
			want: authn.ErrAAL3RequiresUV,
		},
	}
	for _, g := range guards {
		for _, surface := range []string{"primary", "rule"} {
			t.Run(g.name+"/"+surface, func(t *testing.T) {
				t.Parallel()
				cfg := authn.Config{StateRefSigner: newSigner(t)}
				start := g.st
				if surface == "primary" {
					flow, err := authn.CompileLoginFlow(authn.LoginFlowSpec{
						Primary: authn.LoginFlowStep{Kind: "test.passkey", Authenticator: g.auth},
					})
					if err != nil {
						t.Fatalf("CompileLoginFlow: %v", err)
					}
					cfg.LoginFlow = flow
				} else {
					// Primary binds user-1 in this chain, so the guarded
					// factor runs as the rule step after it.
					cfg.LoginFlow = chainFlow(t, buildSuccessAuthenticator(op.FactorPassword, op.AAL1, "pwd"), g.auth)
					start = initialState()
				}
				o, err := authn.New(cfg)
				if err != nil {
					t.Fatalf("New: %v", err)
				}

				st, step, err := o.Tick(context.Background(), start, authn.Input{Now: fakeNow()})
				if err != nil || step.Prompt == nil {
					t.Fatalf("first Tick: step=%+v err=%v", step, err)
				}
				if surface == "rule" {
					primary := &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{}}
					st, step, err = o.Tick(context.Background(), st, authn.Input{Submission: primary, Now: fakeNow()})
					if err != nil || step.Prompt == nil {
						t.Fatalf("Primary submission: step=%+v err=%v", step, err)
					}
				}
				sub := &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{}}
				st, _, err = o.Tick(context.Background(), st, authn.Input{Submission: sub, Now: fakeNow()})
				if !errors.Is(err, g.want) || !errors.Is(err, authn.ErrFactorAbort) {
					t.Fatalf("err = %v, want %v wrapping ErrFactorAbort", err, g.want)
				}
				if st.FactorScratch != nil {
					t.Errorf("FactorScratch = %q after the rejection, want it cleared", st.FactorScratch)
				}
				if _, _, err := o.Tick(context.Background(), st, authn.Input{Submission: sub, Now: fakeNow()}); !errors.Is(err, authn.ErrInvalidStateRef) {
					t.Errorf("resubmitting the rejected ceremony: err = %v, want ErrInvalidStateRef", err)
				}
			})
		}
	}
}
