package authn_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

// TestLoginFlow_RejectionStampsPromptError pins where the
// credentials-rejected notice rides: on the Prompt of the Step returned
// after a rejected submission, on both return paths, and nowhere on a
// terminal rejection.
func TestLoginFlow_RejectionStampsPromptError(t *testing.T) {
	t.Parallel()

	wantErr := func(t *testing.T, step interaction.Step) {
		t.Helper()
		if step.Prompt == nil {
			t.Fatalf("expected a prompt, got %+v", step)
		}
		if step.Prompt.Error == nil || step.Prompt.Error.Code != interaction.PromptErrorCredentialsRejected {
			t.Fatalf("Prompt.Error = %+v, want code %q", step.Prompt.Error, interaction.PromptErrorCredentialsRejected)
		}
	}

	t.Run("same factor re-shown", func(t *testing.T) {
		t.Parallel()

		pwPrompt := promptForFactor(op.FactorPassword)
		pw := &stubAuthenticator{
			typeID:  op.FactorPassword,
			aal:     op.AAL1,
			amr:     "pwd",
			prompts: []string{pwPrompt.Type},
			beginFn: func(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
				return interaction.Step{Prompt: &pwPrompt}, nil
			},
			continueFn: func(_ context.Context, in op.ContinueInput) (interaction.Step, error) {
				if in.Submission.Values["password"] == "correct" {
					return interaction.Step{Result: &interaction.Result{Subject: "user-1", AuthTime: fakeNow()}}, nil
				}
				return interaction.Step{}, fmt.Errorf("password: invalid: %w", authn.ErrFactorRetry)
			},
		}
		flow, err := authn.CompileLoginFlow(authn.LoginFlowSpec{
			Primary: authn.LoginFlowStep{Kind: "myorg.password", Authenticator: pw},
		})
		if err != nil {
			t.Fatalf("CompileLoginFlow: %v", err)
		}
		o, err := authn.New(authn.Config{LoginFlow: flow, StateRefSigner: newSigner(t)})
		if err != nil {
			t.Fatalf("New: %v", err)
		}

		st, step, err := o.Tick(context.Background(), initialState(), authn.Input{Now: fakeNow()})
		if err != nil {
			t.Fatalf("first Tick: %v", err)
		}
		if step.Prompt == nil || step.Prompt.Error != nil {
			t.Fatalf("initial prompt must carry no error, got %+v", step.Prompt)
		}
		st, step, err = o.Tick(context.Background(), st, authn.Input{
			Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"password": "wrong"}},
			Now:        fakeNow(),
		})
		if err != nil {
			t.Fatalf("wrong-password Tick: %v", err)
		}
		wantErr(t, step)
		if pwPrompt.Error != nil {
			t.Errorf("the authenticator's own prompt value was mutated: %+v", pwPrompt.Error)
		}

		// The next prompt built from a correct submission is a grant.
		_, step, err = o.Tick(context.Background(), st, authn.Input{
			Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"password": "correct"}},
			Now:        fakeNow(),
		})
		if err != nil {
			t.Fatalf("correct-password Tick: %v", err)
		}
		if step.Prompt != nil && step.Prompt.Error != nil {
			t.Errorf("a successful step must carry no error, got %+v", step.Prompt.Error)
		}
	})

	t.Run("email-OTP sub-prompt", func(t *testing.T) {
		t.Parallel()

		pw := successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")
		otp := multiStepFactorStub()
		flow, err := authn.CompileLoginFlow(authn.LoginFlowSpec{
			Primary: authn.LoginFlowStep{Kind: "myorg.password", Authenticator: pw},
			Rules: []authn.LoginFlowRule{
				{
					When: func(authn.LoginFlowContext) bool { return true },
					Then: authn.LoginFlowStep{Kind: "myorg.email_otp", Authenticator: otp},
				},
			},
		})
		if err != nil {
			t.Fatalf("CompileLoginFlow: %v", err)
		}
		o, err := authn.New(authn.Config{LoginFlow: flow, StateRefSigner: newSigner(t)})
		if err != nil {
			t.Fatalf("New: %v", err)
		}

		st, step := driveToEmailOTPVerify(t, o)
		_, step, err = o.Tick(context.Background(), st, authn.Input{
			Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"code": "000000"}},
			Now:        fakeNow(),
		})
		if err != nil {
			t.Fatalf("wrong-code Tick: %v", err)
		}
		if step.Prompt == nil || step.Prompt.Type != "auth.email_otp.verify" {
			t.Fatalf("expected the verify prompt, got %+v", step.Prompt)
		}
		wantErr(t, step)
	})

	t.Run("captcha interposes", func(t *testing.T) {
		t.Parallel()

		pwPrompt := promptForFactor(op.FactorPassword)
		pw := &stubAuthenticator{
			typeID:  op.FactorPassword,
			aal:     op.AAL1,
			amr:     "pwd",
			prompts: []string{pwPrompt.Type},
			beginFn: func(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
				return interaction.Step{Prompt: &pwPrompt}, nil
			},
			continueFn: func(_ context.Context, _ op.ContinueInput) (interaction.Step, error) {
				return interaction.Step{}, fmt.Errorf("password: invalid: %w", authn.ErrFactorRetry)
			},
		}
		captchaPrompt := interaction.Prompt{Type: "captcha"}
		captchaAuth := &stubAuthenticator{
			typeID:  "myorg.captcha",
			aal:     op.AAL1,
			amr:     "captcha",
			prompts: []string{captchaPrompt.Type},
			beginFn: func(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
				return interaction.Step{Prompt: &captchaPrompt}, nil
			},
			continueFn: func(_ context.Context, _ op.ContinueInput) (interaction.Step, error) {
				return interaction.Step{Result: &interaction.Result{}}, nil
			},
		}
		flow, err := authn.CompileLoginFlow(authn.LoginFlowSpec{
			Primary: authn.LoginFlowStep{Kind: "myorg.password", Authenticator: pw},
			Rules: []authn.LoginFlowRule{
				{
					When: func(lc authn.LoginFlowContext) bool { return lc.FailedAttempts >= 1 },
					Then: authn.LoginFlowStep{Kind: "myorg.captcha", Authenticator: captchaAuth, IsCaptcha: true},
				},
			},
		})
		if err != nil {
			t.Fatalf("CompileLoginFlow: %v", err)
		}
		o, err := authn.New(authn.Config{LoginFlow: flow, StateRefSigner: newSigner(t)})
		if err != nil {
			t.Fatalf("New: %v", err)
		}

		st, step, err := o.Tick(context.Background(), initialState(), authn.Input{Now: fakeNow()})
		if err != nil {
			t.Fatalf("first Tick: %v", err)
		}
		_, step, err = o.Tick(context.Background(), st, authn.Input{
			Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"password": "wrong"}},
			Now:        fakeNow(),
		})
		if err != nil {
			t.Fatalf("wrong-password Tick: %v", err)
		}
		if step.Prompt == nil || step.Prompt.Type != "captcha" {
			t.Fatalf("expected the captcha prompt, got %+v", step.Prompt)
		}
		wantErr(t, step)
	})

	t.Run("credentialRejectedFinal has no prompt", func(t *testing.T) {
		t.Parallel()

		pwPrompt := promptForFactor(op.FactorPassword)
		pw := &stubAuthenticator{
			typeID:  op.FactorPassword,
			aal:     op.AAL1,
			amr:     "pwd",
			prompts: []string{pwPrompt.Type},
			beginFn: func(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
				return interaction.Step{Prompt: &pwPrompt}, nil
			},
			continueFn: func(_ context.Context, _ op.ContinueInput) (interaction.Step, error) {
				return interaction.Step{}, fmt.Errorf("password: locked by this guess: %w", authn.ErrCredentialRejected)
			},
		}
		flow, err := authn.CompileLoginFlow(authn.LoginFlowSpec{
			Primary: authn.LoginFlowStep{Kind: "myorg.password", Authenticator: pw},
		})
		if err != nil {
			t.Fatalf("CompileLoginFlow: %v", err)
		}
		o, err := authn.New(authn.Config{LoginFlow: flow, StateRefSigner: newSigner(t)})
		if err != nil {
			t.Fatalf("New: %v", err)
		}

		st, step, err := o.Tick(context.Background(), initialState(), authn.Input{Now: fakeNow()})
		if err != nil {
			t.Fatalf("first Tick: %v", err)
		}
		_, step, err = o.Tick(context.Background(), st, authn.Input{
			Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"password": "wrong"}},
			Now:        fakeNow(),
		})
		if !errors.Is(err, authn.ErrCredentialRejected) {
			t.Fatalf("err = %v, want ErrCredentialRejected", err)
		}
		if step.Prompt != nil {
			t.Errorf("a terminal rejection must carry no prompt, got %+v", step.Prompt)
		}
	})
}
