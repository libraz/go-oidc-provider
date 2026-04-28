package op_test

import (
	"context"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

// stepNotWiredMessage is the substring every built-in Step's
// placeholder error MUST contain. H1-D ships the orchestrator
// integration and the [op.ExternalStep] seam but defers per-Step
// primitive wiring (TOTP codec, passkey RP origin, hash adapter,
// email delivery, …) to follow-up waves; built-in Step values such
// as [op.PrimaryPassword] continue to return this sentinel directly
// from Begin / Continue. The compiler in [internal/authn] refuses
// to compile a [op.LoginFlow] that names a built-in Step until the
// follow-up lands, so the deferral surfaces at construction time
// rather than the first request. Update this constant when each
// built-in Step's primitive becomes reachable.
const stepNotWiredMessage = "built-in Step requires LoginFlow compilation"

// TestStepKinds pins that every built-in [op.Step] reports the
// matching [op.StepKind] constant. The mapping is part of the public
// contract; renaming a constant here is a breaking change for any
// rule predicate that inspects [op.LoginContext.CompletedSteps].
func TestStepKinds(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		step op.Step
		want op.StepKind
	}{
		{name: "PrimaryPassword", step: op.PrimaryPassword{}, want: op.StepKindPassword},
		{name: "PrimaryPasskey", step: op.PrimaryPasskey{}, want: op.StepKindPasskey},
		{name: "StepTOTP", step: op.StepTOTP{}, want: op.StepKindTOTP},
		{name: "StepEmailOTP", step: op.StepEmailOTP{}, want: op.StepKindEmailOTP},
		{name: "StepCaptcha", step: op.StepCaptcha{}, want: op.StepKindCaptcha},
		{name: "StepRecoveryCode", step: op.StepRecoveryCode{}, want: op.StepKindRecoveryCode},
	}
	for _, tc := range cases {
		if got := tc.step.Kind(); got != tc.want {
			t.Errorf("%s.Kind() = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestStepBeginContinueNotWired pins that every built-in [op.Step]
// returns the placeholder "step not yet wired" sentinel from Begin
// and Continue. The test exists to flip red the moment a follow-up
// wave wires the orchestrator, ensuring the placeholder is never
// silently left in place.
func TestStepBeginContinueNotWired(t *testing.T) {
	t.Parallel()
	steps := []struct {
		name string
		step op.Step
	}{
		{"PrimaryPassword", op.PrimaryPassword{}},
		{"PrimaryPasskey", op.PrimaryPasskey{}},
		{"StepTOTP", op.StepTOTP{}},
		{"StepEmailOTP", op.StepEmailOTP{}},
		{"StepCaptcha", op.StepCaptcha{}},
		{"StepRecoveryCode", op.StepRecoveryCode{}},
	}
	ctx := context.Background()
	for _, s := range steps {
		_, err := s.step.Begin(ctx, op.BeginInput{})
		if err == nil || !strings.Contains(err.Error(), stepNotWiredMessage) {
			t.Errorf("%s.Begin: err=%v, want error containing %q", s.name, err, stepNotWiredMessage)
		}
		_, err = s.step.Continue(ctx, op.ContinueInput{})
		if err == nil || !strings.Contains(err.Error(), stepNotWiredMessage) {
			t.Errorf("%s.Continue: err=%v, want error containing %q", s.name, err, stepNotWiredMessage)
		}
	}
}

// TestStepKindString covers the String() round-trip on the typed
// identifier.
func TestStepKindString(t *testing.T) {
	t.Parallel()
	if got := op.StepKindPassword.String(); got != "password" {
		t.Errorf("StepKindPassword.String() = %q, want %q", got, "password")
	}
}

// Compile-time confirmation that every built-in Step satisfies the
// public [op.Step] interface. A signature drift on Begin / Continue
// / Kind breaks compilation rather than producing a confusing test
// failure.
var (
	_ op.Step = op.PrimaryPassword{}
	_ op.Step = op.PrimaryPasskey{}
	_ op.Step = op.StepTOTP{}
	_ op.Step = op.StepEmailOTP{}
	_ op.Step = op.StepCaptcha{}
	_ op.Step = op.StepRecoveryCode{}
)
