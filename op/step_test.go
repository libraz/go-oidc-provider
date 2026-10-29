package op_test

import (
	"context"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

// stepNotWiredMessage is the substring a built-in Step's placeholder
// error MUST contain. A built-in [op.Step] is a declaration, not an
// authenticator: its construction-time dependencies (TOTP codec,
// passkey RP origin, hash adapter, email delivery) are resolved when
// [op.New] compiles the [op.LoginFlow], so calling Begin / Continue on
// the bare value — outside that compilation — has nothing to
// authenticate against and says so rather than failing obscurely
// later.
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
		{"StepOneOf", op.StepOneOf{}},
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

// TestStepOneOfKind pins the one-of kind: the inner kinds sorted and
// joined, so declaration order does not change it.
func TestStepOneOfKind(t *testing.T) {
	t.Parallel()
	ext := op.ExternalStep{KindLabel: "myorg.sms"}
	cases := []struct {
		name string
		step op.StepOneOf
		want op.StepKind
	}{
		{name: "sorted", step: op.StepOneOf{Steps: []op.Step{op.StepTOTP{}, op.PrimaryPasskey{}}}, want: "one_of(passkey,totp)"},
		{name: "order independent", step: op.StepOneOf{Steps: []op.Step{op.PrimaryPasskey{}, op.StepTOTP{}}}, want: "one_of(passkey,totp)"},
		{name: "external", step: op.StepOneOf{Steps: []op.Step{op.StepRecoveryCode{}, ext}}, want: "one_of(myorg.sms,recovery_code)"},
		{name: "single", step: op.StepOneOf{Steps: []op.Step{op.StepTOTP{}}}, want: "one_of(totp)"},
		{name: "empty", step: op.StepOneOf{}, want: "one_of()"},
	}
	for _, tc := range cases {
		if got := tc.step.Kind(); got != tc.want {
			t.Errorf("%s: Kind() = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestUnenrolledPolicyZeroIsDeny pins that an unset IfNoneEnrolled denies.
func TestUnenrolledPolicyZeroIsDeny(t *testing.T) {
	t.Parallel()
	if got := (op.StepOneOf{}).IfNoneEnrolled; got != op.UnenrolledDeny {
		t.Fatalf("zero IfNoneEnrolled = %v, want UnenrolledDeny", got)
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
	_ op.Step = op.StepOneOf{}
)
