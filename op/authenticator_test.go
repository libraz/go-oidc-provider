package op_test

import (
	"context"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

func TestFactorType_IsBuiltin(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   op.FactorType
		want bool
	}{
		{op.FactorPassword, true},
		{op.FactorTOTP, true},
		{op.FactorPasskey, true},
		{op.FactorRecoveryCode, true},
		{op.FactorEmailOTP, true},
		{"myorg.sms", false},
		{"", false},
		{"unknown", false},
		{"PASSWORD", false}, // case-sensitive
	}
	for _, tc := range cases {
		if got := tc.in.IsBuiltin(); got != tc.want {
			t.Errorf("FactorType(%q).IsBuiltin() = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestFactorType_IsUserDefined(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   op.FactorType
		want bool
	}{
		{"myorg.sms", true},
		{"acme.kerberos", true},
		{"a.b", true},
		{op.FactorPassword, false}, // built-in
		{op.FactorEmailOTP, false}, // built-in
		{"", false},                // empty
		{"sms_otp", false},         // no dot
		{"missing-prefix", false},  // no dot
	}
	for _, tc := range cases {
		if got := tc.in.IsUserDefined(); got != tc.want {
			t.Errorf("FactorType(%q).IsUserDefined() = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestFactorType_String(t *testing.T) {
	t.Parallel()

	if got := op.FactorPassword.String(); got != "password" {
		t.Errorf("FactorPassword.String() = %q, want %q", got, "password")
	}
}

// stubAuthenticator is the minimal [op.Authenticator] used by option-
// validation tests. Begin / Continue are never invoked in this task
// (the orchestrator that exercises them lands in a follow-up task);
// the stub returns zero values so the compile-time interface check is
// the value the test extracts.
type stubAuthenticator struct {
	typ     op.FactorType
	aal     op.AAL
	amr     string
	prompts []string
}

func (s stubAuthenticator) Type() op.FactorType { return s.typ }
func (s stubAuthenticator) AAL() op.AAL         { return s.aal }
func (s stubAuthenticator) AMR() string         { return s.amr }
func (s stubAuthenticator) Prompts() []string   { return s.prompts }

func (s stubAuthenticator) Begin(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
	return interaction.Step{}, nil
}

func (s stubAuthenticator) Continue(_ context.Context, _ op.ContinueInput) (interaction.Step, error) {
	return interaction.Step{}, nil
}

// stubInteraction is the minimal [op.Interaction] used by option-
// validation tests.
type stubInteraction struct {
	name    string
	trigger op.InteractionTrigger
}

func (s stubInteraction) Name() string                   { return s.name }
func (s stubInteraction) Trigger() op.InteractionTrigger { return s.trigger }

func (s stubInteraction) Begin(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
	return interaction.Step{}, nil
}

func (s stubInteraction) Continue(_ context.Context, _ op.ContinueInput) (interaction.Step, error) {
	return interaction.Step{}, nil
}

// Compile-time confirmation that the stubs satisfy the public
// interfaces.
var (
	_ op.Authenticator = stubAuthenticator{}
	_ op.Interaction   = stubInteraction{}
)

// Compile-time confirmation that BeginInput / Result carry the
// expected fields without breaking signatures across edits.
var (
	_ time.Time = op.BeginInput{}.AuthTime
	_ time.Time = interaction.Result{}.AuthTime
)
