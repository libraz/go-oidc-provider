package op_test

import (
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

// registrationTestStep is an ExternalStep usable at any LoginFlow position.
func registrationTestStep(kind op.StepKind) op.ExternalStep {
	return op.ExternalStep{
		Authenticator: &stubAuth{typeID: op.FactorType("myorg.factor"), aal: op.AAL1, amr: "pwd", prompts: []string{"auth.password"}},
		KindLabel:     kind,
	}
}

// TestLoginFlowCompile_RegistrationAccepted is the control: an ExternalStep
// Registration under its own kind constructs.
func TestLoginFlowCompile_RegistrationAccepted(t *testing.T) {
	t.Parallel()

	flow := op.LoginFlow{
		Primary:      registrationTestStep("myorg.password"),
		Registration: registrationTestStep("myorg.signup"),
		Rules: []op.Rule{
			{When: func(op.LoginContext) bool { return true }, Then: registrationTestStep("myorg.otp")},
		},
	}
	if _, err := op.New(append(validBaseOptsNoAuthn(t), op.WithLoginFlow(flow))...); err != nil {
		t.Fatalf("op.New: %v", err)
	}
}

// TestLoginFlowCompile_RegistrationRejected pins every shape op.New refuses
// at LoginFlow.Registration.
func TestLoginFlowCompile_RegistrationRejected(t *testing.T) {
	t.Parallel()

	always := func(op.LoginContext) bool { return true }
	countFailures := registrationTestStep("myorg.signup")
	countFailures.CountFailures = true
	for _, tc := range []struct {
		name string
		flow op.LoginFlow
		want string
	}{
		{
			name: "built-in step",
			flow: op.LoginFlow{
				Primary:      registrationTestStep("myorg.password"),
				Registration: op.StepCaptcha{Verifier: typedCaptchaVerifier{}},
			},
			want: "Registration must be an ExternalStep",
		},
		{
			name: "unrecognised step",
			flow: op.LoginFlow{
				Primary:      registrationTestStep("myorg.password"),
				Registration: foreignStep{kind: "myorg.signup"},
			},
			want: "Registration must be an ExternalStep",
		},
		{
			name: "StepOneOf",
			flow: op.LoginFlow{
				Primary: registrationTestStep("myorg.password"),
				Registration: op.StepOneOf{Steps: []op.Step{
					registrationTestStep("myorg.signup"),
					registrationTestStep("myorg.signup2"),
				}},
			},
			want: "Registration must be an ExternalStep",
		},
		{
			name: "CountFailures",
			flow: op.LoginFlow{
				Primary:      registrationTestStep("myorg.password"),
				Registration: countFailures,
			},
			want: "CountFailures",
		},
		{
			name: "empty KindLabel",
			flow: op.LoginFlow{
				Primary:      registrationTestStep("myorg.password"),
				Registration: registrationTestStep(""),
			},
			want: "Registration.KindLabel must not be empty",
		},
		{
			name: "built-in KindLabel",
			flow: op.LoginFlow{
				Primary:      registrationTestStep("myorg.password"),
				Registration: registrationTestStep(op.StepKindPassword),
			},
			want: "built-in StepKind",
		},
		{
			name: "bare KindLabel",
			flow: op.LoginFlow{
				Primary:      registrationTestStep("myorg.password"),
				Registration: registrationTestStep("signup"),
			},
			want: "dotted prefix",
		},
		{
			name: "KindLabel shared with Primary",
			flow: op.LoginFlow{
				Primary:      registrationTestStep("myorg.signup"),
				Registration: registrationTestStep("myorg.signup"),
			},
			want: "already used by Primary",
		},
		{
			name: "KindLabel shared with a Primary StepOneOf member",
			flow: op.LoginFlow{
				Primary: op.StepOneOf{Steps: []op.Step{
					registrationTestStep("myorg.password"),
					registrationTestStep("myorg.signup"),
				}},
				Registration: registrationTestStep("myorg.signup"),
			},
			want: "already used by Primary.StepOneOf.Steps[1]",
		},
		{
			name: "KindLabel shared with a Rule StepOneOf member",
			flow: op.LoginFlow{
				Primary:      registrationTestStep("myorg.password"),
				Registration: registrationTestStep("myorg.signup"),
				Rules: []op.Rule{{When: always, Then: op.StepOneOf{Steps: []op.Step{
					registrationTestStep("myorg.signup"),
					registrationTestStep("myorg.otp"),
				}}}},
			},
			want: "already used by Rules[0].Then.StepOneOf.Steps[0]",
		},
		{
			name: "Rule names the Registration kind",
			flow: op.LoginFlow{
				Primary:      registrationTestStep("myorg.password"),
				Registration: registrationTestStep("myorg.signup"),
				Rules:        []op.Rule{{When: always, Then: registrationTestStep("myorg.signup")}},
			},
			want: "Rules[0].Then must not name the Registration StepKind",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := op.New(append(validBaseOptsNoAuthn(t), op.WithLoginFlow(tc.flow))...)
			if err == nil {
				t.Fatal("op.New accepted the flow, want a configuration error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}
