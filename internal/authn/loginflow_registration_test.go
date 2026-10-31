package authn_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

const (
	registrationKind   = "test.signup"
	registrationFactor = op.FactorType("test.signup")
)

// countingPrimary is a password Primary binding user-1 whose Begin calls
// are counted, so a test can assert Primary never ran.
func countingPrimary(begins *int) *stubAuthenticator {
	primary := successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")
	prompt := promptForFactor(op.FactorPassword)
	primary.beginFn = func(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
		*begins++
		return interaction.Step{Prompt: &prompt}, nil
	}
	return primary
}

// registrationAuth is a Registration authenticator that prompts once and
// then binds subject.
func registrationAuth(subject string) *stubAuthenticator {
	return successAuth(registrationFactor, op.AAL1, "pwd", subject)
}

// registrationOrchestrator compiles spec and builds an orchestrator on it.
func registrationOrchestrator(t *testing.T, spec authn.LoginFlowSpec) *authn.Orchestrator {
	t.Helper()
	flow, err := authn.CompileLoginFlow(spec)
	if err != nil {
		t.Fatalf("CompileLoginFlow: %v", err)
	}
	o, err := authn.New(authn.Config{LoginFlow: flow, StateRefSigner: newSigner(t)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return o
}

// registrationState is the State a prompt=create request starts from:
// a fresh authentication is required and no subject is carried, unless
// the test seeds one.
func registrationState(subject string) authn.State {
	st := initialState()
	st.Subject = subject
	st.ReauthRequired = true
	st.Registration = true
	return st
}

// TestLoginFlow_RegistrationRunsInPlaceOfPrimary pins that a Registration
// chain runs the Registration step, never Primary, and that the subject it
// binds replaces any subject the chain started with.
func TestLoginFlow_RegistrationRunsInPlaceOfPrimary(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		subject string
	}{
		{name: "no subject carried"},
		{name: "existing subject carried", subject: "user-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var primaryBegins int
			o := registrationOrchestrator(t, authn.LoginFlowSpec{
				Primary:      authn.LoginFlowStep{Kind: "test.password", Authenticator: countingPrimary(&primaryBegins)},
				Registration: authn.LoginFlowStep{Kind: registrationKind, Authenticator: registrationAuth("new-user")},
			})
			st, err := runChain(t, o, registrationState(tc.subject))
			if err != nil {
				t.Fatalf("chain: %v", err)
			}
			if primaryBegins != 0 {
				t.Errorf("Primary Begin ran %d times, want 0", primaryBegins)
			}
			if st.Subject != "new-user" {
				t.Errorf("Subject = %q, want new-user", st.Subject)
			}
			if !slices.Contains(st.CompletedStepKinds, registrationKind) || slices.Contains(st.CompletedStepKinds, "test.password") {
				t.Errorf("CompletedStepKinds = %v, want Registration and not Primary", st.CompletedStepKinds)
			}
		})
	}
}

// TestLoginFlow_RegistrationThenRules pins that the chain after
// Registration is the ordinary one: a rule that keys off the Registration
// kind in CompletedKinds fires for the new subject.
func TestLoginFlow_RegistrationThenRules(t *testing.T) {
	t.Parallel()

	var followUpSubject string
	followUp := successAuth(op.FactorTOTP, op.AAL2, "otp", "new-user")
	prompt := promptForFactor(op.FactorTOTP)
	followUp.beginFn = func(_ context.Context, in op.BeginInput) (interaction.Step, error) {
		followUpSubject = in.Subject
		return interaction.Step{Prompt: &prompt}, nil
	}
	o := registrationOrchestrator(t, authn.LoginFlowSpec{
		Primary:      authn.LoginFlowStep{Kind: "test.password", Authenticator: successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")},
		Registration: authn.LoginFlowStep{Kind: registrationKind, Authenticator: registrationAuth("new-user")},
		Rules: []authn.LoginFlowRule{{
			When: func(lc authn.LoginFlowContext) bool { return slices.Contains(lc.CompletedKinds, registrationKind) },
			Then: authn.LoginFlowStep{Kind: "test.totp", Authenticator: followUp},
		}},
	})
	st, err := runChain(t, o, registrationState(""))
	if err != nil {
		t.Fatalf("chain: %v", err)
	}
	if !slices.Contains(st.CompletedStepKinds, "test.totp") {
		t.Errorf("CompletedStepKinds = %v, want the follow-up rule step", st.CompletedStepKinds)
	}
	if followUpSubject != "new-user" {
		t.Errorf("follow-up Begin subject = %q, want new-user", followUpSubject)
	}
}

// TestLoginFlow_RegistrationGetsNoSubject pins that Registration is not
// handed the subject the chain carried over from the entry session.
func TestLoginFlow_RegistrationGetsNoSubject(t *testing.T) {
	t.Parallel()

	begun, continued := "unset", "unset"
	reg := registrationAuth("new-user")
	prompt := promptForFactor(op.FactorPassword)
	reg.beginFn = func(_ context.Context, in op.BeginInput) (interaction.Step, error) {
		begun = in.Subject
		return interaction.Step{Prompt: &prompt}, nil
	}
	reg.continueFn = func(_ context.Context, in op.ContinueInput) (interaction.Step, error) {
		continued = in.Subject
		return interaction.Step{Result: &interaction.Result{Subject: "new-user", AuthTime: fakeNow()}}, nil
	}
	o := registrationOrchestrator(t, authn.LoginFlowSpec{
		Primary:      authn.LoginFlowStep{Kind: "test.password", Authenticator: successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")},
		Registration: authn.LoginFlowStep{Kind: registrationKind, Authenticator: reg},
	})
	if _, err := runChain(t, o, registrationState("user-1")); err != nil {
		t.Fatalf("chain: %v", err)
	}
	if begun != "" || continued != "" {
		t.Errorf("Begin/Continue subject = %q/%q, want empty", begun, continued)
	}
}

// TestLoginFlow_RegistrationWithoutSubjectEndsAttempt pins that a
// Registration completion naming no subject ends the attempt, including
// when the chain carries an existing subject that would otherwise stand
// in for it.
func TestLoginFlow_RegistrationWithoutSubjectEndsAttempt(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		subject string
		inBegin bool
	}{
		{name: "no subject carried, Continue"},
		{name: "existing subject carried, Continue", subject: "user-1"},
		{name: "no subject carried, Begin", inBegin: true},
		{name: "existing subject carried, Begin", subject: "user-1", inBegin: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var begins int
			reg := registrationAuth("")
			if tc.inBegin {
				reg.beginFn = func(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
					begins++
					return interaction.Step{Result: &interaction.Result{AuthTime: fakeNow()}}, nil
				}
			}
			o := registrationOrchestrator(t, authn.LoginFlowSpec{
				Primary:      authn.LoginFlowStep{Kind: "test.password", Authenticator: successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")},
				Registration: authn.LoginFlowStep{Kind: registrationKind, Authenticator: reg},
			})
			st, err := runChain(t, o, registrationState(tc.subject))
			if !errors.Is(err, authn.ErrInvalidStep) {
				t.Fatalf("err = %v, want ErrInvalidStep", err)
			}
			if len(st.Factors) != 0 {
				t.Errorf("Factors = %v, want none recorded", st.Factors)
			}
			if tc.inBegin && begins != 1 {
				t.Errorf("Begin ran %d times, want 1", begins)
			}
		})
	}
}

// TestLoginFlow_RegistrationNotRequirableByDecider pins that a Decider
// Require naming the Registration kind is refused like an unknown kind,
// both inside the chain and in the session-reuse probe.
func TestLoginFlow_RegistrationNotRequirableByDecider(t *testing.T) {
	t.Parallel()

	var regBegins int
	reg := registrationAuth("new-user")
	prompt := promptForFactor(op.FactorPassword)
	reg.beginFn = func(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
		regBegins++
		return interaction.Step{Prompt: &prompt}, nil
	}
	o := registrationOrchestrator(t, authn.LoginFlowSpec{
		Primary:      authn.LoginFlowStep{Kind: "test.password", Authenticator: successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")},
		Registration: authn.LoginFlowStep{Kind: registrationKind, Authenticator: reg},
		Decider: &stubLoginFlowDecider{decide: func(context.Context, authn.LoginFlowContext) authn.LoginFlowDecision {
			return authn.LoginFlowRequire{Step: authn.LoginFlowStep{Kind: registrationKind}}
		}},
	})
	if _, err := runChain(t, o, initialState()); !errors.Is(err, authn.ErrInvalidStep) {
		t.Fatalf("err = %v, want ErrInvalidStep", err)
	}
	if regBegins != 0 {
		t.Errorf("Registration Begin ran %d times, want 0", regBegins)
	}
	reuse := initialState()
	reuse.Subject = "user-1"
	if !o.LoginFlowRequiresStep(context.Background(), reuse) {
		t.Error("LoginFlowRequiresStep = false for a Require naming Registration, want true (fail closed)")
	}
}

// TestLoginFlow_RegistrationNotReachableByRiskStepUp pins that Registration
// is not indexed by factor type: a risk step-up demanding its factor type
// fails closed instead of running Registration inside a login.
func TestLoginFlow_RegistrationNotReachableByRiskStepUp(t *testing.T) {
	t.Parallel()

	var regBegins int
	reg := registrationAuth("user-1")
	prompt := promptForFactor(op.FactorPassword)
	reg.beginFn = func(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
		regBegins++
		return interaction.Step{Prompt: &prompt}, nil
	}
	o := registrationOrchestrator(t, authn.LoginFlowSpec{
		Primary:      authn.LoginFlowStep{Kind: "test.password", Authenticator: successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")},
		Registration: authn.LoginFlowStep{Kind: registrationKind, Authenticator: reg},
		Risk: &stubRisk{assess: func(context.Context, op.RiskInput) (op.RiskOutcome, error) {
			return op.RiskOutcome{Decision: op.RiskRequire, RequiredFactors: []op.FactorType{registrationFactor}}, nil
		}},
	})
	if _, err := runChain(t, o, initialState()); !errors.Is(err, authn.ErrNoEligibleAuthenticator) {
		t.Fatalf("err = %v, want ErrNoEligibleAuthenticator", err)
	}
	if regBegins != 0 {
		t.Errorf("Registration Begin ran %d times, want 0", regBegins)
	}
}

// TestLoginFlow_RegistrationChainWithoutStep pins that a Registration
// chain on a flow that declares no Registration step fails instead of
// falling back to a login through Primary.
func TestLoginFlow_RegistrationChainWithoutStep(t *testing.T) {
	t.Parallel()

	var primaryBegins int
	o := registrationOrchestrator(t, authn.LoginFlowSpec{
		Primary: authn.LoginFlowStep{Kind: "test.password", Authenticator: countingPrimary(&primaryBegins)},
	})
	if _, err := runChain(t, o, registrationState("")); !errors.Is(err, authn.ErrInvalidStep) {
		t.Fatalf("err = %v, want ErrInvalidStep", err)
	}
	if primaryBegins != 0 {
		t.Errorf("Primary Begin ran %d times, want 0", primaryBegins)
	}
}

// TestLoginFlow_RegistrationCompileRejects pins the compiler's shape
// checks on Registration.
func TestLoginFlow_RegistrationCompileRejects(t *testing.T) {
	t.Parallel()

	primary := authn.LoginFlowStep{Kind: "test.password", Authenticator: successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")}
	reg := registrationAuth("new-user")
	for _, tc := range []struct {
		name string
		spec authn.LoginFlowSpec
	}{
		{name: "one-of", spec: authn.LoginFlowSpec{
			Primary: primary,
			Registration: authn.LoginFlowStep{Kind: registrationKind, OneOf: []authn.LoginFlowStep{
				{Kind: "test.inner", Authenticator: reg},
			}},
		}},
		{name: "captcha", spec: authn.LoginFlowSpec{
			Primary:      primary,
			Registration: authn.LoginFlowStep{Kind: registrationKind, Authenticator: reg, IsCaptcha: true},
		}},
		{name: "nil authenticator", spec: authn.LoginFlowSpec{
			Primary:      primary,
			Registration: authn.LoginFlowStep{Kind: registrationKind},
		}},
		{name: "empty kind", spec: authn.LoginFlowSpec{
			Primary:      primary,
			Registration: authn.LoginFlowStep{Authenticator: reg},
		}},
		{name: "kind shared with Primary", spec: authn.LoginFlowSpec{
			Primary:      primary,
			Registration: authn.LoginFlowStep{Kind: primary.Kind, Authenticator: reg},
		}},
		{name: "rule names the Registration kind", spec: authn.LoginFlowSpec{
			Primary:      primary,
			Registration: authn.LoginFlowStep{Kind: registrationKind, Authenticator: reg},
			Rules: []authn.LoginFlowRule{{
				When: func(authn.LoginFlowContext) bool { return true },
				Then: authn.LoginFlowStep{Kind: registrationKind, Authenticator: successAuth(op.FactorTOTP, op.AAL2, "otp", "user-1")},
			}},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := authn.CompileLoginFlow(tc.spec); err == nil {
				t.Fatal("CompileLoginFlow accepted the flow, want an error")
			}
		})
	}
}
