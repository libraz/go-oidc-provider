package authn_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

// requireFactors builds an assessor that answers every consult with a
// Require decision naming the supplied factor types.
func requireFactors(factors ...op.FactorType) *stubRisk {
	return &stubRisk{
		assess: func(_ context.Context, _ op.RiskInput) (op.RiskOutcome, error) {
			return op.RiskOutcome{
				Decision:        op.RiskRequire,
				RequiredFactors: factors,
				Reason:          "anomaly.test",
			}, nil
		},
	}
}

// completePrimary drives the chain from its initial state through the
// Primary password step and returns the state plus the step the
// orchestrator emitted in answer to the credential.
func completePrimary(t *testing.T, o *authn.Orchestrator) (authn.State, interaction.Step) {
	t.Helper()
	st, step, err := o.Tick(context.Background(), initialState(), authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("primary begin: %v", err)
	}
	if step.Prompt == nil {
		t.Fatalf("primary begin returned no prompt: %+v", step)
	}
	st, step, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"password": "x"}},
		Now:        fakeNow(),
	})
	if err != nil {
		t.Fatalf("primary continue: %v", err)
	}
	return st, step
}

// TestLoginFlowRiskRequiredFactorIsDemanded is the behavioural
// acceptance for the required-factor directive on the LoginFlow surface:
// an assessor that names a factor the declarative rules would never
// reach (every predicate is false) still gets that factor prompted, and
// the chain does not grant until it completes.
func TestLoginFlowRiskRequiredFactorIsDemanded(t *testing.T) {
	t.Parallel()

	pw := successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")
	totp := successAuth(op.FactorTOTP, op.AAL2, "otp", "user-1")
	flow, err := authn.CompileLoginFlow(authn.LoginFlowSpec{
		Primary: authn.LoginFlowStep{Kind: "myorg.password", Authenticator: pw},
		Rules: []authn.LoginFlowRule{
			{
				// Deliberately never fires: the step-up must come
				// from the risk directive, not from the rule list.
				When: func(authn.LoginFlowContext) bool { return false },
				Then: authn.LoginFlowStep{Kind: "myorg.totp", Authenticator: totp},
			},
		},
		Risk: requireFactors(op.FactorTOTP),
	})
	if err != nil {
		t.Fatalf("CompileLoginFlow: %v", err)
	}
	o, err := authn.New(authn.Config{LoginFlow: flow, StateRefSigner: newSigner(t)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	st, step := completePrimary(t, o)
	if step.Result != nil {
		t.Fatalf("chain granted after Primary alone; risk demanded totp, got Result %+v", step.Result)
	}
	if step.Prompt == nil || step.Prompt.Type != "auth.totp" {
		t.Fatalf("expected auth.totp prompt from the risk directive, got %+v", step)
	}

	st, step, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"code": "123"}},
		Now:        fakeNow(),
	})
	if err != nil {
		t.Fatalf("totp continue: %v", err)
	}
	if step.Result == nil {
		t.Fatalf("expected terminal Result once the demanded factor completed, got %+v", step)
	}
	if got := len(st.Factors); got != 2 {
		t.Fatalf("Factors = %d, want 2 (password + the risk-demanded totp)", got)
	}
	if st.Factors[1].Type != op.FactorTOTP {
		t.Errorf("second factor = %q, want %q", st.Factors[1].Type, op.FactorTOTP)
	}
}

// TestLoginFlowRiskRequiredFactorSurvivesDeciderAllow pins the choke
// point: a Decider that answers Allow cannot release the chain while a
// risk-required factor is outstanding. Allow is an embedder policy over
// the rule list, not an override of the assessor's verdict.
func TestLoginFlowRiskRequiredFactorSurvivesDeciderAllow(t *testing.T) {
	t.Parallel()

	pw := successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")
	totp := successAuth(op.FactorTOTP, op.AAL2, "otp", "user-1")
	decider := &stubLoginFlowDecider{
		decide: func(_ context.Context, _ authn.LoginFlowContext) authn.LoginFlowDecision {
			return authn.LoginFlowAllow{}
		},
	}
	flow, err := authn.CompileLoginFlow(authn.LoginFlowSpec{
		Primary: authn.LoginFlowStep{Kind: "myorg.password", Authenticator: pw},
		Rules: []authn.LoginFlowRule{
			{
				When: func(authn.LoginFlowContext) bool { return false },
				Then: authn.LoginFlowStep{Kind: "myorg.totp", Authenticator: totp},
			},
		},
		Decider: decider,
		Risk:    requireFactors(op.FactorTOTP),
	})
	if err != nil {
		t.Fatalf("CompileLoginFlow: %v", err)
	}
	o, err := authn.New(authn.Config{LoginFlow: flow, StateRefSigner: newSigner(t)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, step := completePrimary(t, o)
	if step.Result != nil {
		t.Fatalf("Decider Allow released the chain with a risk step-up outstanding: %+v", step.Result)
	}
	if step.Prompt == nil || step.Prompt.Type != "auth.totp" {
		t.Fatalf("expected auth.totp prompt, got %+v", step)
	}
}

// TestLoginFlowRiskRequiredFactorNotDeclaredFailsClosed asserts the
// fail-closed branch: when no declared Step can produce a demanded
// factor type, the attempt ends in ErrNoEligibleAuthenticator rather
// than granting a session at the assurance the assessor refused. This
// mirrors the legacy chain path, whose risk-filtered candidate set
// returns the same sentinel when it comes back empty.
func TestLoginFlowRiskRequiredFactorNotDeclaredFailsClosed(t *testing.T) {
	t.Parallel()

	pw := successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")
	flow, err := authn.CompileLoginFlow(authn.LoginFlowSpec{
		Primary: authn.LoginFlowStep{Kind: "myorg.password", Authenticator: pw},
		Risk:    requireFactors(op.FactorPasskey),
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
		t.Fatalf("primary begin: %v", err)
	}
	_, step, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"password": "x"}},
		Now:        fakeNow(),
	})
	if !errors.Is(err, authn.ErrNoEligibleAuthenticator) {
		t.Fatalf("err = %v (step %+v), want ErrNoEligibleAuthenticator", err, step)
	}
}

// TestLoginFlowRiskRequiredFactorSatisfiedByPrimary asserts the
// no-op branch: a demand the Primary step itself satisfies inserts
// nothing and the chain grants on the same pass. Without the completed-
// factor check the obligation would re-drive a step that has already
// run.
func TestLoginFlowRiskRequiredFactorSatisfiedByPrimary(t *testing.T) {
	t.Parallel()

	pw := successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")
	flow, err := authn.CompileLoginFlow(authn.LoginFlowSpec{
		Primary: authn.LoginFlowStep{Kind: "myorg.password", Authenticator: pw},
		Risk:    requireFactors(op.FactorPassword),
	})
	if err != nil {
		t.Fatalf("CompileLoginFlow: %v", err)
	}
	o, err := authn.New(authn.Config{LoginFlow: flow, StateRefSigner: newSigner(t)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	st, step := completePrimary(t, o)
	if step.Result == nil {
		t.Fatalf("expected terminal Result, got %+v", step)
	}
	if got := len(st.Factors); got != 1 {
		t.Errorf("Factors = %d, want 1 (Primary already satisfied the demand)", got)
	}
}

// TestLoginFlowRiskRequiredFactorSurvivesPersistence drives the same
// demand across the encoding the HTTP layer applies between requests.
// The risk consult happens on the first tick and the demand is enforced
// on a later one, so an obligation that does not survive the round trip
// would evaporate in production while every in-process test still
// passed.
func TestLoginFlowRiskRequiredFactorSurvivesPersistence(t *testing.T) {
	t.Parallel()

	pw := successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")
	totp := successAuth(op.FactorTOTP, op.AAL2, "otp", "user-1")
	flow, err := authn.CompileLoginFlow(authn.LoginFlowSpec{
		Primary: authn.LoginFlowStep{Kind: "myorg.password", Authenticator: pw},
		Rules: []authn.LoginFlowRule{
			{
				When: func(authn.LoginFlowContext) bool { return false },
				Then: authn.LoginFlowStep{Kind: "myorg.totp", Authenticator: totp},
			},
		},
		Risk: requireFactors(op.FactorTOTP),
	})
	if err != nil {
		t.Fatalf("CompileLoginFlow: %v", err)
	}
	o, err := authn.New(authn.Config{LoginFlow: flow, StateRefSigner: newSigner(t)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// roundTrip mirrors the authorize endpoint's persistence: the whole
	// State is marshalled to JSON between ticks.
	roundTrip := func(st authn.State) authn.State {
		t.Helper()
		blob, merr := json.Marshal(st)
		if merr != nil {
			t.Fatalf("marshal State: %v", merr)
		}
		var out authn.State
		if uerr := json.Unmarshal(blob, &out); uerr != nil {
			t.Fatalf("unmarshal State: %v", uerr)
		}
		return out
	}

	st, step, err := o.Tick(context.Background(), initialState(), authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("primary begin: %v", err)
	}
	st, step, err = o.Tick(context.Background(), roundTrip(st), authn.Input{
		Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"password": "x"}},
		Now:        fakeNow(),
	})
	if err != nil {
		t.Fatalf("primary continue: %v", err)
	}
	if step.Result != nil {
		t.Fatalf("chain granted after Primary; the risk demand did not survive persistence: %+v", step.Result)
	}
	if step.Prompt == nil || step.Prompt.Type != "auth.totp" {
		t.Fatalf("expected auth.totp prompt after the state round trip, got %+v", step)
	}
	_, step, err = o.Tick(context.Background(), roundTrip(st), authn.Input{
		Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"code": "123"}},
		Now:        fakeNow(),
	})
	if err != nil {
		t.Fatalf("totp continue: %v", err)
	}
	if step.Result == nil {
		t.Fatalf("expected terminal Result once the demanded factor completed, got %+v", step)
	}
}

// TestLoginFlowRiskRequireWithoutFactorsDoesNotBlock keeps the
// score-only Require path open: an assessor that raises the risk grade
// without naming a candidate demands no step-up, so a flow with no
// matching rule still grants.
func TestLoginFlowRiskRequireWithoutFactorsDoesNotBlock(t *testing.T) {
	t.Parallel()

	pw := successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")
	flow, err := authn.CompileLoginFlow(authn.LoginFlowSpec{
		Primary: authn.LoginFlowStep{Kind: "myorg.password", Authenticator: pw},
		Risk:    requireFactors(),
	})
	if err != nil {
		t.Fatalf("CompileLoginFlow: %v", err)
	}
	o, err := authn.New(authn.Config{LoginFlow: flow, StateRefSigner: newSigner(t)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	st, step := completePrimary(t, o)
	if step.Result == nil {
		t.Fatalf("expected terminal Result, got %+v", step)
	}
	if st.RiskScoreCached != op.RiskScoreHigh {
		t.Errorf("RiskScoreCached = %v, want RiskScoreHigh (Decision-only fallback)", st.RiskScoreCached)
	}
}
