package authn_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

// capturingDecider records the last LoginFlowContext it was handed and
// always defers to the rule list, so a test can inspect exactly what a
// rule predicate would see without changing the chain's outcome.
type capturingDecider struct {
	seen  authn.LoginFlowContext
	calls int
}

func (d *capturingDecider) Decide(_ context.Context, lc authn.LoginFlowContext) authn.LoginFlowDecision { //nolint:ireturn,nolintlint // sealed-sum LoginFlowDecision is the contract.
	d.seen = lc
	d.calls++
	return authn.LoginFlowPass{}
}

// driveToDeciderConsult runs Primary to completion so the decider is
// consulted on the post-Primary pass, and returns the resulting state.
func driveToDeciderConsult(t *testing.T, o *authn.Orchestrator, st authn.State) authn.State {
	t.Helper()
	st, step, err := o.Tick(context.Background(), st, authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("primary begin: %v", err)
	}
	st, _, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"password": "x"}},
		Now:        fakeNow(),
	})
	if err != nil {
		t.Fatalf("primary continue: %v", err)
	}
	return st
}

// newCapturingFlow builds a single-step flow whose decider records the
// context, and the orchestrator that drives it.
func newCapturingFlow(t *testing.T) (*authn.Orchestrator, *capturingDecider) {
	t.Helper()
	pw := successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")
	decider := &capturingDecider{}
	flow, err := authn.CompileLoginFlow(authn.LoginFlowSpec{
		Primary: authn.LoginFlowStep{Kind: "myorg.password", Authenticator: pw},
		Decider: decider,
	})
	if err != nil {
		t.Fatalf("CompileLoginFlow: %v", err)
	}
	o, err := authn.New(authn.Config{LoginFlow: flow, StateRefSigner: newSigner(t)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return o, decider
}

// TestLoginContext_UnresolvableRemoteIPIsEmptyNotPlaceholder pins the
// contract [op.ClientHints.RemoteIP] documents: an address the HTTP
// layer could not resolve reaches a rule predicate as the empty string.
//
// netip.Addr renders its zero value as the literal "invalid IP", which
// is not an address but reads like one: a predicate comparing against an
// allowlist sees a non-empty value and takes the "we know where this
// request came from" branch, and the same string lands in the audit
// trail as though it were observed.
func TestLoginContext_UnresolvableRemoteIPIsEmptyNotPlaceholder(t *testing.T) {
	t.Parallel()

	o, decider := newCapturingFlow(t)
	st := initialState()
	st.RemoteIP = netip.Addr{} // the HTTP layer resolved no trusted address

	driveToDeciderConsult(t, o, st)

	if decider.calls == 0 {
		t.Fatal("decider was never consulted; the test drove the wrong path")
	}
	if got := decider.seen.RemoteIP; got != "" {
		t.Errorf("RemoteIP = %q, want %q — a predicate cannot tell a placeholder from an observed address", got, "")
	}
}

// TestLoginContext_ResolvedRemoteIPReachesPredicate is the control for
// the test above: the guard must not blank an address that was resolved.
func TestLoginContext_ResolvedRemoteIPReachesPredicate(t *testing.T) {
	t.Parallel()

	o, decider := newCapturingFlow(t)
	st := initialState() // seeded with 203.0.113.10

	driveToDeciderConsult(t, o, st)

	if got := decider.seen.RemoteIP; got != "203.0.113.10" {
		t.Errorf("RemoteIP = %q, want 203.0.113.10", got)
	}
}

// TestLoginContext_AcceptLanguageReachesPredicate pins the field the
// orchestrator face previously left empty while the ACR-resolver face
// populated it. A predicate cannot tell which face built the context it
// is reading, so a value present on one and absent on the other is a
// policy that changes behaviour depending on where in the chain it runs.
func TestLoginContext_AcceptLanguageReachesPredicate(t *testing.T) {
	t.Parallel()

	o, decider := newCapturingFlow(t)
	st := initialState()
	st.AcceptLanguage = "ja,en;q=0.9"

	driveToDeciderConsult(t, o, st)

	if got := decider.seen.AcceptLanguage; got != "ja,en;q=0.9" {
		t.Errorf("AcceptLanguage = %q, want %q", got, "ja,en;q=0.9")
	}
}

// TestLoginFlowRuleNewDevice_AssessorSignalDemandsStepUp is the
// behavioural acceptance for the device-trust seam: an assessor that
// reports an unfamiliar device causes a RuleNewDevice-shaped rule to
// actually run its step, not merely to set a field.
//
// The path is worth pinning because the two ends are far apart: the risk
// consult happens once per chain, before Primary runs, while the rule
// predicate is evaluated after Primary completes. The signal therefore
// reaches the predicate only through the cached copy on State, and a
// break anywhere along it produces a silently dormant step-up rather
// than an error.
func TestLoginFlowRuleNewDevice_AssessorSignalDemandsStepUp(t *testing.T) {
	t.Parallel()

	pw := successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")
	totp := successAuth(op.FactorTOTP, op.AAL2, "otp", "user-1")
	assessor := &stubRisk{
		assess: func(_ context.Context, _ op.RiskInput) (op.RiskOutcome, error) {
			// Allow, not Require: the assessor reports the device is
			// unfamiliar and leaves the policy to the flow's rules.
			return op.RiskOutcome{Decision: op.RiskAllow, NewDevice: true}, nil
		},
	}
	flow, err := authn.CompileLoginFlow(authn.LoginFlowSpec{
		Primary: authn.LoginFlowStep{Kind: "myorg.password", Authenticator: pw},
		Rules: []authn.LoginFlowRule{
			{
				// The projection of op.RuleNewDevice.
				When: func(lc authn.LoginFlowContext) bool { return lc.NewDevice },
				Then: authn.LoginFlowStep{Kind: "myorg.totp", Authenticator: totp},
			},
		},
		Risk: assessor,
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
	if err != nil {
		t.Fatalf("primary continue: %v", err)
	}
	if step.Result != nil {
		t.Fatalf("chain granted after Primary; the new-device rule never fired: %+v", step.Result)
	}
	if step.Prompt == nil || step.Prompt.Type != "auth.totp" {
		t.Fatalf("expected auth.totp prompt from the new-device rule, got %+v", step)
	}
}

// TestLoginFlowRuleNewDevice_DormantWithoutAssessor pins the documented
// dormancy: with no assessor wired there is no device signal, so the
// same flow grants after Primary. This is the property the godoc
// promises, and it is what makes the rule safe to declare before the
// signal source exists.
func TestLoginFlowRuleNewDevice_DormantWithoutAssessor(t *testing.T) {
	t.Parallel()

	pw := successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")
	totp := successAuth(op.FactorTOTP, op.AAL2, "otp", "user-1")
	flow, err := authn.CompileLoginFlow(authn.LoginFlowSpec{
		Primary: authn.LoginFlowStep{Kind: "myorg.password", Authenticator: pw},
		Rules: []authn.LoginFlowRule{
			{
				When: func(lc authn.LoginFlowContext) bool { return lc.NewDevice },
				Then: authn.LoginFlowStep{Kind: "myorg.totp", Authenticator: totp},
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
		t.Fatalf("primary begin: %v", err)
	}
	_, step, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"password": "x"}},
		Now:        fakeNow(),
	})
	if err != nil {
		t.Fatalf("primary continue: %v", err)
	}
	if step.Result == nil {
		t.Fatalf("expected terminal Result with no assessor wired, got %+v", step)
	}
}
