package authn_test

import (
	"context"
	"slices"
	"sync"
	"testing"

	opaudit "github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/auditevent"
	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

// reuseFixture is a LoginFlow whose single rule always fires and
// records what every consumer of the attempt's authentication saw.
type reuseFixture struct {
	o       *authn.Orchestrator
	emitter *recordingAuditEmitter

	mu        sync.Mutex
	ruleKinds [][]string
	riskAMR   [][]string
}

func newReuseFixture(t *testing.T, second *stubAuthenticator) *reuseFixture {
	t.Helper()
	f := &reuseFixture{emitter: &recordingAuditEmitter{}}
	flow, err := authn.CompileLoginFlow(authn.LoginFlowSpec{
		Primary: authn.LoginFlowStep{Kind: "myorg.password", Authenticator: successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")},
		Rules: []authn.LoginFlowRule{{
			When: func(lc authn.LoginFlowContext) bool {
				f.mu.Lock()
				f.ruleKinds = append(f.ruleKinds, slices.Clone(lc.CompletedKinds))
				f.mu.Unlock()
				return true
			},
			Then: authn.LoginFlowStep{Kind: "myorg.totp", Authenticator: second},
		}},
		Risk: &stubRisk{assess: func(_ context.Context, in op.RiskInput) (op.RiskOutcome, error) {
			f.mu.Lock()
			f.riskAMR = append(f.riskAMR, slices.Clone(in.AMRSoFar))
			f.mu.Unlock()
			return op.RiskOutcome{Decision: op.RiskAllow, Score: op.RiskScoreLow}, nil
		}},
	})
	if err != nil {
		t.Fatalf("CompileLoginFlow: %v", err)
	}
	f.o, err = authn.New(authn.Config{LoginFlow: flow, AuditEmitter: f.emitter, StateRefSigner: newSigner(t)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return f
}

// reusedSessionState is a chain started from a live password session
// that may serve the request.
func reusedSessionState() authn.State {
	st := initialState()
	st.Subject = "user-1"
	st.EntryAuthn = &authn.EntryAuthn{Subject: "user-1", ACR: op.AAL1.ACRURI(), AMR: []string{"pwd"}}
	return st
}

// TestAuthContextSessionReuseStepUp pins that a step-up run on top of
// a reused session is described as an additional factor over that
// session by every consumer: the rule predicates (on the pre-mint reuse
// check and inside the chain) see Primary completed, the risk assessor
// sees the session's amr, the audit stream files the step-up under
// mfa.*, and the auth context the chain completes with carries the union
// of methods at the higher level.
func TestAuthContextSessionReuseStepUp(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		f := newReuseFixture(t, successAuth(op.FactorTOTP, op.AAL2, "otp", "user-1"))
		if !f.o.LoginFlowRequiresStep(context.Background(), reusedSessionState()) {
			t.Fatal("LoginFlowRequiresStep = false, want true for an always-firing rule")
		}
		st, step, err := f.o.Tick(context.Background(), reusedSessionState(), authn.Input{Now: fakeNow()})
		if err != nil {
			t.Fatalf("first Tick: %v", err)
		}
		if step.Prompt == nil || step.Prompt.Type != "auth.totp" {
			t.Fatalf("first prompt = %+v, want the rule's step with Primary inherited", step.Prompt)
		}
		st, _, err = f.o.Tick(context.Background(), st, authn.Input{
			Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"code": "000000"}},
			Now:        fakeNow(),
		})
		if err != nil {
			t.Fatalf("step-up Tick: %v", err)
		}

		for i, kinds := range f.ruleKinds {
			if !slices.Equal(kinds, []string{"myorg.password"}) {
				t.Errorf("rule evaluation %d saw CompletedKinds = %v, want [myorg.password]", i, kinds)
			}
		}
		if len(f.riskAMR) != 1 || !slices.Equal(f.riskAMR[0], []string{"pwd"}) {
			t.Errorf("risk AMRSoFar = %v, want one consult with [pwd]", f.riskAMR)
		}
		assertAuditEvents(t, f.emitter.snapshot(), []wantAuditEvent{
			{name: auditevent.AuditMFASuccess, level: opaudit.LevelInfo, actor: "user-1", factor: op.FactorTOTP},
		})

		ac := f.o.AuthContext(st)
		if !ac.Inherited || ac.Methods != 2 {
			t.Errorf("Inherited/Methods = %v/%d, want true/2", ac.Inherited, ac.Methods)
		}
		if want := []string{"myorg.password", "myorg.totp"}; !slices.Equal(ac.CompletedKinds, want) {
			t.Errorf("CompletedKinds = %v, want %v", ac.CompletedKinds, want)
		}
		if want := []string{"mfa", "otp", "pwd"}; !slices.Equal(ac.AMR, want) {
			t.Errorf("AMR = %v, want %v", ac.AMR, want)
		}
		if ac.ACR != op.AAL2.ACRURI() {
			t.Errorf("ACR = %q, want %q", ac.ACR, op.AAL2.ACRURI())
		}
	})

	t.Run("failure", func(t *testing.T) {
		t.Parallel()

		f := newReuseFixture(t, failingAuthenticator(op.FactorTOTP, op.AAL2, "otp"))
		st, step, err := f.o.Tick(context.Background(), reusedSessionState(), authn.Input{Now: fakeNow()})
		if err != nil {
			t.Fatalf("first Tick: %v", err)
		}
		if _, _, err = f.o.Tick(context.Background(), st, authn.Input{
			Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"code": "000000"}},
			Now:        fakeNow(),
		}); err != nil {
			t.Fatalf("step-up Tick: %v", err)
		}
		assertAuditEvents(t, f.emitter.snapshot(), []wantAuditEvent{
			{name: auditevent.AuditMFAFailed, level: opaudit.LevelWarn, actor: "user-1", factor: op.FactorTOTP},
		})
	})
}

// TestAuthContextEntrySessionDoesNotStand pins the two cases where the
// entry session's authentication must not substitute for Primary: a
// request that demanded a fresh authentication, and a chain whose
// subject is not the session's.
func TestAuthContextEntrySessionDoesNotStand(t *testing.T) {
	t.Parallel()

	reauth := reusedSessionState()
	reauth.ReauthRequired = true
	otherSubject := reusedSessionState()
	otherSubject.Subject = "user-2"

	for name, st := range map[string]authn.State{"reauth-required": reauth, "other-subject": otherSubject} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f := newReuseFixture(t, successAuth(op.FactorTOTP, op.AAL2, "otp", "user-1"))
			ac := f.o.AuthContext(st)
			if ac.Inherited || ac.Methods != 0 || len(ac.CompletedKinds) != 0 || len(ac.AMR) != 0 || ac.ACR != "" {
				t.Errorf("AuthContext = %+v, want nothing inherited", ac)
			}
		})
	}

	f := newReuseFixture(t, successAuth(op.FactorTOTP, op.AAL2, "otp", "user-1"))
	_, step, err := f.o.Tick(context.Background(), reauth, authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if step.Prompt == nil || step.Prompt.Type != "auth.password" {
		t.Fatalf("reauth prompt = %+v, want Primary's", step.Prompt)
	}
}
