package authn_test

import (
	"context"
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

// runChain drives every prompt of the chain with an empty submission
// and returns the first error, or nil once a terminal Result lands.
func runChain(t *testing.T, o *authn.Orchestrator, st authn.State) (authn.State, error) {
	t.Helper()
	st, step, err := o.Tick(context.Background(), st, authn.Input{Now: fakeNow()})
	for err == nil && step.Prompt != nil {
		st, step, err = o.Tick(context.Background(), st, authn.Input{
			Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{}},
			Now:        fakeNow(),
		})
	}
	return st, err
}

// TestTick_LaterFactorCannotRebindSubject pins that once a factor in the
// chain has bound the subject, a later factor answering for a different
// subject ends the chain instead of silently switching accounts — the
// session would otherwise carry the first factor's assurance under the
// second subject.
//
// Tracks: CVE-2026-100679 (stoatchat — the MFA ticket was not bound to
// the user who completed the first factor, so it could finish another
// user's login).
func TestTick_LaterFactorCannotRebindSubject(t *testing.T) {
	t.Parallel()

	flow, err := authn.CompileLoginFlow(authn.LoginFlowSpec{
		Primary: authn.LoginFlowStep{Kind: "test.password", Authenticator: successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")},
		Rules: []authn.LoginFlowRule{{
			When: func(authn.LoginFlowContext) bool { return true },
			Then: authn.LoginFlowStep{Kind: "test.totp", Authenticator: successAuth(op.FactorTOTP, op.AAL2, "otp", "user-2")},
		}},
	})
	if err != nil {
		t.Fatalf("CompileLoginFlow: %v", err)
	}
	o, err := authn.New(authn.Config{LoginFlow: flow, StateRefSigner: newSigner(t)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	st, err := runChain(t, o, initialState())
	if !errors.Is(err, authn.ErrSubjectMismatch) {
		t.Fatalf("err = %v, want ErrSubjectMismatch", err)
	}
	if st.Subject != "user-1" {
		t.Errorf("Subject = %q, want the first factor's user-1", st.Subject)
	}
}

// TestTick_FirstFactorMayReplaceInheritedSubject is the control: a
// subject inherited from the entry session is not bound by this chain,
// so the first factor may authenticate a different account.
func TestTick_FirstFactorMayReplaceInheritedSubject(t *testing.T) {
	t.Parallel()

	o, err := authn.New(authn.Config{
		LoginFlow:      chainFlow(t, successAuth(op.FactorPassword, op.AAL1, "pwd", "user-2")),
		StateRefSigner: newSigner(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	st := initialState()
	st.Subject = "user-1"
	st.ReauthRequired = true
	st, err = runChain(t, o, st)
	if err != nil {
		t.Fatalf("chain: %v", err)
	}
	if st.Subject != "user-2" {
		t.Errorf("Subject = %q, want user-2", st.Subject)
	}
}

// TestTick_RuleStepCannotRebindInheritedSubject pins that a chain
// standing on the entry session's authentication is bound to that
// session's subject: a rule step answering for another subject ends the
// chain, as it would after a factor run in the same attempt.
func TestTick_RuleStepCannotRebindInheritedSubject(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		subject string
		wantErr error
	}{
		{name: "other subject", subject: "user-2", wantErr: authn.ErrSubjectMismatch},
		{name: "session subject", subject: "user-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			flow, err := authn.CompileLoginFlow(authn.LoginFlowSpec{
				Primary: authn.LoginFlowStep{Kind: "test.password", Authenticator: successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")},
				Rules: []authn.LoginFlowRule{{
					When: func(authn.LoginFlowContext) bool { return true },
					Then: authn.LoginFlowStep{Kind: "test.external", Authenticator: successAuth(op.FactorType("test.external"), op.AAL2, "", tc.subject)},
				}},
			})
			if err != nil {
				t.Fatalf("CompileLoginFlow: %v", err)
			}
			o, err := authn.New(authn.Config{LoginFlow: flow, StateRefSigner: newSigner(t)})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			st := initialState()
			st.Subject = "user-1"
			st.EntryAuthn = &authn.EntryAuthn{Subject: "user-1", AMR: []string{"pwd"}}
			st, err = runChain(t, o, st)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if st.Subject != "user-1" {
				t.Errorf("Subject = %q, want the session's user-1", st.Subject)
			}
		})
	}
}
