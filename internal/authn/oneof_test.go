package authn_test

// One-of step case model, pairwise over four factors: position
// (primary / post-primary), enrolled count (0 / 1 / 2+), IfNoneEnrolled
// (Deny / Skip) and factor-choice submission (valid / unoffered / none),
// with primary x Skip excluded because the public compiler rejects it.
// The coverwise tools were not reachable from this environment, so the
// table was built by hand; every remaining value pair appears in at
// least one row.
//
//	#  position  enrolled  policy  submission
//	1  primary   0         Deny    valid
//	2  primary   1         Deny    unoffered
//	3  primary   2+        Deny    none
//	4  post      0         Skip    unoffered
//	5  post      1         Skip    none
//	6  post      2+        Skip    valid
//	7  post      0         Deny    none
//	8  post      1         Deny    valid
//	9  post      2+        Deny    unoffered
//
// At primary no subject is bound, so nothing is probed and both inner
// steps are offered whatever they would report. After primary a
// submission applies only where a choice is offered (2+); with 0 or 1
// enrolled the row pins that no choice prompt appears.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	opaudit "github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/auditevent"
	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

const (
	oneOfPostKind    = "one_of(email_otp,recovery_code,totp)"
	oneOfPrimaryKind = "one_of(myorg.ldap,password)"
)

// probedAuth is a stub authenticator that also reports enrollment.
type probedAuth struct {
	*stubAuthenticator
	enrolled bool
	err      error
	probes   atomic.Int32
}

func (p *probedAuth) Enrolled(context.Context, string) (bool, error) {
	p.probes.Add(1)
	return p.enrolled, p.err
}

func probed(typeID op.FactorType, enrolled bool) *probedAuth {
	return &probedAuth{stubAuthenticator: successAuth(typeID, op.AAL2, "otp", "user-1"), enrolled: enrolled}
}

func oneOfStep(kind string, policy authn.UnenrolledPolicy, steps ...authn.LoginFlowStep) authn.LoginFlowStep {
	return authn.LoginFlowStep{Kind: kind, OneOf: append([]authn.LoginFlowStep{}, steps...), IfNoneEnrolled: policy}
}

func alwaysRule(then authn.LoginFlowStep) authn.LoginFlowRule {
	return authn.LoginFlowRule{When: func(authn.LoginFlowContext) bool { return true }, Then: then}
}

func passwordStep() authn.LoginFlowStep {
	return authn.LoginFlowStep{Kind: "password", Authenticator: successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")}
}

type oneOfFixture struct {
	o       *authn.Orchestrator
	emitter *recordingAuditEmitter
	inner   []*probedAuth
	primary bool
}

// newOneOfFixture builds a flow whose one-of step sits at primary
// (password, myorg.ldap) or in an always-firing rule after a password
// primary (totp, recovery_code, email_otp). The first enrolled inner
// steps report enrolled.
func newOneOfFixture(t *testing.T, primary bool, enrolled int, policy authn.UnenrolledPolicy) *oneOfFixture {
	t.Helper()
	types := []op.FactorType{op.FactorTOTP, op.FactorRecoveryCode, op.FactorEmailOTP}
	if primary {
		types = []op.FactorType{op.FactorPassword, "myorg.ldap"}
	}
	f := &oneOfFixture{emitter: &recordingAuditEmitter{}, primary: primary}
	steps := make([]authn.LoginFlowStep, 0, len(types))
	for i, typ := range types {
		a := probed(typ, i < enrolled)
		f.inner = append(f.inner, a)
		steps = append(steps, authn.LoginFlowStep{Kind: string(typ), Authenticator: a})
	}
	spec := authn.LoginFlowSpec{Primary: oneOfStep(oneOfPrimaryKind, policy, steps...)}
	if !primary {
		spec = authn.LoginFlowSpec{
			Primary: passwordStep(),
			Rules:   []authn.LoginFlowRule{alwaysRule(oneOfStep(oneOfPostKind, policy, steps...))},
		}
	}
	flow, err := authn.CompileLoginFlow(spec)
	if err != nil {
		t.Fatalf("CompileLoginFlow: %v", err)
	}
	f.o, err = authn.New(authn.Config{LoginFlow: flow, AuditEmitter: f.emitter, StateRefSigner: newSigner(t)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return f
}

// start ticks the chain to the point the one-of step runs.
func (f *oneOfFixture) start(t *testing.T) (authn.State, interaction.Step, error) {
	t.Helper()
	st, step, err := f.o.Tick(context.Background(), initialState(), authn.Input{Now: fakeNow()})
	if f.primary {
		return st, step, err
	}
	if err != nil || step.Prompt == nil {
		t.Fatalf("primary Tick = %+v, %v; want the password prompt", step, err)
	}
	return submitValues(f.o, st, step.Prompt, map[string]string{"password": "x"})
}

func submitValues(o *authn.Orchestrator, st authn.State, prompt *interaction.Prompt, values map[string]string) (authn.State, interaction.Step, error) {
	return o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{StateRef: prompt.StateRef, Values: values},
		Now:        fakeNow(),
	})
}

func stepBeginFailedEvents(events []opaudit.Event) []opaudit.Event {
	var out []opaudit.Event
	for _, ev := range events {
		if ev.Name == string(auditevent.AuditLoginStepBeginFailed) {
			out = append(out, ev)
		}
	}
	return out
}

func assertBeginFailed(t *testing.T, events []opaudit.Event, kind, reason string) {
	t.Helper()
	got := stepBeginFailedEvents(events)
	if len(got) != 1 {
		t.Fatalf("login.step_begin_failed events = %+v, want exactly one", got)
	}
	if got[0].Extras["step_kind"] != kind || got[0].Extras["reason"] != reason {
		t.Errorf("event extras = %v, want step_kind=%q reason=%q", got[0].Extras, kind, reason)
	}
}

// assertChoicePrompt checks step is the factor-choice prompt offering
// exactly want, labelled through FactorLabelKey.
func assertChoicePrompt(t *testing.T, st authn.State, step interaction.Step, kind string, want []string) {
	t.Helper()
	if step.Prompt == nil || step.Prompt.Type != interaction.PromptTypeChooseFactor {
		t.Fatalf("step = %+v, want a %s prompt", step, interaction.PromptTypeChooseFactor)
	}
	data, ok := step.Prompt.Data.(interaction.FactorChoicePromptData)
	if !ok {
		t.Fatalf("prompt data = %T, want FactorChoicePromptData", step.Prompt.Data)
	}
	kinds := make([]string, 0, len(data.Options))
	for _, opt := range data.Options {
		kinds = append(kinds, opt.Kind)
		if opt.Label != interaction.FactorLabelKey(opt.Kind) {
			t.Errorf("option %q label = %q, want %q", opt.Kind, opt.Label, interaction.FactorLabelKey(opt.Kind))
		}
	}
	if !slices.Equal(kinds, want) {
		t.Errorf("offered = %v, want %v", kinds, want)
	}
	if st.PendingOneOfKind != kind || !slices.Equal(st.OfferedFactorKinds, want) || st.ActiveStepKind != kind {
		t.Errorf("state pending/offered/active = %q/%v/%q, want %q/%v/%q",
			st.PendingOneOfKind, st.OfferedFactorKinds, st.ActiveStepKind, kind, want, kind)
	}
}

func TestOneOf_Pairwise(t *testing.T) {
	t.Parallel()

	rows := []struct {
		primary  bool
		enrolled int
		policy   authn.UnenrolledPolicy
		submit   string
	}{
		{primary: true, enrolled: 0, policy: authn.UnenrolledDeny, submit: "valid"},
		{primary: true, enrolled: 1, policy: authn.UnenrolledDeny, submit: "unoffered"},
		{primary: true, enrolled: 2, policy: authn.UnenrolledDeny, submit: "none"},
		{primary: false, enrolled: 0, policy: authn.UnenrolledSkip, submit: "unoffered"},
		{primary: false, enrolled: 1, policy: authn.UnenrolledSkip, submit: "none"},
		{primary: false, enrolled: 2, policy: authn.UnenrolledSkip, submit: "valid"},
		{primary: false, enrolled: 0, policy: authn.UnenrolledDeny, submit: "none"},
		{primary: false, enrolled: 1, policy: authn.UnenrolledDeny, submit: "valid"},
		{primary: false, enrolled: 2, policy: authn.UnenrolledDeny, submit: "unoffered"},
	}
	for i, row := range rows {
		t.Run(fmt.Sprintf("row%d", i+1), func(t *testing.T) {
			t.Parallel()

			f := newOneOfFixture(t, row.primary, row.enrolled, row.policy)
			st, step, err := f.start(t)

			kind, offered, unoffered := oneOfPostKind, []string{"totp", "recovery_code"}, "email_otp"
			wantCompleted := []string{"password", "totp", oneOfPostKind}
			if row.primary {
				kind, offered, unoffered = oneOfPrimaryKind, []string{"password", "myorg.ldap"}, "myorg.unknown"
				wantCompleted = []string{"password", oneOfPrimaryKind}
			}

			switch {
			case !row.primary && row.enrolled == 0 && row.policy == authn.UnenrolledDeny:
				if !errors.Is(err, authn.ErrFactorNotEnrolled) {
					t.Fatalf("err = %v, want ErrFactorNotEnrolled", err)
				}
				assertBeginFailed(t, f.emitter.snapshot(), kind, "not_enrolled")
				return
			case !row.primary && row.enrolled == 0:
				if err != nil || step.Result == nil {
					t.Fatalf("Tick = %+v, %v; want the chain to finish past the skipped step", step, err)
				}
				if !slices.Equal(st.SkippedStepKinds, []string{kind}) || slices.Contains(st.CompletedStepKinds, kind) {
					t.Errorf("skipped/completed = %v/%v, want the one-of skipped and not completed", st.SkippedStepKinds, st.CompletedStepKinds)
				}
				assertBeginFailed(t, f.emitter.snapshot(), kind, "not_enrolled_skipped")
				return
			case !row.primary && row.enrolled == 1:
				if err != nil || step.Prompt == nil || step.Prompt.Type == interaction.PromptTypeChooseFactor || st.ActiveStepKind != "totp" {
					t.Fatalf("Tick = %+v (active %q), %v; want the enrolled factor begun directly", step, st.ActiveStepKind, err)
				}
				st, step, err = submitValues(f.o, st, step.Prompt, map[string]string{"code": "123456"})
				if err != nil || step.Result == nil {
					t.Fatalf("factor Tick = %+v, %v; want the terminal Result", step, err)
				}
				if !slices.Equal(st.CompletedStepKinds, wantCompleted) {
					t.Errorf("CompletedStepKinds = %v, want %v", st.CompletedStepKinds, wantCompleted)
				}
				return
			}

			if err != nil {
				t.Fatalf("Tick: %v", err)
			}
			assertChoicePrompt(t, st, step, kind, offered)
			if row.primary {
				for _, a := range f.inner {
					if n := a.probes.Load(); n != 0 {
						t.Errorf("%s probed %d times at primary, want 0", a.Type(), n)
					}
				}
			}

			switch row.submit {
			case "unoffered", "none":
				values := map[string]string{}
				if row.submit == "unoffered" {
					values[interaction.FactorChoiceField] = unoffered
				}
				if _, _, err := submitValues(f.o, st, step.Prompt, values); !errors.Is(err, authn.ErrInvalidStateRef) {
					t.Fatalf("submission %v err = %v, want ErrInvalidStateRef", values, err)
				}
			case "valid":
				st, step, err = submitValues(f.o, st, step.Prompt, map[string]string{interaction.FactorChoiceField: offered[0]})
				if err != nil || step.Prompt == nil || st.ActiveStepKind != offered[0] {
					t.Fatalf("choice Tick = %+v (active %q), %v; want %s begun", step, st.ActiveStepKind, err, offered[0])
				}
				st, step, err = submitValues(f.o, st, step.Prompt, map[string]string{"code": "123456"})
				if err != nil || step.Result == nil {
					t.Fatalf("factor Tick = %+v, %v; want the terminal Result", step, err)
				}
				if !slices.Equal(st.CompletedStepKinds, wantCompleted) {
					t.Errorf("CompletedStepKinds = %v, want %v", st.CompletedStepKinds, wantCompleted)
				}
				if st.PendingOneOfKind != "" || st.OfferedFactorKinds != nil {
					t.Errorf("pending/offered = %q/%v after completion, want cleared", st.PendingOneOfKind, st.OfferedFactorKinds)
				}
			}
		})
	}
}

// TestOneOf_ChoiceSubmissionUnofferedEnrolledLater pins that a choice is
// checked against what was offered, not re-probed: a factor enrolled
// after the prompt went out is still refused.
func TestOneOf_ChoiceSubmissionUnofferedEnrolledLater(t *testing.T) {
	t.Parallel()

	f := newOneOfFixture(t, false, 2, authn.UnenrolledDeny)
	st, step, err := f.start(t)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	f.inner[2].enrolled = true
	if _, _, err := submitValues(f.o, st, step.Prompt, map[string]string{interaction.FactorChoiceField: "email_otp"}); !errors.Is(err, authn.ErrInvalidStateRef) {
		t.Fatalf("err = %v, want ErrInvalidStateRef", err)
	}
	if n := f.inner[2].probes.Load(); n != 1 {
		t.Errorf("email_otp probed %d times, want 1 (no re-probe on submission)", n)
	}
}

// TestOneOf_ChoiceSubmissionValidResumesOnRetry pins that a wrong code on
// the chosen factor re-prompts that factor rather than the choice.
func TestOneOf_ChoiceSubmissionValidResumesOnRetry(t *testing.T) {
	t.Parallel()

	f := newOneOfFixture(t, false, 2, authn.UnenrolledDeny)
	var calls atomic.Int32
	f.inner[0].continueFn = func(_ context.Context, in op.ContinueInput) (interaction.Step, error) {
		if calls.Add(1) == 1 {
			return interaction.Step{}, fmt.Errorf("wrong code: %w", authn.ErrFactorRetry)
		}
		return interaction.Step{Result: &interaction.Result{Subject: in.Subject, AuthTime: fakeNow()}}, nil
	}
	st, step, err := f.start(t)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	st, step, err = submitValues(f.o, st, step.Prompt, map[string]string{interaction.FactorChoiceField: "totp"})
	if err != nil {
		t.Fatalf("choice: %v", err)
	}
	st, step, err = submitValues(f.o, st, step.Prompt, map[string]string{"code": "000000"})
	if err != nil || step.Prompt == nil || step.Prompt.Type != "auth.totp" {
		t.Fatalf("retry Tick = %+v, %v; want the auth.totp prompt again", step, err)
	}
	st, step, err = submitValues(f.o, st, step.Prompt, map[string]string{"code": "123456"})
	if err != nil || step.Result == nil {
		t.Fatalf("second attempt = %+v, %v; want the terminal Result", step, err)
	}
	if want := []string{"password", "totp", oneOfPostKind}; !slices.Equal(st.CompletedStepKinds, want) {
		t.Errorf("CompletedStepKinds = %v, want %v", st.CompletedStepKinds, want)
	}
	if n := f.inner[0].probes.Load(); n != 1 {
		t.Errorf("totp probed %d times, want 1", n)
	}
}

// TestOneOf_ProbeErrorFailsClosed pins that an enrollment probe error
// ends the chain as a fault, not as a user-side abort, and is audited.
func TestOneOf_ProbeErrorFailsClosed(t *testing.T) {
	t.Parallel()

	f := newOneOfFixture(t, false, 2, authn.UnenrolledSkip)
	probeErr := errors.New("store unavailable")
	f.inner[1].err = probeErr
	_, step, err := f.start(t)
	if !errors.Is(err, probeErr) || errors.Is(err, authn.ErrFactorAbort) {
		t.Fatalf("err = %v, want the probe error and no ErrFactorAbort", err)
	}
	if step.Prompt != nil {
		t.Errorf("prompt = %+v after a probe error, want none", step.Prompt)
	}
	assertBeginFailed(t, f.emitter.snapshot(), oneOfPostKind, "error")
}

// TestOneOf_InnerStepRunByDeciderCompletesOneOf pins that every inner
// kind is routable by itself and that completing it completes its
// one-of step too.
func TestOneOf_InnerStepRunByDeciderCompletesOneOf(t *testing.T) {
	t.Parallel()

	totp := probed(op.FactorTOTP, true)
	decider := &stubLoginFlowDecider{decide: func(_ context.Context, lc authn.LoginFlowContext) authn.LoginFlowDecision {
		if slices.Contains(lc.CompletedKinds, "totp") {
			return authn.LoginFlowPass{}
		}
		return authn.LoginFlowRequire{Step: authn.LoginFlowStep{Kind: "totp"}}
	}}
	flow, err := authn.CompileLoginFlow(authn.LoginFlowSpec{
		Primary: passwordStep(),
		Rules: []authn.LoginFlowRule{alwaysRule(oneOfStep("one_of(passkey,totp)", authn.UnenrolledDeny,
			authn.LoginFlowStep{Kind: "totp", Authenticator: totp},
			authn.LoginFlowStep{Kind: "passkey", Authenticator: probed(op.FactorPasskey, true)},
		))},
		Decider: decider,
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
		t.Fatalf("primary: %v", err)
	}
	st, step, err = submitValues(o, st, step.Prompt, map[string]string{"password": "x"})
	if err != nil || step.Prompt == nil || step.Prompt.Type != "auth.totp" {
		t.Fatalf("Tick = %+v, %v; want the decider's totp prompt", step, err)
	}
	st, step, err = submitValues(o, st, step.Prompt, map[string]string{"code": "123456"})
	if err != nil || step.Result == nil {
		t.Fatalf("Tick = %+v, %v; want the terminal Result with the one-of satisfied", step, err)
	}
	if want := []string{"password", "totp", "one_of(passkey,totp)"}; !slices.Equal(st.CompletedStepKinds, want) {
		t.Errorf("CompletedStepKinds = %v, want %v", st.CompletedStepKinds, want)
	}
}

func TestOneOf_CompileChecks(t *testing.T) {
	t.Parallel()

	totp := authn.LoginFlowStep{Kind: "totp", Authenticator: successAuth(op.FactorTOTP, op.AAL2, "otp", "user-1")}
	rec := authn.LoginFlowStep{Kind: "recovery_code", Authenticator: successAuth(op.FactorRecoveryCode, op.AAL2, "otp", "user-1")}
	captcha := authn.LoginFlowStep{Kind: "captcha", Authenticator: successAuth("captcha", op.AAL0, "", ""), IsCaptcha: true}
	innerPassword := authn.LoginFlowStep{Kind: "password", Authenticator: successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")}

	cases := []struct {
		name    string
		primary authn.LoginFlowStep
		rules   []authn.LoginFlowStep
		wantErr string
	}{
		{name: "empty", rules: []authn.LoginFlowStep{oneOfStep("a", authn.UnenrolledDeny)}, wantErr: "OneOf is empty"},
		{name: "nested", rules: []authn.LoginFlowStep{oneOfStep("a", authn.UnenrolledDeny, oneOfStep("b", authn.UnenrolledDeny, totp))}, wantErr: "must not be a one-of step"},
		{name: "captcha inside", rules: []authn.LoginFlowStep{oneOfStep("a", authn.UnenrolledDeny, totp, captcha)}, wantErr: "must not be a captcha step"},
		{name: "inner duplicates primary", rules: []authn.LoginFlowStep{oneOfStep("a", authn.UnenrolledDeny, innerPassword)}, wantErr: "duplicate StepKind"},
		{name: "inner duplicated across rules", rules: []authn.LoginFlowStep{oneOfStep("a", authn.UnenrolledDeny, totp), oneOfStep("b", authn.UnenrolledDeny, totp)}, wantErr: "duplicate StepKind"},
		{name: "inner duplicates a rule", rules: []authn.LoginFlowStep{totp, oneOfStep("a", authn.UnenrolledDeny, rec, totp)}, wantErr: "duplicate StepKind"},
		{name: "one-of kind duplicates a rule", rules: []authn.LoginFlowStep{totp, oneOfStep("totp", authn.UnenrolledDeny, rec)}, wantErr: "duplicate StepKind"},
		{name: "policy above range", rules: []authn.LoginFlowStep{oneOfStep("a", authn.UnenrolledPolicy(2), totp)}, wantErr: "not a declared policy"},
		{name: "policy negative", rules: []authn.LoginFlowStep{oneOfStep("a", authn.UnenrolledPolicy(-1), totp)}, wantErr: "not a declared policy"},
		{name: "both set", rules: []authn.LoginFlowStep{{Kind: "a", Authenticator: totp.Authenticator, OneOf: []authn.LoginFlowStep{rec}}}, wantErr: "sets both"},
		{name: "nil inner", rules: []authn.LoginFlowStep{oneOfStep("a", authn.UnenrolledDeny, authn.LoginFlowStep{Kind: "x"})}, wantErr: "is nil"},
		{name: "single step", rules: []authn.LoginFlowStep{oneOfStep("a", authn.UnenrolledSkip, totp)}},
		{name: "at primary", primary: oneOfStep("p", authn.UnenrolledDeny, innerPassword), rules: []authn.LoginFlowStep{totp}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			spec := authn.LoginFlowSpec{Primary: tc.primary}
			if tc.primary.Kind == "" {
				spec.Primary = passwordStep()
			}
			for _, r := range tc.rules {
				spec.Rules = append(spec.Rules, alwaysRule(r))
			}
			_, err := authn.CompileLoginFlow(spec)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("CompileLoginFlow: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}
