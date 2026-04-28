package authn_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

// stubLoginFlowDecider is a hand-rolled authn.LoginFlowDecider whose
// Decide returns a caller-supplied closure. The struct is used by every
// LoginFlow integration test to exercise a specific decision branch.
type stubLoginFlowDecider struct {
	decide func(ctx context.Context, lc authn.LoginFlowContext) authn.LoginFlowDecision
	calls  atomic.Int32
}

func (d *stubLoginFlowDecider) Decide(ctx context.Context, lc authn.LoginFlowContext) authn.LoginFlowDecision { //nolint:ireturn // sealed-sum LoginFlowDecision is the contract.
	d.calls.Add(1)
	return d.decide(ctx, lc)
}

// successAuth wraps a stubAuthenticator and returns a Result on first
// Continue. The fixture matches the existing buildSuccessAuthenticator
// pattern but lets the test pin the exact subject so the LoginFlow
// dedup tests can assert that Subject survived across multiple steps.
func successAuth(typeID op.FactorType, aal op.AAL, amr, subject string) *stubAuthenticator {
	prompt := promptForFactor(typeID)
	return &stubAuthenticator{
		typeID:  typeID,
		aal:     aal,
		amr:     amr,
		prompts: []string{prompt.Type},
		beginFn: func(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
			return interaction.Step{Prompt: &prompt}, nil
		},
		continueFn: func(_ context.Context, _ op.ContinueInput) (interaction.Step, error) {
			return interaction.Step{Result: &interaction.Result{Subject: subject, AuthTime: fakeNow()}}, nil
		},
	}
}

// 1. Primary-only LoginFlow grants after Primary completes.
func TestLoginFlowPrimaryOnly(t *testing.T) {
	t.Parallel()

	pw := successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")
	flow, err := authn.CompileLoginFlow(authn.LoginFlowSpec{
		Primary: authn.LoginFlowStep{Kind: "myorg.password", Authenticator: pw},
	})
	if err != nil {
		t.Fatalf("CompileLoginFlow: %v", err)
	}
	o, err := authn.New(authn.Config{
		LoginFlow:      flow,
		StateRefSigner: newSigner(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	st, step, err := o.Tick(context.Background(), initialState(), authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("first Tick: %v", err)
	}
	if step.Prompt == nil || step.Prompt.Type != "auth.password" {
		t.Fatalf("expected auth.password prompt, got %+v", step)
	}

	st, step, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"password": "x"}},
		Now:        fakeNow(),
	})
	if err != nil {
		t.Fatalf("second Tick: %v", err)
	}
	if step.Result == nil {
		t.Fatalf("expected terminal Result, got %+v", step)
	}
	if step.Result.Subject != "user-1" {
		t.Errorf("Result.Subject = %q, want user-1", step.Result.Subject)
	}
	if got := st.CompletedStepKinds; len(got) != 1 || got[0] != "myorg.password" {
		t.Errorf("CompletedStepKinds = %v, want [myorg.password]", got)
	}
}

// 2. Decider Allow short-circuits the rule list.
func TestLoginFlowDeciderAllow(t *testing.T) {
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
				When: func(authn.LoginFlowContext) bool { return true },
				Then: authn.LoginFlowStep{Kind: "myorg.totp", Authenticator: totp},
			},
		},
		Decider: decider,
	})
	if err != nil {
		t.Fatalf("CompileLoginFlow: %v", err)
	}
	o, _ := authn.New(authn.Config{LoginFlow: flow, StateRefSigner: newSigner(t)})

	// Prompt for password.
	st, step, err := o.Tick(context.Background(), initialState(), authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("first Tick: %v", err)
	}
	_, step, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"password": "x"}},
		Now:        fakeNow(),
	})
	if err != nil {
		t.Fatalf("second Tick: %v", err)
	}
	if step.Result == nil {
		t.Fatalf("Decider Allow should grant immediately, got %+v", step)
	}
}

// 3. Decider Deny surfaces ErrRiskDenied.
func TestLoginFlowDeciderDeny(t *testing.T) {
	t.Parallel()

	pw := successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")
	decider := &stubLoginFlowDecider{
		decide: func(_ context.Context, _ authn.LoginFlowContext) authn.LoginFlowDecision {
			return authn.LoginFlowDeny{Reason: "policy.geo"}
		},
	}
	flow, _ := authn.CompileLoginFlow(authn.LoginFlowSpec{
		Primary: authn.LoginFlowStep{Kind: "myorg.password", Authenticator: pw},
		Decider: decider,
	})
	o, _ := authn.New(authn.Config{LoginFlow: flow, StateRefSigner: newSigner(t)})

	// Drive to the password prompt and submit.
	st, step, err := o.Tick(context.Background(), initialState(), authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("first Tick: %v", err)
	}
	_, _, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"password": "x"}},
		Now:        fakeNow(),
	})
	if !errors.Is(err, authn.ErrRiskDenied) {
		t.Fatalf("err = %v, want ErrRiskDenied", err)
	}
}

// 4. Decider Require runs the named step.
func TestLoginFlowDeciderRequire(t *testing.T) {
	t.Parallel()

	pw := successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")
	totp := successAuth(op.FactorTOTP, op.AAL2, "otp", "user-1")
	decider := &stubLoginFlowDecider{
		decide: func(_ context.Context, lc authn.LoginFlowContext) authn.LoginFlowDecision {
			// Only require TOTP after password completes.
			for _, k := range lc.CompletedKinds {
				if k == "myorg.totp" {
					return authn.LoginFlowAllow{}
				}
			}
			return authn.LoginFlowRequire{Step: authn.LoginFlowStep{Kind: "myorg.totp"}}
		},
	}
	flow, _ := authn.CompileLoginFlow(authn.LoginFlowSpec{
		Primary: authn.LoginFlowStep{Kind: "myorg.password", Authenticator: pw},
		Rules: []authn.LoginFlowRule{
			{
				When: func(authn.LoginFlowContext) bool { return false },
				Then: authn.LoginFlowStep{Kind: "myorg.totp", Authenticator: totp},
			},
		},
		Decider: decider,
	})
	o, _ := authn.New(authn.Config{LoginFlow: flow, StateRefSigner: newSigner(t)})

	st, step, err := o.Tick(context.Background(), initialState(), authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("primary begin: %v", err)
	}
	st, step, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"password": "x"}},
		Now:        fakeNow(),
	})
	if err != nil {
		t.Fatalf("primary continue: %v", err)
	}
	if step.Prompt == nil || step.Prompt.Type != "auth.totp" {
		t.Fatalf("expected auth.totp prompt after Require, got %+v", step)
	}
	st, step, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"code": "123456"}},
		Now:        fakeNow(),
	})
	if err != nil {
		t.Fatalf("totp continue: %v", err)
	}
	if step.Result == nil {
		t.Fatalf("expected terminal Result after TOTP, got %+v", step)
	}
	wantKinds := []string{"myorg.password", "myorg.totp"}
	if len(st.CompletedStepKinds) != 2 || st.CompletedStepKinds[0] != wantKinds[0] || st.CompletedStepKinds[1] != wantKinds[1] {
		t.Errorf("CompletedStepKinds = %v, want %v", st.CompletedStepKinds, wantKinds)
	}
}

// 5. Decider Require for an unknown StepKind surfaces ErrInvalidStep.
func TestLoginFlowDeciderRequireUnknownKind(t *testing.T) {
	t.Parallel()

	pw := successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")
	decider := &stubLoginFlowDecider{
		decide: func(_ context.Context, _ authn.LoginFlowContext) authn.LoginFlowDecision {
			return authn.LoginFlowRequire{Step: authn.LoginFlowStep{Kind: "myorg.unknown"}}
		},
	}
	flow, _ := authn.CompileLoginFlow(authn.LoginFlowSpec{
		Primary: authn.LoginFlowStep{Kind: "myorg.password", Authenticator: pw},
		Decider: decider,
	})
	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	o, _ := authn.New(authn.Config{LoginFlow: flow, StateRefSigner: newSigner(t), Logger: logger})

	st, step, err := o.Tick(context.Background(), initialState(), authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("primary begin: %v", err)
	}
	_, _, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"password": "x"}},
		Now:        fakeNow(),
	})
	if !errors.Is(err, authn.ErrInvalidStep) {
		t.Fatalf("err = %v, want ErrInvalidStep", err)
	}
	if !strings.Contains(logBuf.String(), "unknown StepKind") {
		t.Errorf("expected unknown-kind log entry, got %q", logBuf.String())
	}
}

// 6. Rule matching — no Decider; the first matching rule fires.
func TestLoginFlowRuleMatch(t *testing.T) {
	t.Parallel()

	pw := successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")
	totp := successAuth(op.FactorTOTP, op.AAL2, "otp", "user-1")
	flow, _ := authn.CompileLoginFlow(authn.LoginFlowSpec{
		Primary: authn.LoginFlowStep{Kind: "myorg.password", Authenticator: pw},
		Rules: []authn.LoginFlowRule{
			{
				When: func(_ authn.LoginFlowContext) bool { return true }, // always
				Then: authn.LoginFlowStep{Kind: "myorg.totp", Authenticator: totp},
			},
		},
	})
	o, _ := authn.New(authn.Config{LoginFlow: flow, StateRefSigner: newSigner(t)})

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
	if step.Prompt == nil || step.Prompt.Type != "auth.totp" {
		t.Fatalf("expected auth.totp prompt from rule, got %+v", step)
	}
}

// 7. Rule.When panic is recovered and treated as no-match.
func TestLoginFlowRulePanicRecovery(t *testing.T) {
	t.Parallel()

	pw := successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")
	totp := successAuth(op.FactorTOTP, op.AAL2, "otp", "user-1")
	flow, _ := authn.CompileLoginFlow(authn.LoginFlowSpec{
		Primary: authn.LoginFlowStep{Kind: "myorg.password", Authenticator: pw},
		Rules: []authn.LoginFlowRule{
			{
				When: func(authn.LoginFlowContext) bool { panic("oops") },
				Then: authn.LoginFlowStep{Kind: "myorg.totp", Authenticator: totp},
			},
		},
	})
	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	o, _ := authn.New(authn.Config{LoginFlow: flow, StateRefSigner: newSigner(t), Logger: logger})

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
	// Predicate panicked → no rule matched → grant.
	if step.Result == nil {
		t.Fatalf("expected terminal Result after panic recovery, got %+v", step)
	}
	if !strings.Contains(logBuf.String(), "rule predicate panicked") {
		t.Errorf("expected predicate-panic log, got %q", logBuf.String())
	}
}

// 8. Decider panic falls through to Pass (rules drive the chain).
func TestLoginFlowDeciderPanicRecovery(t *testing.T) {
	t.Parallel()

	pw := successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")
	decider := &stubLoginFlowDecider{
		decide: func(_ context.Context, _ authn.LoginFlowContext) authn.LoginFlowDecision {
			panic("decider exploded")
		},
	}
	flow, _ := authn.CompileLoginFlow(authn.LoginFlowSpec{
		Primary: authn.LoginFlowStep{Kind: "myorg.password", Authenticator: pw},
		Decider: decider,
	})
	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	o, _ := authn.New(authn.Config{LoginFlow: flow, StateRefSigner: newSigner(t), Logger: logger})

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
	// Decider panicked → Pass → no rules → grant.
	if step.Result == nil {
		t.Fatalf("expected terminal Result after decider panic, got %+v", step)
	}
	if !strings.Contains(logBuf.String(), "decider panicked") {
		t.Errorf("expected decider-panic log, got %q", logBuf.String())
	}
}

// 9. Risk.Assess is invoked at most once per chain regardless of how
// many ticks run.
func TestLoginFlowRiskCalledOnce(t *testing.T) {
	t.Parallel()

	pw := successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")
	totp := successAuth(op.FactorTOTP, op.AAL2, "otp", "user-1")
	var calls atomic.Int32
	risk := &stubRisk{
		assess: func(_ context.Context, _ op.RiskInput) (op.RiskOutcome, error) {
			calls.Add(1)
			return op.RiskOutcome{Decision: op.RiskRequire, RequiredFactors: []op.FactorType{op.FactorTOTP}}, nil
		},
	}
	flow, _ := authn.CompileLoginFlow(authn.LoginFlowSpec{
		Primary: authn.LoginFlowStep{Kind: "myorg.password", Authenticator: pw},
		Rules: []authn.LoginFlowRule{
			{
				When: func(lc authn.LoginFlowContext) bool { return lc.RiskScore >= 3 },
				Then: authn.LoginFlowStep{Kind: "myorg.totp", Authenticator: totp},
			},
		},
		Risk: risk,
	})
	o, _ := authn.New(authn.Config{LoginFlow: flow, StateRefSigner: newSigner(t)})

	// Drive primary, then totp.
	st, step, err := o.Tick(context.Background(), initialState(), authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("primary begin: %v", err)
	}
	st, step, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"password": "x"}},
		Now:        fakeNow(),
	})
	if err != nil {
		t.Fatalf("primary continue: %v", err)
	}
	if step.Prompt == nil || step.Prompt.Type != "auth.totp" {
		t.Fatalf("expected auth.totp prompt (rule fired on RiskScore>=3), got %+v", step)
	}
	_, _, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"code": "123"}},
		Now:        fakeNow(),
	})
	if err != nil {
		t.Fatalf("totp continue: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("Risk.Assess invoked %d times across the chain, want exactly 1 (budget invariant)", got)
	}
}

// 10. CompletedStepKinds dedup: a rule whose Then.Kind is already
// present is skipped on the next pass even if its predicate still
// returns true.
func TestLoginFlowDedupSkipsRule(t *testing.T) {
	t.Parallel()

	pw := successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")
	totp := successAuth(op.FactorTOTP, op.AAL2, "otp", "user-1")
	flow, _ := authn.CompileLoginFlow(authn.LoginFlowSpec{
		Primary: authn.LoginFlowStep{Kind: "myorg.password", Authenticator: pw},
		Rules: []authn.LoginFlowRule{
			{
				When: func(authn.LoginFlowContext) bool { return true },
				Then: authn.LoginFlowStep{Kind: "myorg.totp", Authenticator: totp},
			},
		},
	})
	o, _ := authn.New(authn.Config{LoginFlow: flow, StateRefSigner: newSigner(t)})

	st, step, err := o.Tick(context.Background(), initialState(), authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("primary begin: %v", err)
	}
	st, step, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"password": "x"}},
		Now:        fakeNow(),
	})
	if err != nil {
		t.Fatalf("primary continue: %v", err)
	}
	// Drive TOTP.
	st, step, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"code": "123"}},
		Now:        fakeNow(),
	})
	if err != nil {
		t.Fatalf("totp continue: %v", err)
	}
	if step.Result == nil {
		t.Fatalf("expected grant after dedup skipped re-run of totp, got %+v", step)
	}
	if len(st.CompletedStepKinds) != 2 {
		t.Errorf("CompletedStepKinds = %v, want 2 entries (no dedup duplicate)", st.CompletedStepKinds)
	}
}

// 11. Captcha threshold gate: with LastFailures=3 the captcha prompt
// fires before Primary, even when LoginFlow does not declare a
// StepCaptcha — this is the legacy after-N-failures captcha and the
// LoginFlow path inherits it.
func TestLoginFlowCaptchaThresholdBeforePrimary(t *testing.T) {
	t.Parallel()

	pw := successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")
	captcha := &stubCaptcha{
		verify: func(_ context.Context, _ op.CaptchaInput) error { return nil },
	}
	flow, _ := authn.CompileLoginFlow(authn.LoginFlowSpec{
		Primary: authn.LoginFlowStep{Kind: "myorg.password", Authenticator: pw},
	})
	o, _ := authn.New(authn.Config{
		LoginFlow:      flow,
		Captcha:        captcha,
		StateRefSigner: newSigner(t),
	})

	st := initialState()
	st.LastFailures = 3
	_, step, err := o.Tick(context.Background(), st, authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if step.Prompt == nil || step.Prompt.Type != "captcha" {
		t.Fatalf("expected captcha prompt before primary, got %+v", step)
	}
}

// 12. ExternalStep authenticator is forwarded verbatim — Type / AAL /
// AMR contributions land in State.Factors with the embedder's
// declared values.
func TestLoginFlowExternalStepFactorContribution(t *testing.T) {
	t.Parallel()

	custom := &stubAuthenticator{
		typeID:  "myorg.hwk", // user-defined
		aal:     op.AAL3,
		amr:     "hwk",
		prompts: []string{"auth.myorg.hwk"},
		beginFn: func(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
			return interaction.Step{Prompt: &interaction.Prompt{Type: "auth.myorg.hwk"}}, nil
		},
		continueFn: func(_ context.Context, _ op.ContinueInput) (interaction.Step, error) {
			return interaction.Step{Result: &interaction.Result{Subject: "user-9", AuthTime: fakeNow()}}, nil
		},
	}
	flow, _ := authn.CompileLoginFlow(authn.LoginFlowSpec{
		Primary: authn.LoginFlowStep{Kind: "myorg.hwk", Authenticator: custom},
	})
	o, _ := authn.New(authn.Config{LoginFlow: flow, StateRefSigner: newSigner(t)})

	st, step, err := o.Tick(context.Background(), initialState(), authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("primary begin: %v", err)
	}
	st, step, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"x": "y"}},
		Now:        fakeNow(),
	})
	if err != nil {
		t.Fatalf("primary continue: %v", err)
	}
	if step.Result == nil {
		t.Fatalf("expected terminal Result, got %+v", step)
	}
	if len(st.Factors) != 1 || st.Factors[0].Type != "myorg.hwk" || st.Factors[0].AssuranceLevel != op.AAL3 {
		t.Errorf("Factors = %+v, want one entry with myorg.hwk + AAL3", st.Factors)
	}
}

// 13. Rejecting LoginFlow + Authenticators at construction time.
func TestLoginFlowMutualExclusionAtNew(t *testing.T) {
	t.Parallel()

	pw := successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")
	flow, _ := authn.CompileLoginFlow(authn.LoginFlowSpec{
		Primary: authn.LoginFlowStep{Kind: "myorg.password", Authenticator: pw},
	})
	_, err := authn.New(authn.Config{
		LoginFlow:      flow,
		Authenticators: []op.Authenticator{pw},
		StateRefSigner: newSigner(t),
	})
	if err == nil {
		t.Fatal("expected error for LoginFlow + Authenticators, got nil")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("err = %v, want mutually-exclusive diagnostic", err)
	}
}

// 14. Compile-time rejection of duplicate StepKind across rules.
func TestCompileLoginFlowDuplicateKind(t *testing.T) {
	t.Parallel()

	pw := successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")
	totp := successAuth(op.FactorTOTP, op.AAL2, "otp", "user-1")
	_, err := authn.CompileLoginFlow(authn.LoginFlowSpec{
		Primary: authn.LoginFlowStep{Kind: "myorg.password", Authenticator: pw},
		Rules: []authn.LoginFlowRule{
			{
				When: func(authn.LoginFlowContext) bool { return true },
				Then: authn.LoginFlowStep{Kind: "myorg.totp", Authenticator: totp},
			},
			{
				When: func(authn.LoginFlowContext) bool { return true },
				Then: authn.LoginFlowStep{Kind: "myorg.totp", Authenticator: totp},
			},
		},
	})
	if err == nil {
		t.Fatal("expected duplicate-kind compile error, got nil")
	}
	if !strings.Contains(err.Error(), "duplicate StepKind") {
		t.Errorf("err = %v, want duplicate-StepKind message", err)
	}
}

// 15. Compile-time rejection of nil Primary.
func TestCompileLoginFlowNilPrimary(t *testing.T) {
	t.Parallel()

	_, err := authn.CompileLoginFlow(authn.LoginFlowSpec{})
	if err == nil {
		t.Fatal("expected error for nil Primary, got nil")
	}
	if !strings.Contains(err.Error(), "Primary") {
		t.Errorf("err = %v, want it to mention Primary", err)
	}
}
