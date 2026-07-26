package authn_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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

func (d *stubLoginFlowDecider) Decide(ctx context.Context, lc authn.LoginFlowContext) authn.LoginFlowDecision { //nolint:ireturn,nolintlint // sealed-sum LoginFlowDecision is the contract.
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

// TestLoginFlowRiskExplicitScoreReachesMedium pins the
// [RiskOutcome.Score] override path: an assessor that returns
// `Decision: RiskRequire, Score: RiskScoreMedium` causes the
// orchestrator to cache Medium, so a Medium-threshold rule fires
// while a High-threshold rule (declared first to win on High) stays
// silent. This is the case the Decision-only fallback cannot reach.
func TestLoginFlowRiskExplicitScoreReachesMedium(t *testing.T) {
	t.Parallel()

	pw := successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")
	totp := successAuth(op.FactorTOTP, op.AAL2, "otp", "user-1")
	emailOTP := successAuth(op.FactorEmailOTP, op.AAL1, "email", "user-1")
	risk := &stubRisk{
		assess: func(_ context.Context, _ op.RiskInput) (op.RiskOutcome, error) {
			return op.RiskOutcome{
				Decision: op.RiskRequire,
				Score:    op.RiskScoreMedium,
				Reason:   "anomaly.test",
			}, nil
		},
	}
	flow, _ := authn.CompileLoginFlow(authn.LoginFlowSpec{
		Primary: authn.LoginFlowStep{Kind: "myorg.password", Authenticator: pw},
		Rules: []authn.LoginFlowRule{
			{
				When: func(lc authn.LoginFlowContext) bool { return lc.RiskScore >= op.RiskScoreHigh },
				Then: authn.LoginFlowStep{Kind: "myorg.totp", Authenticator: totp},
			},
			{
				When: func(lc authn.LoginFlowContext) bool { return lc.RiskScore >= op.RiskScoreMedium },
				Then: authn.LoginFlowStep{Kind: "myorg.email_otp", Authenticator: emailOTP},
			},
		},
		Risk: risk,
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
	if step.Prompt == nil || step.Prompt.Type != "auth.email_otp.send" {
		t.Fatalf("expected auth.email_otp.send prompt (Medium-threshold rule), got %+v", step)
	}
}

// TestLoginFlowRiskScoreFallsBackToHighOnRequire pins the
// Decision-only fallback: an assessor that leaves [RiskOutcome.Score]
// at zero and returns `Decision: RiskRequire` still produces
// [RiskScoreHigh] in the cache, so the existing two-line assessor in
// embedder code keeps working unchanged.
func TestLoginFlowRiskScoreFallsBackToHighOnRequire(t *testing.T) {
	t.Parallel()

	pw := successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")
	totp := successAuth(op.FactorTOTP, op.AAL2, "otp", "user-1")
	risk := &stubRisk{
		assess: func(_ context.Context, _ op.RiskInput) (op.RiskOutcome, error) {
			return op.RiskOutcome{Decision: op.RiskRequire}, nil
		},
	}
	flow, _ := authn.CompileLoginFlow(authn.LoginFlowSpec{
		Primary: authn.LoginFlowStep{Kind: "myorg.password", Authenticator: pw},
		Rules: []authn.LoginFlowRule{
			{
				When: func(lc authn.LoginFlowContext) bool { return lc.RiskScore >= op.RiskScoreHigh },
				Then: authn.LoginFlowStep{Kind: "myorg.totp", Authenticator: totp},
			},
		},
		Risk: risk,
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
		t.Fatalf("expected auth.totp prompt (High-threshold rule via fallback), got %+v", step)
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
			// AAL3 authenticators MUST report UserVerified=true; the
			// orchestrator's gate (guardAAL3RequiresUV) rejects AAL3 factors
			// that did not perform UV per NIST SP 800-63B.
			return interaction.Step{Result: &interaction.Result{
				Subject:      "user-9",
				AuthTime:     fakeNow(),
				UserVerified: true,
			}}, nil
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

// TestLoginFlowTOTPRequiresPrimary pins the chain-isolation property
// that lets the OP avoid the cal.com / Keycloak primary-skip class:
// even with TOTP declared as a Rule, the orchestrator's first Tick
// MUST emit Primary's prompt and tag the StateRef with Primary's
// kind. The TOTP step is unreachable until Primary's CompletedStepKind
// has been recorded.
//
// Tracks:
//   - GHSA-9r3w-4j8q-pw98 (cal.com, 2024-04, CVSS 9.8) — TRPC
//     verifyTwoFactor accepted (email, password, totpCode) and
//     returned a session without verifying the password. CWE-287.
//   - GHSA-5jfq-x6xp-7rw2 (Keycloak, 2024-09, CVSS 6.8) — direct OTP
//     submission bypassed the primary credential. Same structural
//     defect.
//
// The matching adapter-side gate is
// totp.TestAuthenticator_BeginRequiresSubject /
// totp.TestAuthenticator_ContinueRequiresSubject. Together the two
// layers (orchestrator first-step invariant + TOTP subject-required
// gate) make the bypass class unreachable.
func TestLoginFlowTOTPRequiresPrimary(t *testing.T) {
	t.Parallel()

	pw := successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")
	totp := successAuth(op.FactorTOTP, op.AAL2, "otp", "user-1")
	flow, err := authn.CompileLoginFlow(authn.LoginFlowSpec{
		Primary: authn.LoginFlowStep{Kind: "myorg.password", Authenticator: pw},
		Rules: []authn.LoginFlowRule{
			{
				When: func(authn.LoginFlowContext) bool { return true },
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

	// First Tick on a fresh State MUST emit Primary's prompt — the
	// TOTP rule's `When: true` is irrelevant because advanceLoginFlow
	// short-circuits to Primary while CompletedStepKinds is empty.
	st, step, err := o.Tick(context.Background(), initialState(), authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("first Tick: %v", err)
	}
	if step.Prompt == nil {
		t.Fatalf("expected prompt on first Tick, got %+v", step)
	}
	if step.Prompt.Type != "auth.password" {
		t.Errorf("first prompt = %q, want auth.password — TOTP-first would be the primary-skip bypass class", step.Prompt.Type)
	}
	if st.ActiveStepKind != "myorg.password" {
		t.Errorf("ActiveStepKind = %q, want myorg.password", st.ActiveStepKind)
	}
	if len(st.CompletedStepKinds) != 0 {
		t.Errorf("CompletedStepKinds = %v, want empty before any submission", st.CompletedStepKinds)
	}

	// Submitting a TOTP-shaped value to the password StateRef MUST be
	// routed to Primary, not TOTP. successAuth's continueFn ignores
	// the submission values, so the test asserts the routing — the
	// completed kind that lands first is myorg.password regardless of
	// what the SPA submitted.
	primaryStateRef := step.Prompt.StateRef
	st, step, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{
			StateRef: primaryStateRef,
			Values:   map[string]string{"code": "123456"},
		},
		Now: fakeNow(),
	})
	if err != nil {
		t.Fatalf("second Tick: %v", err)
	}
	if len(st.CompletedStepKinds) == 0 || st.CompletedStepKinds[0] != "myorg.password" {
		t.Errorf("first completed step = %v, want first entry = myorg.password — TOTP-first would mean cal.com-class bypass", st.CompletedStepKinds)
	}

	// After Primary completes, TOTP becomes reachable: the next Tick
	// is expected to emit auth.totp. Driving it to terminal Result
	// confirms the chain reaches AAL2 via the documented order, not a
	// shortcut.
	if step.Prompt == nil || step.Prompt.Type != "auth.totp" {
		t.Fatalf("expected auth.totp prompt after Primary, got %+v", step)
	}
	st, step, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{
			StateRef: step.Prompt.StateRef,
			Values:   map[string]string{"code": "123456"},
		},
		Now: fakeNow(),
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

// TestLoginFlowACRRuleFiresWhenStateCarriesACRValues pins the projector's
// ACRValues round-trip: a RuleACR-style predicate that inspects
// LoginFlowContext.ACRValues MUST observe the request's acr_values list
// after Primary completes, so the OP cannot assert an elevated ACR claim
// without running the matching step-up factor.
//
// The original projector dropped State.ACRValues on the floor so every
// RuleACR predicate evaluated against an empty slice; the chain
// short-circuited to AfterAuthn with only the Primary factor on file
// while the wire still echoed the requested acr_values to the RP. This
// regression test asserts the fix: when State.ACRValues carries
// "urn:test:silver" and a rule's predicate fires on that value, the
// orchestrator schedules the rule's TOTP step before granting.
func TestLoginFlowACRRuleFiresWhenStateCarriesACRValues(t *testing.T) {
	t.Parallel()

	pw := successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")
	totp := successAuth(op.FactorTOTP, op.AAL2, "otp", "user-1")
	flow, err := authn.CompileLoginFlow(authn.LoginFlowSpec{
		Primary: authn.LoginFlowStep{Kind: "myorg.password", Authenticator: pw},
		Rules: []authn.LoginFlowRule{
			{
				When: func(lc authn.LoginFlowContext) bool {
					for _, v := range lc.ACRValues {
						if v == "urn:test:silver" {
							return true
						}
					}
					return false
				},
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

	st := initialState()
	st.ACRValues = []string{"urn:test:silver"}

	// Drive Primary.
	st, step, err := o.Tick(context.Background(), st, authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("primary begin: %v", err)
	}
	if step.Prompt == nil || step.Prompt.Type != "auth.password" {
		t.Fatalf("expected auth.password prompt, got %+v", step)
	}
	st, step, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"password": "x"}},
		Now:        fakeNow(),
	})
	if err != nil {
		t.Fatalf("primary continue: %v", err)
	}
	// Rule predicate must have fired: the orchestrator schedules TOTP
	// instead of granting outright.
	if step.Result != nil {
		t.Fatalf("orchestrator granted before TOTP ran — RuleACR did not fire (security regression)")
	}
	if step.Prompt == nil || step.Prompt.Type != "auth.totp" {
		t.Fatalf("expected auth.totp prompt after RuleACR fired, got %+v — projector likely dropped State.ACRValues", step)
	}

	// Drive TOTP to completion to confirm the chain reaches AAL2 via
	// the documented order, not a shortcut.
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
	wantKindsACR := []string{"myorg.password", "myorg.totp"}
	if len(st.CompletedStepKinds) != 2 || st.CompletedStepKinds[0] != wantKindsACR[0] || st.CompletedStepKinds[1] != wantKindsACR[1] {
		t.Errorf("CompletedStepKinds = %v, want %v", st.CompletedStepKinds, wantKindsACR)
	}
}

// TestLoginFlowACRRuleSilentWhenStateOmitsACRValues is the control case
// for [TestLoginFlowACRRuleFiresWhenStateCarriesACRValues]: with no
// ACRValues on State, the same RuleACR-style predicate MUST NOT fire,
// and the chain grants on Primary alone. The test exists to confirm
// the projector did not start populating ACRValues unconditionally
// (which would over-trigger every step-up rule).
func TestLoginFlowACRRuleSilentWhenStateOmitsACRValues(t *testing.T) {
	t.Parallel()

	pw := successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")
	totp := successAuth(op.FactorTOTP, op.AAL2, "otp", "user-1")
	flow, err := authn.CompileLoginFlow(authn.LoginFlowSpec{
		Primary: authn.LoginFlowStep{Kind: "myorg.password", Authenticator: pw},
		Rules: []authn.LoginFlowRule{
			{
				When: func(lc authn.LoginFlowContext) bool {
					for _, v := range lc.ACRValues {
						if v == "urn:test:silver" {
							return true
						}
					}
					return false
				},
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

	// Initial State carries no ACRValues — the rule predicate must
	// observe the empty slice and stay silent.
	st := initialState()

	st, step, err := o.Tick(context.Background(), st, authn.Input{Now: fakeNow()})
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
		t.Fatalf("expected terminal Result after Primary (no ACRValues, no rule match), got %+v", step)
	}
}

// TestLoginFlowSoftFactorErrorReemitsPrompt regression-locks the
// path that drops a wrong-credential submission back into the same
// factor's prompt. Authenticators that wrap [authn.ErrFactorRetry]
// MUST trigger the orchestrator to (a) observe the failure (so
// [RuleAfterFailedAttempts] can fire) and (b) re-emit the prompt
// instead of bubbling the error to the HTTP layer as a 500.
func TestLoginFlowSoftFactorErrorReemitsPrompt(t *testing.T) {
	t.Parallel()

	pwPrompt := promptForFactor(op.FactorPassword)
	beginCalls := 0
	pw := &stubAuthenticator{
		typeID:  op.FactorPassword,
		aal:     op.AAL1,
		amr:     "pwd",
		prompts: []string{pwPrompt.Type},
		beginFn: func(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
			beginCalls++
			return interaction.Step{Prompt: &pwPrompt}, nil
		},
		continueFn: func(_ context.Context, _ op.ContinueInput) (interaction.Step, error) {
			return interaction.Step{}, fmt.Errorf("password: invalid: %w", authn.ErrFactorRetry)
		},
	}
	flow, err := authn.CompileLoginFlow(authn.LoginFlowSpec{
		Primary: authn.LoginFlowStep{Kind: "myorg.password", Authenticator: pw},
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
		t.Fatalf("first Tick: %v", err)
	}
	if step.Prompt == nil {
		t.Fatalf("expected initial prompt, got %+v", step)
	}
	if beginCalls != 1 {
		t.Fatalf("Begin call count after first Tick = %d, want 1", beginCalls)
	}

	st2, step2, err := o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"password": "wrong"}},
		Now:        fakeNow(),
	})
	if err != nil {
		t.Fatalf("retry Tick returned err = %v, want nil (soft retry must re-emit prompt)", err)
	}
	if step2.Result != nil {
		t.Fatalf("retry Tick produced Result; soft retry must keep the chain pending")
	}
	if step2.Prompt == nil || step2.Prompt.Type != pwPrompt.Type {
		t.Fatalf("retry Tick prompt = %+v, want %s", step2.Prompt, pwPrompt.Type)
	}
	if beginCalls != 2 {
		t.Fatalf("Begin call count after retry = %d, want 2 (orchestrator must call Begin to refresh prompt)", beginCalls)
	}
	if got := st2.LastFailures; got != 1 {
		t.Errorf("LastFailures after one soft failure = %d, want 1", got)
	}
}

// multiStepFactorStub models email-OTP's two-screen shape for the
// LoginFlow M-3 retry tests: Begin and the first Continue (empty scratch)
// emit the "send" screen; every later Continue works the "verify" screen.
// A wrong code re-emits the verify prompt alongside ErrFactorRetry so the
// orchestrator can keep the user on the verify screen; the code "correct"
// grants.
func multiStepFactorStub() *stubAuthenticator {
	const (
		sendType   = "auth.email_otp.send"
		verifyType = "auth.email_otp.verify"
	)
	verifyScratch := []byte{0x01}
	return &stubAuthenticator{
		typeID:  op.FactorEmailOTP,
		aal:     op.AAL2,
		amr:     "otp",
		prompts: []string{sendType, verifyType},
		beginFn: func(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
			return interaction.Step{Prompt: &interaction.Prompt{Type: sendType}}, nil
		},
		continueFn: func(_ context.Context, in op.ContinueInput) (interaction.Step, error) {
			if len(in.Scratch) == 0 {
				return interaction.Step{Prompt: &interaction.Prompt{Type: verifyType}, Scratch: verifyScratch}, nil
			}
			if in.Submission.Values["code"] == "correct" {
				return interaction.Step{Result: &interaction.Result{Subject: "user-1", AuthTime: fakeNow()}}, nil
			}
			return interaction.Step{Prompt: &interaction.Prompt{Type: verifyType}, Scratch: verifyScratch}, fmt.Errorf("emailotp: wrong code: %w", authn.ErrFactorRetry)
		},
	}
}

// driveToEmailOTPVerify runs the password primary then the email-OTP send
// screen, returning the state and the verify prompt's Step so a test can
// submit a code against it.
func driveToEmailOTPVerify(t *testing.T, o *authn.Orchestrator) (authn.State, interaction.Step) {
	t.Helper()
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
	if step.Prompt == nil || step.Prompt.Type != "auth.email_otp.send" {
		t.Fatalf("expected email_otp.send prompt, got %+v", step.Prompt)
	}
	st, step, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"email": "a@b.c"}},
		Now:        fakeNow(),
	})
	if err != nil {
		t.Fatalf("send continue: %v", err)
	}
	if step.Prompt == nil || step.Prompt.Type != "auth.email_otp.verify" {
		t.Fatalf("expected email_otp.verify prompt, got %+v", step.Prompt)
	}
	return st, step
}

// TestLoginFlowMultiStepFactorWrongCodeReShowsVerifyStep pins M-3 on the
// LoginFlow path: a wrong code on the email-OTP verify screen re-shows
// the VERIFY prompt (delivered code still valid), not the send screen,
// and a subsequent correct code grants — proving the verify scratch was
// preserved across the retry rather than being reset by a restart.
func TestLoginFlowMultiStepFactorWrongCodeReShowsVerifyStep(t *testing.T) {
	t.Parallel()

	pw := successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")
	otp := multiStepFactorStub()
	flow, err := authn.CompileLoginFlow(authn.LoginFlowSpec{
		Primary: authn.LoginFlowStep{Kind: "myorg.password", Authenticator: pw},
		Rules: []authn.LoginFlowRule{
			{
				When: func(authn.LoginFlowContext) bool { return true },
				Then: authn.LoginFlowStep{Kind: "myorg.email_otp", Authenticator: otp},
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

	st, step := driveToEmailOTPVerify(t, o)

	// Wrong code -> re-show verify (not send), scratch preserved.
	st, step, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"code": "000000"}},
		Now:        fakeNow(),
	})
	if err != nil {
		t.Fatalf("wrong-code Tick: %v", err)
	}
	if step.Prompt == nil || step.Prompt.Type != "auth.email_otp.verify" {
		t.Fatalf("wrong code must re-show verify prompt, got %+v", step.Prompt)
	}
	if len(st.FactorScratch) == 0 {
		t.Fatalf("verify scratch must be preserved on retry, got empty")
	}
	if st.LastFailures != 1 {
		t.Errorf("LastFailures = %d, want 1", st.LastFailures)
	}
	if st.ActiveStepKind != "myorg.email_otp" {
		t.Errorf("ActiveStepKind = %q, want myorg.email_otp (still on the factor)", st.ActiveStepKind)
	}

	// Correct code on the still-live verify step -> grant.
	_, step, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"code": "correct"}},
		Now:        fakeNow(),
	})
	if err != nil {
		t.Fatalf("correct-code Tick: %v", err)
	}
	if step.Result == nil || step.Result.Subject != "user-1" {
		t.Fatalf("expected grant, got %+v", step)
	}
}

// TestLoginFlowMultiStepFactorRetryYieldsToCaptchaRule pins that the M-3
// verify-re-show shortcut does NOT bypass a pending captcha rule. A
// captcha-shaped rule whose predicate flips on the first failed attempt
// MUST interpose after a wrong code on the verify screen, rather than the
// factor silently re-showing its own prompt and skipping the challenge.
func TestLoginFlowMultiStepFactorRetryYieldsToCaptchaRule(t *testing.T) {
	t.Parallel()

	pw := successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")
	otp := multiStepFactorStub()
	captchaPrompt := interaction.Prompt{Type: "captcha"}
	captchaAuth := &stubAuthenticator{
		typeID:  "myorg.captcha",
		aal:     op.AAL1,
		amr:     "captcha",
		prompts: []string{captchaPrompt.Type},
		beginFn: func(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
			return interaction.Step{Prompt: &captchaPrompt}, nil
		},
		continueFn: func(_ context.Context, _ op.ContinueInput) (interaction.Step, error) {
			return interaction.Step{Result: &interaction.Result{}}, nil
		},
	}
	flow, err := authn.CompileLoginFlow(authn.LoginFlowSpec{
		Primary: authn.LoginFlowStep{Kind: "myorg.password", Authenticator: pw},
		Rules: []authn.LoginFlowRule{
			// Captcha declared first so it wins over the email-OTP rule
			// once its predicate flips on the first failed verify attempt.
			{
				When: func(lc authn.LoginFlowContext) bool { return lc.FailedAttempts >= 1 },
				Then: authn.LoginFlowStep{Kind: "myorg.captcha", Authenticator: captchaAuth, IsCaptcha: true},
			},
			{
				When: func(authn.LoginFlowContext) bool { return true },
				Then: authn.LoginFlowStep{Kind: "myorg.email_otp", Authenticator: otp},
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

	st, step := driveToEmailOTPVerify(t, o)

	// Wrong code -> the pending captcha rule interposes instead of the
	// verify prompt re-showing.
	_, step, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"code": "000000"}},
		Now:        fakeNow(),
	})
	if err != nil {
		t.Fatalf("wrong-code Tick: %v", err)
	}
	if step.Prompt == nil || step.Prompt.Type != "captcha" {
		t.Fatalf("wrong code with a pending captcha rule must emit captcha, got %+v", step.Prompt)
	}
}

// TestLoginFlowCaptchaRuleFiresAfterFailedAttempts pins the contract
// that a captcha-shaped rule (e.g. RuleAfterFailedAttempts(3,
// StepCaptcha)) actually interposes between the failing credential
// factor and the next prompt. Without the pre-Primary captcha-rule
// scan the rule list is consulted only after Primary completes — a
// state soft credential failures never reach — so the rule would
// silently never fire.
func TestLoginFlowCaptchaRuleFiresAfterFailedAttempts(t *testing.T) {
	t.Parallel()

	pwPrompt := promptForFactor(op.FactorPassword)
	pw := &stubAuthenticator{
		typeID:  op.FactorPassword,
		aal:     op.AAL1,
		amr:     "pwd",
		prompts: []string{pwPrompt.Type},
		beginFn: func(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
			return interaction.Step{Prompt: &pwPrompt}, nil
		},
		continueFn: func(_ context.Context, in op.ContinueInput) (interaction.Step, error) {
			if in.Submission.Values["password"] == "correct" {
				return interaction.Step{Result: &interaction.Result{Subject: "user-1", AuthTime: fakeNow()}}, nil
			}
			return interaction.Step{}, fmt.Errorf("password: invalid: %w", authn.ErrFactorRetry)
		},
	}

	captchaPrompt := interaction.Prompt{Type: "captcha"}
	captchaAuth := &stubAuthenticator{
		typeID:  "myorg.captcha",
		aal:     op.AAL1,
		amr:     "captcha",
		prompts: []string{captchaPrompt.Type},
		beginFn: func(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
			return interaction.Step{Prompt: &captchaPrompt}, nil
		},
		continueFn: func(_ context.Context, _ op.ContinueInput) (interaction.Step, error) {
			return interaction.Step{Result: &interaction.Result{}}, nil
		},
	}

	flow, err := authn.CompileLoginFlow(authn.LoginFlowSpec{
		Primary: authn.LoginFlowStep{Kind: "myorg.password", Authenticator: pw},
		Rules: []authn.LoginFlowRule{
			{
				When: func(lc authn.LoginFlowContext) bool { return lc.FailedAttempts >= 3 },
				Then: authn.LoginFlowStep{Kind: "myorg.captcha", Authenticator: captchaAuth, IsCaptcha: true},
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
		t.Fatalf("first Tick: %v", err)
	}
	if step.Prompt == nil || step.Prompt.Type != pwPrompt.Type {
		t.Fatalf("first prompt = %+v, want password", step.Prompt)
	}

	// Submit three wrong passwords. Each soft failure increments
	// LastFailures. The captcha rule predicate flips on the third
	// pass and the orchestrator emits the captcha prompt.
	for i := 1; i <= 3; i++ {
		st, step, err = o.Tick(context.Background(), st, authn.Input{
			Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"password": "wrong"}},
			Now:        fakeNow(),
		})
		if err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
		if step.Prompt == nil {
			t.Fatalf("attempt %d: expected a prompt, got %+v", i, step)
		}
		if i < 3 && step.Prompt.Type != pwPrompt.Type {
			t.Fatalf("attempt %d prompt = %s, want password", i, step.Prompt.Type)
		}
		if i == 3 && step.Prompt.Type != captchaPrompt.Type {
			t.Fatalf("attempt %d prompt = %s, want captcha (rule must fire)", i, step.Prompt.Type)
		}
	}
	if got := st.LastFailures; got != 3 {
		t.Errorf("LastFailures after 3 soft failures = %d, want 3", got)
	}

	// Solve the captcha. The orchestrator should clear LastFailures
	// and re-prompt for the password.
	st, step, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"token": "ok"}},
		Now:        fakeNow(),
	})
	if err != nil {
		t.Fatalf("captcha continue: %v", err)
	}
	if step.Prompt == nil || step.Prompt.Type != pwPrompt.Type {
		t.Fatalf("after captcha prompt = %+v, want password", step.Prompt)
	}
	if got := st.LastFailures; got != 0 {
		t.Errorf("LastFailures after captcha success = %d, want 0", got)
	}
	if !st.CaptchaPassed {
		t.Errorf("CaptchaPassed = false, want true after captcha success")
	}

	// Final correct password lands the chain in PhaseAfterAuthn.
	st, step, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"password": "correct"}},
		Now:        fakeNow(),
	})
	if err != nil {
		t.Fatalf("final continue: %v", err)
	}
	if step.Result == nil {
		t.Fatalf("expected terminal Result, got %+v", step)
	}
	if st.Subject != "user-1" {
		t.Errorf("Subject = %q, want user-1", st.Subject)
	}
}
