package authn_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/op"
)

// newSigner constructs a deterministic StateRef signer for tests. The
// key is fixed bytes; tests that need rotation construct their own.
func newSigner(t *testing.T) *authn.StateRefSigner {
	t.Helper()
	key := bytes.Repeat([]byte{0xAB}, 32)
	s, err := authn.NewStateRefSigner(key)
	if err != nil {
		t.Fatalf("NewStateRefSigner: %v", err)
	}
	return s
}

// fakeNow returns a fixed reference time used by tests. The exact
// value is irrelevant beyond consistency.
func fakeNow() time.Time {
	return time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
}

// initialState returns a fresh State seeded with the per-attempt
// metadata the HTTP layer would normally persist. The orchestrator's
// first Tick advances it to PhaseAuthn (or runs BeforeAuthn first if
// any interaction matches).
func initialState() authn.State {
	return authn.State{
		InteractionUID:  "uid-test",
		ClientID:        "client-test",
		RemoteIP:        netip.MustParseAddr("203.0.113.10"),
		UserAgent:       "go-test/1.0",
		AuthTime:        fakeNow(),
		ActiveFactorIdx: -1,
		Phase:           authn.PhaseBeforeAuthn,
	}
}

// stubAuthenticator is a hand-rolled op.Authenticator for orchestrator
// tests. The struct lets each test wire begin / continue behaviour
// independently without pulling in the per-method packages.
type stubAuthenticator struct {
	typeID     op.FactorType
	aal        op.AAL
	amr        string
	prompts    []string
	beginFn    func(ctx context.Context, in op.BeginInput) (op.Step, error)
	continueFn func(ctx context.Context, sub op.FormSubmission) (op.Step, error)
}

func (s *stubAuthenticator) Type() op.FactorType { return s.typeID }
func (s *stubAuthenticator) AAL() op.AAL         { return s.aal }
func (s *stubAuthenticator) AMR() string         { return s.amr }
func (s *stubAuthenticator) Prompts() []string   { return s.prompts }
func (s *stubAuthenticator) Begin(ctx context.Context, in op.BeginInput) (op.Step, error) {
	return s.beginFn(ctx, in)
}

func (s *stubAuthenticator) Continue(ctx context.Context, sub op.FormSubmission) (op.Step, error) {
	return s.continueFn(ctx, sub)
}

// stubInteraction is a hand-rolled op.Interaction.
type stubInteraction struct {
	name       string
	trigger    op.InteractionTrigger
	beginFn    func(ctx context.Context, in op.BeginInput) (op.Step, error)
	continueFn func(ctx context.Context, sub op.FormSubmission) (op.Step, error)
}

func (i *stubInteraction) Name() string                   { return i.name }
func (i *stubInteraction) Trigger() op.InteractionTrigger { return i.trigger }
func (i *stubInteraction) Begin(ctx context.Context, in op.BeginInput) (op.Step, error) {
	return i.beginFn(ctx, in)
}

func (i *stubInteraction) Continue(ctx context.Context, sub op.FormSubmission) (op.Step, error) {
	return i.continueFn(ctx, sub)
}

// stubRisk is a hand-rolled op.RiskAssessor whose Assess returns a
// caller-provided RiskOutcome / error.
type stubRisk struct {
	assess func(ctx context.Context, in op.RiskInput) (op.RiskOutcome, error)
}

func (r *stubRisk) Assess(ctx context.Context, in op.RiskInput) (op.RiskOutcome, error) {
	return r.assess(ctx, in)
}

// stubCaptcha is a hand-rolled op.CaptchaVerifier.
type stubCaptcha struct {
	verify func(ctx context.Context, in op.CaptchaInput) error
}

func (c *stubCaptcha) Verify(ctx context.Context, in op.CaptchaInput) error {
	return c.verify(ctx, in)
}

// recordingObserver collects every event for later assertions.
type recordingObserver struct {
	mu     sync.Mutex
	events []op.LoginAttempt
}

func (r *recordingObserver) Observe(_ context.Context, evt op.LoginAttempt) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, evt)
}

func (r *recordingObserver) snapshot() []op.LoginAttempt {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]op.LoginAttempt, len(r.events))
	copy(out, r.events)
	return out
}

// passwordPrompt is a convenience constructor for the canonical
// password Prompt shape the tests emit.
func passwordPrompt() *op.Prompt {
	return &op.Prompt{
		Type: "auth.password",
		Data: op.PasswordPromptData{},
	}
}

// 1. Single password factor success.
func TestTickSinglePasswordSuccess(t *testing.T) {
	t.Parallel()

	pw := &stubAuthenticator{
		typeID:  op.FactorPassword,
		aal:     op.AAL1,
		amr:     "pwd",
		prompts: []string{"auth.password"},
		beginFn: func(_ context.Context, _ op.BeginInput) (op.Step, error) {
			return op.Step{Prompt: passwordPrompt()}, nil
		},
		continueFn: func(_ context.Context, _ op.FormSubmission) (op.Step, error) {
			return op.Step{Result: &op.Result{Subject: "user-1", AuthTime: fakeNow()}}, nil
		},
	}
	o, err := authn.New(authn.Config{
		Authenticators: []op.Authenticator{pw},
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
	if step.Prompt.StateRef == "" {
		t.Fatal("StateRef must be populated")
	}

	st, step, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &op.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"password": "hunter2"}},
		Now:        fakeNow(),
	})
	if err != nil {
		t.Fatalf("second Tick: %v", err)
	}
	if step.Result == nil {
		t.Fatalf("expected terminal Result, got %+v", step)
	}
	if step.Result.Subject != "user-1" {
		t.Errorf("Result.Subject = %q, want %q", step.Result.Subject, "user-1")
	}

	acr, amr, level := authn.Aggregate(st.Factors)
	if acr != "urn:mace:incommon:iap:bronze" {
		t.Errorf("acr = %q, want bronze", acr)
	}
	if level != op.AAL1 {
		t.Errorf("level = %v, want AAL1", level)
	}
	if len(amr) != 1 || amr[0] != "pwd" {
		t.Errorf("amr = %v, want [pwd]", amr)
	}
}

// 2. Multi-step factor (email OTP). Begin emits send-prompt; submit
// email -> verify-prompt; submit code -> Result.
func TestTickMultiStepEmailOTP(t *testing.T) {
	t.Parallel()

	step := 0
	email := &stubAuthenticator{
		typeID:  op.FactorEmailOTP,
		aal:     op.AAL2,
		amr:     "otp",
		prompts: []string{"auth.email_otp.send", "auth.email_otp.verify"},
		beginFn: func(_ context.Context, _ op.BeginInput) (op.Step, error) {
			return op.Step{Prompt: &op.Prompt{
				Type: "auth.email_otp.send",
				Data: op.EmailOTPSendPromptData{},
			}}, nil
		},
		continueFn: func(_ context.Context, _ op.FormSubmission) (op.Step, error) {
			step++
			if step == 1 {
				return op.Step{Prompt: &op.Prompt{
					Type: "auth.email_otp.verify",
					Data: op.EmailOTPVerifyPromptData{MaskedEmail: "a***@e***"},
				}}, nil
			}
			return op.Step{Result: &op.Result{Subject: "user-9", AuthTime: fakeNow()}}, nil
		},
	}

	// Email OTP requires a known subject; pre-seed it.
	state := initialState()
	state.Subject = "user-9"

	o, err := authn.New(authn.Config{
		Authenticators: []op.Authenticator{email},
		StateRefSigner: newSigner(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	st, sendStep, err := o.Tick(context.Background(), state, authn.Input{Now: fakeNow()})
	if err != nil || sendStep.Prompt == nil || sendStep.Prompt.Type != "auth.email_otp.send" {
		t.Fatalf("send step: err=%v step=%+v", err, sendStep)
	}

	st, verifyStep, err := o.Tick(context.Background(), st, authn.Input{
		Submission: &op.FormSubmission{StateRef: sendStep.Prompt.StateRef, Values: map[string]string{"email": "a@e"}},
		Now:        fakeNow(),
	})
	if err != nil || verifyStep.Prompt == nil || verifyStep.Prompt.Type != "auth.email_otp.verify" {
		t.Fatalf("verify step: err=%v step=%+v", err, verifyStep)
	}

	_, finalStep, err := o.Tick(context.Background(), st, authn.Input{
		Submission: &op.FormSubmission{StateRef: verifyStep.Prompt.StateRef, Values: map[string]string{"code": "123456"}},
		Now:        fakeNow(),
	})
	if err != nil {
		t.Fatalf("final Tick: %v", err)
	}
	if finalStep.Result == nil || finalStep.Result.Subject != "user-9" {
		t.Errorf("expected Result subject user-9, got %+v", finalStep)
	}
}

// 3. Risk Require overrides default order.
func TestTickRiskRequireSelectsPasskey(t *testing.T) {
	t.Parallel()

	pw := buildSuccessAuthenticator(op.FactorPassword, op.AAL1, "pwd")
	totp := buildSuccessAuthenticator(op.FactorTOTP, op.AAL2, "otp")
	pk := buildSuccessAuthenticator(op.FactorPasskey, op.AAL2, "hwk")

	risk := &stubRisk{
		assess: func(_ context.Context, in op.RiskInput) (op.RiskOutcome, error) {
			if in.Stage == op.RiskPreFactor {
				return op.RiskOutcome{
					Decision:        op.RiskRequire,
					RequiredFactors: []op.FactorType{op.FactorPasskey},
				}, nil
			}
			return op.RiskOutcome{Decision: op.RiskAllow}, nil
		},
	}
	o, err := authn.New(authn.Config{
		Authenticators: []op.Authenticator{pw, totp, pk},
		Risk:           risk,
		StateRefSigner: newSigner(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, step, err := o.Tick(context.Background(), initialState(), authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if step.Prompt == nil || step.Prompt.Type != "auth.passkey" {
		t.Fatalf("expected auth.passkey prompt, got %+v", step.Prompt)
	}
}

// 4. Risk Deny.
func TestTickRiskDeny(t *testing.T) {
	t.Parallel()

	pw := buildSuccessAuthenticator(op.FactorPassword, op.AAL1, "pwd")
	risk := &stubRisk{
		assess: func(_ context.Context, _ op.RiskInput) (op.RiskOutcome, error) {
			return op.RiskOutcome{Decision: op.RiskDeny, Reason: "anomaly.geo"}, nil
		},
	}
	o, err := authn.New(authn.Config{
		Authenticators: []op.Authenticator{pw},
		Risk:           risk,
		StateRefSigner: newSigner(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, _, err = o.Tick(context.Background(), initialState(), authn.Input{Now: fakeNow()})
	if !errors.Is(err, authn.ErrRiskDenied) {
		t.Fatalf("Tick err = %v, want ErrRiskDenied", err)
	}
}

// 5. Captcha challenge after 3 failures, then verify and continue.
func TestTickCaptchaAfterThreeFailures(t *testing.T) {
	t.Parallel()

	pw := buildSuccessAuthenticator(op.FactorPassword, op.AAL1, "pwd")
	verifier := &stubCaptcha{
		verify: func(_ context.Context, _ op.CaptchaInput) error { return nil },
	}
	o, err := authn.New(authn.Config{
		Authenticators: []op.Authenticator{pw},
		Captcha:        verifier,
		StateRefSigner: newSigner(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	st := initialState()
	st.LastFailures = 3

	st, captchaStep, err := o.Tick(context.Background(), st, authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("captcha Tick: %v", err)
	}
	if captchaStep.Prompt == nil || captchaStep.Prompt.Type != "captcha" {
		t.Fatalf("expected captcha prompt, got %+v", captchaStep.Prompt)
	}

	// Solve captcha; expect to land on the password prompt.
	_, pwStep, err := o.Tick(context.Background(), st, authn.Input{
		Submission:   &op.FormSubmission{StateRef: captchaStep.Prompt.StateRef},
		CaptchaToken: "ok",
		Now:          fakeNow(),
	})
	if err != nil {
		t.Fatalf("post-captcha Tick: %v", err)
	}
	if pwStep.Prompt == nil || pwStep.Prompt.Type != "auth.password" {
		t.Fatalf("expected password prompt, got %+v", pwStep.Prompt)
	}
}

// 6. Captcha failure re-emits the prompt; observers are NOT called for
// captcha events.
func TestTickCaptchaFailureReemits(t *testing.T) {
	t.Parallel()

	pw := buildSuccessAuthenticator(op.FactorPassword, op.AAL1, "pwd")
	verifier := &stubCaptcha{
		verify: func(_ context.Context, _ op.CaptchaInput) error {
			return errors.New("token invalid")
		},
	}
	obs := &recordingObserver{}
	o, err := authn.New(authn.Config{
		Authenticators: []op.Authenticator{pw},
		Captcha:        verifier,
		Observers:      []op.LoginAttemptObserver{obs},
		StateRefSigner: newSigner(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	st := initialState()
	st.LastFailures = 3

	st, captchaStep, err := o.Tick(context.Background(), st, authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("first captcha tick: %v", err)
	}

	_, retryStep, err := o.Tick(context.Background(), st, authn.Input{
		Submission:   &op.FormSubmission{StateRef: captchaStep.Prompt.StateRef},
		CaptchaToken: "wrong",
		Now:          fakeNow(),
	})
	if err != nil {
		t.Fatalf("retry tick: %v", err)
	}
	if retryStep.Prompt == nil || retryStep.Prompt.Type != "captcha" {
		t.Fatalf("expected re-emitted captcha prompt, got %+v", retryStep.Prompt)
	}
	// New token must differ from the rejected one.
	if retryStep.Prompt.StateRef == captchaStep.Prompt.StateRef {
		t.Error("StateRef must rotate on re-emit")
	}
	if got := obs.snapshot(); len(got) != 0 {
		t.Errorf("observers fired on captcha event: %+v", got)
	}
}

// 7. StateRef mismatch (wrong step) and expired tokens are both
// rejected as ErrInvalidStateRef.
func TestTickStateRefMismatch(t *testing.T) {
	t.Parallel()

	pw := buildSuccessAuthenticator(op.FactorPassword, op.AAL1, "pwd")
	o, err := authn.New(authn.Config{
		Authenticators: []op.Authenticator{pw},
		StateRefSigner: newSigner(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	st, step, err := o.Tick(context.Background(), initialState(), authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("first tick: %v", err)
	}

	// Bump the step counter on the persisted state to simulate a
	// concurrent advance; the StateRef should now fail the step
	// check.
	bumped := st
	bumped.StepCounter++
	_, _, err = o.Tick(context.Background(), bumped, authn.Input{
		Submission: &op.FormSubmission{StateRef: step.Prompt.StateRef},
		Now:        fakeNow(),
	})
	if !errors.Is(err, authn.ErrInvalidStateRef) {
		t.Fatalf("step mismatch: err = %v, want ErrInvalidStateRef", err)
	}

	// Expired token (advance the clock past the TTL).
	_, _, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &op.FormSubmission{StateRef: step.Prompt.StateRef},
		Now:        fakeNow().Add(time.Hour),
	})
	if !errors.Is(err, authn.ErrInvalidStateRef) {
		t.Fatalf("expired: err = %v, want ErrInvalidStateRef", err)
	}
}

// 8. Unregistered AMR drop: the authenticator returns "custom"; the
// orchestrator logs a warning and stores the factor (Aggregate then
// produces no AMR contribution beyond the factor type's own mapping).
func TestTickUnregisteredAMRDropped(t *testing.T) {
	t.Parallel()

	pw := buildSuccessAuthenticator("myorg.custom", op.AAL1, "custom")
	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	o, err := authn.New(authn.Config{
		Authenticators: []op.Authenticator{pw},
		StateRefSigner: newSigner(t),
		Logger:         logger,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	st, step, err := o.Tick(context.Background(), initialState(), authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("first tick: %v", err)
	}
	st, _, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &op.FormSubmission{StateRef: step.Prompt.StateRef},
		Now:        fakeNow(),
	})
	if err != nil {
		t.Fatalf("second tick: %v", err)
	}
	if !strings.Contains(logBuf.String(), "unregistered AMR value") {
		t.Errorf("expected drop warning in log, got %q", logBuf.String())
	}
	_, amr, _ := authn.Aggregate(st.Factors)
	if amr != nil {
		t.Errorf("amr = %v, want nil (custom factor must not contribute)", amr)
	}
}

// 9. Subject-required factor skip: only TOTP registered, but Subject
// is empty -> ErrNoEligibleAuthenticator.
func TestTickNoEligibleAuthenticator(t *testing.T) {
	t.Parallel()

	totp := buildSuccessAuthenticator(op.FactorTOTP, op.AAL2, "otp")
	o, err := authn.New(authn.Config{
		Authenticators: []op.Authenticator{totp},
		StateRefSigner: newSigner(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, _, err = o.Tick(context.Background(), initialState(), authn.Input{Now: fakeNow()})
	if !errors.Is(err, authn.ErrNoEligibleAuthenticator) {
		t.Fatalf("Tick err = %v, want ErrNoEligibleAuthenticator", err)
	}
}

// 10. BeforeAuthn Interaction insertion: the first emitted Prompt is
// the interaction, not a factor.
func TestTickInteractionBeforeAuthn(t *testing.T) {
	t.Parallel()

	pw := buildSuccessAuthenticator(op.FactorPassword, op.AAL1, "pwd")
	region := &stubInteraction{
		name:    "myorg.region.gate",
		trigger: op.TriggerBeforeAuthn,
		beginFn: func(_ context.Context, _ op.BeginInput) (op.Step, error) {
			return op.Step{Prompt: &op.Prompt{
				Type: "myorg.region.prompt",
				Data: op.PasswordPromptData{},
			}}, nil
		},
		continueFn: func(_ context.Context, _ op.FormSubmission) (op.Step, error) {
			return op.Step{Result: &op.Result{}}, nil
		},
	}
	o, err := authn.New(authn.Config{
		Authenticators: []op.Authenticator{pw},
		Interactions:   []op.Interaction{region},
		StateRefSigner: newSigner(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, step, err := o.Tick(context.Background(), initialState(), authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if step.Prompt == nil || step.Prompt.Type != "myorg.region.prompt" {
		t.Fatalf("expected region.prompt, got %+v", step.Prompt)
	}
}

// 11. AfterAuthn Interaction insertion: the orchestrator emits the
// interaction after the factor completes, before PhaseDone.
func TestTickInteractionAfterAuthn(t *testing.T) {
	t.Parallel()

	pw := buildSuccessAuthenticator(op.FactorPassword, op.AAL1, "pwd")
	consent := &stubInteraction{
		name:    "consent",
		trigger: op.TriggerAfterAuthn,
		beginFn: func(_ context.Context, _ op.BeginInput) (op.Step, error) {
			return op.Step{Prompt: &op.Prompt{
				Type: "consent.scope",
				Data: op.ConsentScopePromptData{},
			}}, nil
		},
		continueFn: func(_ context.Context, _ op.FormSubmission) (op.Step, error) {
			return op.Step{Result: &op.Result{}}, nil
		},
	}
	o, err := authn.New(authn.Config{
		Authenticators: []op.Authenticator{pw},
		Interactions:   []op.Interaction{consent},
		StateRefSigner: newSigner(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	st, step, err := o.Tick(context.Background(), initialState(), authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("first tick: %v", err)
	}
	st, step, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &op.FormSubmission{StateRef: step.Prompt.StateRef},
		Now:        fakeNow(),
	})
	if err != nil {
		t.Fatalf("second tick: %v", err)
	}
	if step.Prompt == nil || step.Prompt.Type != "consent.scope" {
		t.Fatalf("expected consent prompt, got %+v", step.Prompt)
	}
	st, step, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &op.FormSubmission{StateRef: step.Prompt.StateRef},
		Now:        fakeNow(),
	})
	if err != nil {
		t.Fatalf("third tick: %v", err)
	}
	if step.Result == nil {
		t.Fatalf("expected terminal Result, got %+v", step)
	}
	if !st.InteractionsRun["consent"] {
		t.Error("InteractionsRun should record consent")
	}
}

// 12. Observer fan-out: two observers receive AttemptSuccess.
func TestTickObserverFanout(t *testing.T) {
	t.Parallel()

	pw := buildSuccessAuthenticator(op.FactorPassword, op.AAL1, "pwd")
	a := &recordingObserver{}
	b := &recordingObserver{}
	o, err := authn.New(authn.Config{
		Authenticators: []op.Authenticator{pw},
		Observers:      []op.LoginAttemptObserver{a, b},
		StateRefSigner: newSigner(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	st, step, err := o.Tick(context.Background(), initialState(), authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("first tick: %v", err)
	}
	_, _, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &op.FormSubmission{StateRef: step.Prompt.StateRef},
		Now:        fakeNow(),
	})
	if err != nil {
		t.Fatalf("second tick: %v", err)
	}
	for name, ob := range map[string]*recordingObserver{"a": a, "b": b} {
		evts := ob.snapshot()
		if len(evts) != 1 {
			t.Errorf("observer %s: %d events, want 1", name, len(evts))
			continue
		}
		if evts[0].Outcome != op.AttemptSuccess {
			t.Errorf("observer %s: outcome = %v, want AttemptSuccess", name, evts[0].Outcome)
		}
		if evts[0].Factor != op.FactorPassword {
			t.Errorf("observer %s: factor = %v, want password", name, evts[0].Factor)
		}
	}
}

// buildSuccessAuthenticator constructs a stubAuthenticator that emits
// a generic prompt on Begin and returns a Result with subject "user-1"
// on Continue. Tests that need different subjects override the
// continueFn directly.
func buildSuccessAuthenticator(t op.FactorType, aal op.AAL, amr string) *stubAuthenticator {
	prompt := promptForFactor(t)
	return &stubAuthenticator{
		typeID:  t,
		aal:     aal,
		amr:     amr,
		prompts: []string{prompt.Type},
		beginFn: func(_ context.Context, _ op.BeginInput) (op.Step, error) {
			return op.Step{Prompt: &prompt}, nil
		},
		continueFn: func(_ context.Context, _ op.FormSubmission) (op.Step, error) {
			return op.Step{Result: &op.Result{Subject: "user-1", AuthTime: fakeNow()}}, nil
		},
	}
}

// promptForFactor returns a canonical Prompt for a built-in factor
// type. Tests that exercise custom factor types (e.g.,
// "myorg.custom") receive a generic password-shaped prompt; the
// orchestrator does not validate the prompt namespace.
func promptForFactor(t op.FactorType) op.Prompt {
	switch t {
	case op.FactorPassword:
		return op.Prompt{Type: "auth.password", Data: op.PasswordPromptData{}}
	case op.FactorTOTP:
		return op.Prompt{Type: "auth.totp", Data: op.TOTPPromptData{}}
	case op.FactorPasskey:
		return op.Prompt{Type: "auth.passkey", Data: op.PasskeyPromptData{Challenge: []byte("c")}}
	case op.FactorRecoveryCode:
		return op.Prompt{Type: "auth.recovery_code", Data: op.RecoveryCodePromptData{}}
	case op.FactorEmailOTP:
		return op.Prompt{Type: "auth.email_otp.send", Data: op.EmailOTPSendPromptData{}}
	default:
		return op.Prompt{Type: "auth.password", Data: op.PasswordPromptData{}}
	}
}
