package authn_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
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
	beginFn    func(ctx context.Context, in op.BeginInput) (interaction.Step, error)
	continueFn func(ctx context.Context, in op.ContinueInput) (interaction.Step, error)
}

func (s *stubAuthenticator) Type() op.FactorType { return s.typeID }
func (s *stubAuthenticator) AAL() op.AAL         { return s.aal }
func (s *stubAuthenticator) AMR() string         { return s.amr }
func (s *stubAuthenticator) Prompts() []string   { return s.prompts }
func (s *stubAuthenticator) Begin(ctx context.Context, in op.BeginInput) (interaction.Step, error) {
	return s.beginFn(ctx, in)
}

func (s *stubAuthenticator) Continue(ctx context.Context, in op.ContinueInput) (interaction.Step, error) {
	return s.continueFn(ctx, in)
}

// stubInteraction is a hand-rolled op.Interaction.
type stubInteraction struct {
	name       string
	trigger    op.InteractionTrigger
	beginFn    func(ctx context.Context, in op.BeginInput) (interaction.Step, error)
	continueFn func(ctx context.Context, in op.ContinueInput) (interaction.Step, error)
}

func (i *stubInteraction) Name() string                   { return i.name }
func (i *stubInteraction) Trigger() op.InteractionTrigger { return i.trigger }
func (i *stubInteraction) Begin(ctx context.Context, in op.BeginInput) (interaction.Step, error) {
	return i.beginFn(ctx, in)
}

func (i *stubInteraction) Continue(ctx context.Context, in op.ContinueInput) (interaction.Step, error) {
	return i.continueFn(ctx, in)
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
func passwordPrompt() *interaction.Prompt {
	return &interaction.Prompt{
		Type: "auth.password",
		Data: interaction.PasswordPromptData{},
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
		beginFn: func(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
			return interaction.Step{Prompt: passwordPrompt()}, nil
		},
		continueFn: func(_ context.Context, _ op.ContinueInput) (interaction.Step, error) {
			return interaction.Step{Result: &interaction.Result{Subject: "user-1", AuthTime: fakeNow()}}, nil
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
		Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"password": "hunter2"}},
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

// TestTickPropagatesClientView pins the client-view wiring:
// State.Client (the read-only [interaction.ClientView] populated by
// the HTTP layer) MUST surface verbatim on every BeginInput.Client
// the orchestrator hands a registered Authenticator. The check is one
// positive test — the propagation path is the same shape as ClientID
// / RequestedScopes, both of which already have round-trip coverage.
func TestTickPropagatesClientView(t *testing.T) {
	t.Parallel()

	want := interaction.ClientView{
		ClientID: "rp-1",
		Name:     "Acme Console",
		LogoURL:  "https://acme.example.com/logo.png",
	}
	var got interaction.ClientView
	pw := &stubAuthenticator{
		typeID:  op.FactorPassword,
		aal:     op.AAL1,
		amr:     "pwd",
		prompts: []string{"auth.password"},
		beginFn: func(_ context.Context, in op.BeginInput) (interaction.Step, error) {
			got = in.Client
			return interaction.Step{Prompt: passwordPrompt()}, nil
		},
		continueFn: func(_ context.Context, _ op.ContinueInput) (interaction.Step, error) {
			return interaction.Step{Result: &interaction.Result{Subject: "user-1", AuthTime: fakeNow()}}, nil
		},
	}
	o, err := authn.New(authn.Config{
		Authenticators: []op.Authenticator{pw},
		StateRefSigner: newSigner(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	state := initialState()
	state.Client = want
	if _, _, err := o.Tick(context.Background(), state, authn.Input{Now: fakeNow()}); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if got != want {
		t.Errorf("BeginInput.Client = %+v, want %+v", got, want)
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
		beginFn: func(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
			return interaction.Step{Prompt: &interaction.Prompt{
				Type: "auth.email_otp.send",
				Data: interaction.EmailOTPSendPromptData{},
			}}, nil
		},
		continueFn: func(_ context.Context, _ op.ContinueInput) (interaction.Step, error) {
			step++
			if step == 1 {
				return interaction.Step{Prompt: &interaction.Prompt{
					Type: "auth.email_otp.verify",
					Data: interaction.EmailOTPVerifyPromptData{MaskedEmail: "a***@e***"},
				}}, nil
			}
			return interaction.Step{Result: &interaction.Result{Subject: "user-9", AuthTime: fakeNow()}}, nil
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
		Submission: &interaction.FormSubmission{StateRef: sendStep.Prompt.StateRef, Values: map[string]string{"email": "a@e"}},
		Now:        fakeNow(),
	})
	if err != nil || verifyStep.Prompt == nil || verifyStep.Prompt.Type != "auth.email_otp.verify" {
		t.Fatalf("verify step: err=%v step=%+v", err, verifyStep)
	}

	_, finalStep, err := o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{StateRef: verifyStep.Prompt.StateRef, Values: map[string]string{"code": "123456"}},
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

// TestTickRiskMinAALWithoutRequiredFactors exercises the MinAAL
// directive on the legacy Authenticators path: an assessor returns
// Require with MinAAL AAL2 and an empty RequiredFactors set. The
// orchestrator must read this as "any registered factor that meets
// AAL2": a user whose only factor is AAL1 has no eligible candidate
// (step-up denied), while a user with an AAL2 factor proceeds with it.
func TestTickRiskMinAALWithoutRequiredFactors(t *testing.T) {
	t.Parallel()

	riskRequireAAL2 := func() *stubRisk {
		return &stubRisk{
			assess: func(_ context.Context, in op.RiskInput) (op.RiskOutcome, error) {
				if in.Stage == op.RiskPreFactor {
					return op.RiskOutcome{
						Decision: op.RiskRequire,
						MinAAL:   op.AAL2,
					}, nil
				}
				return op.RiskOutcome{Decision: op.RiskAllow}, nil
			},
		}
	}

	t.Run("aal1-only-denied", func(t *testing.T) {
		t.Parallel()

		pw := buildSuccessAuthenticator(op.FactorPassword, op.AAL1, "pwd")
		o, err := authn.New(authn.Config{
			Authenticators: []op.Authenticator{pw},
			Risk:           riskRequireAAL2(),
			StateRefSigner: newSigner(t),
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		_, _, err = o.Tick(context.Background(), initialState(), authn.Input{Now: fakeNow()})
		if !errors.Is(err, authn.ErrNoEligibleAuthenticator) {
			t.Fatalf("Tick err = %v, want ErrNoEligibleAuthenticator", err)
		}
	})

	t.Run("aal2-proceeds", func(t *testing.T) {
		t.Parallel()

		pw := buildSuccessAuthenticator(op.FactorPassword, op.AAL1, "pwd")
		pk := buildSuccessAuthenticator(op.FactorPasskey, op.AAL2, "hwk")
		o, err := authn.New(authn.Config{
			Authenticators: []op.Authenticator{pw, pk},
			Risk:           riskRequireAAL2(),
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
			t.Fatalf("expected auth.passkey prompt (AAL1 password filtered out), got %+v", step.Prompt)
		}
	})
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

// TestTickOTPWrongCodeObservesFailureAndTripsCaptcha pins the failure-
// observation contract for OTP-style factors. A wrong code surfaces as
// an ErrFactorRetry-wrapping error — the shape the TOTP / email-OTP /
// recovery adapters now return — so the orchestrator MUST fire the
// observer and advance the brute-force counter on every miss (unlike
// the old nil-error re-prompt, which left SIEM blind). The miss that
// crosses the captcha threshold interposes the challenge in the same
// response, and it stays interposed on the next advance.
func TestTickOTPWrongCodeObservesFailureAndTripsCaptcha(t *testing.T) {
	t.Parallel()

	// Mirror the sentinel shape the OTP adapters emit on a wrong guess.
	wrongCode := fmt.Errorf("otp: wrong code: %w", authn.ErrFactorRetry)
	otp := &stubAuthenticator{
		typeID:  op.FactorTOTP,
		aal:     op.AAL2,
		amr:     "otp",
		prompts: []string{"auth.totp"},
		beginFn: func(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
			return interaction.Step{Prompt: &interaction.Prompt{
				Type: "auth.totp",
				Data: interaction.TOTPPromptData{},
			}}, nil
		},
		continueFn: func(_ context.Context, _ op.ContinueInput) (interaction.Step, error) {
			return interaction.Step{}, wrongCode
		},
	}
	obs := &recordingObserver{}
	captcha := &stubCaptcha{verify: func(_ context.Context, _ op.CaptchaInput) error { return nil }}
	o, err := authn.New(authn.Config{
		Authenticators: []op.Authenticator{otp},
		Observers:      []op.LoginAttemptObserver{obs},
		Captcha:        captcha,
		StateRefSigner: newSigner(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// OTP is a second factor; the subject is pre-bound so the factor is
	// eligible without a preceding identifying factor.
	st := initialState()
	st.Subject = "user-1"

	st, step, err := o.Tick(context.Background(), st, authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("first Tick: %v", err)
	}
	if step.Prompt == nil || step.Prompt.Type != "auth.totp" {
		t.Fatalf("expected auth.totp prompt, got %+v", step.Prompt)
	}

	for i := 1; i <= captchaFailureThresholdForTest; i++ {
		st, step, err = o.Tick(context.Background(), st, authn.Input{
			Submission: &interaction.FormSubmission{
				StateRef: step.Prompt.StateRef,
				Values:   map[string]string{"code": "000000"},
			},
			Now: fakeNow(),
		})
		if err != nil {
			t.Fatalf("wrong-code Tick %d: %v", i, err)
		}
		if st.LastFailures != i {
			t.Errorf("LastFailures after miss %d = %d, want %d", i, st.LastFailures, i)
		}
		// A miss below the threshold re-emits the factor prompt so the
		// SPA can retry; the miss that reaches the threshold interposes
		// the captcha in the very same response.
		want := "auth.totp"
		if i >= captchaFailureThresholdForTest {
			want = "captcha"
		}
		if step.Prompt == nil || step.Prompt.Type != want {
			t.Fatalf("miss %d: expected %q prompt, got %+v", i, want, step.Prompt)
		}
	}

	failures := 0
	for _, e := range obs.snapshot() {
		if e.Outcome == op.AttemptFailure && e.Factor == op.FactorTOTP {
			failures++
		}
	}
	if failures != captchaFailureThresholdForTest {
		t.Errorf("observer AttemptFailure events = %d, want %d", failures, captchaFailureThresholdForTest)
	}

	// A fresh advance (no submission) keeps the captcha gate interposed
	// because LastFailures has reached the threshold.
	_, captchaStep, err := o.Tick(context.Background(), st, authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("post-threshold Tick: %v", err)
	}
	if captchaStep.Prompt == nil || captchaStep.Prompt.Type != "captcha" {
		t.Fatalf("expected captcha prompt after %d failures, got %+v", captchaFailureThresholdForTest, captchaStep.Prompt)
	}
}

// captchaFailureThresholdForTest mirrors the orchestrator's internal
// captchaFailureThreshold constant. It is redeclared here because the
// constant is unexported and the test lives in the _test package.
const captchaFailureThresholdForTest = 3

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
		Submission:   &interaction.FormSubmission{StateRef: captchaStep.Prompt.StateRef},
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
		Submission:   &interaction.FormSubmission{StateRef: captchaStep.Prompt.StateRef},
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
		Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef},
		Now:        fakeNow(),
	})
	if !errors.Is(err, authn.ErrInvalidStateRef) {
		t.Fatalf("step mismatch: err = %v, want ErrInvalidStateRef", err)
	}

	// Expired token (advance the clock past the TTL).
	_, _, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef},
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
		Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef},
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
		beginFn: func(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
			return interaction.Step{Prompt: &interaction.Prompt{
				Type: "myorg.region.prompt",
				Data: interaction.PasswordPromptData{},
			}}, nil
		},
		continueFn: func(_ context.Context, _ op.ContinueInput) (interaction.Step, error) {
			return interaction.Step{Result: &interaction.Result{}}, nil
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
		beginFn: func(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
			return interaction.Step{Prompt: &interaction.Prompt{
				Type: "consent.scope",
				Data: interaction.ConsentScopePromptData{},
			}}, nil
		},
		continueFn: func(_ context.Context, _ op.ContinueInput) (interaction.Step, error) {
			return interaction.Step{Result: &interaction.Result{}}, nil
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
		Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef},
		Now:        fakeNow(),
	})
	if err != nil {
		t.Fatalf("second tick: %v", err)
	}
	if step.Prompt == nil || step.Prompt.Type != "consent.scope" {
		t.Fatalf("expected consent prompt, got %+v", step.Prompt)
	}
	st, step, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef},
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
		Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef},
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

// TestTickFactorScratchRoundtrip verifies that a per-factor Scratch
// payload returned from Authenticator.Begin survives the orchestrator's
// state encoding and is delivered back to Authenticator.Continue
// through ContinueInput.Scratch on the matching submission. The
// fixture also asserts that a successful Result clears State.FactorScratch
// so a subsequent factor cannot accidentally inherit the stale slot.
//
// Tracks: CVE-2026-28787 (OneUptime) — a WebAuthn ceremony challenge was
// handed to the client and accepted back at verification, so a captured
// assertion replayed for as long as the attacker cared to retry. This
// test pins the half of the defence that makes a ceremony single-use:
// the per-ceremony blob lives only in server-side state, and the slot is
// cleared the moment the factor produces a Result, so the same challenge
// is never presented to a second verification.
func TestTickFactorScratchRoundtrip(t *testing.T) {
	t.Parallel()

	wantScratch := []byte("session-blob-v1")
	var seenContinueScratch []byte
	pk := &stubAuthenticator{
		typeID:  op.FactorPasskey,
		aal:     op.AAL2,
		amr:     "hwk",
		prompts: []string{"auth.passkey"},
		beginFn: func(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
			return interaction.Step{
				Prompt:  &interaction.Prompt{Type: "auth.passkey", Data: interaction.PasskeyPromptData{Challenge: []byte("c")}},
				Scratch: wantScratch,
			}, nil
		},
		continueFn: func(_ context.Context, in op.ContinueInput) (interaction.Step, error) {
			seenContinueScratch = append([]byte(nil), in.Scratch...)
			return interaction.Step{Result: &interaction.Result{Subject: "user-1", AuthTime: fakeNow()}}, nil
		},
	}
	o, err := authn.New(authn.Config{
		Authenticators: []op.Authenticator{pk},
		StateRefSigner: newSigner(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	st0 := initialState()
	st0.Subject = "user-1"

	st, step, err := o.Tick(context.Background(), st0, authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("first Tick: %v", err)
	}
	if step.Prompt == nil {
		t.Fatalf("expected Prompt, got %+v", step)
	}
	if !bytes.Equal(st.FactorScratch, wantScratch) {
		t.Errorf("State.FactorScratch = %q, want %q", st.FactorScratch, wantScratch)
	}

	st, step, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"response": "x"}},
		Now:        fakeNow(),
	})
	if err != nil {
		t.Fatalf("second Tick: %v", err)
	}
	if step.Result == nil {
		t.Fatalf("expected Result, got %+v", step)
	}
	if !bytes.Equal(seenContinueScratch, wantScratch) {
		t.Errorf("ContinueInput.Scratch = %q, want %q", seenContinueScratch, wantScratch)
	}
	if len(st.FactorScratch) != 0 {
		t.Errorf("State.FactorScratch = %q, want empty after factor success", st.FactorScratch)
	}
}

// TestTickMultiStepFactorWrongCodeReShowsVerifyStep pins M-3 on the
// legacy chain: a multi-step factor (send screen -> verify screen, as
// email-OTP) that returns its verify prompt alongside ErrFactorRetry on
// a wrong guess is re-shown the VERIFY prompt with its scratch preserved,
// rather than restarted at the send screen. A restart would discard the
// still-valid delivered code and burn the resend budget. The final
// correct-code submission proves Continue kept seeing the verify scratch.
func TestTickMultiStepFactorWrongCodeReShowsVerifyStep(t *testing.T) {
	t.Parallel()

	const (
		sendType   = "auth.email_otp.send"
		verifyType = "auth.email_otp.verify"
	)
	verifyScratch := []byte{0x01}
	wrongCode := fmt.Errorf("emailotp: wrong code: %w", authn.ErrFactorRetry)
	var seenScratch [][]byte
	otp := &stubAuthenticator{
		typeID:  op.FactorEmailOTP,
		aal:     op.AAL2,
		amr:     "otp",
		prompts: []string{sendType, verifyType},
		beginFn: func(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
			return interaction.Step{Prompt: &interaction.Prompt{Type: sendType}}, nil
		},
		continueFn: func(_ context.Context, in op.ContinueInput) (interaction.Step, error) {
			seenScratch = append(seenScratch, append([]byte(nil), in.Scratch...))
			if len(in.Scratch) == 0 {
				// Send step: deliver the code and advance to verify.
				return interaction.Step{Prompt: &interaction.Prompt{Type: verifyType}, Scratch: verifyScratch}, nil
			}
			if in.Submission.Values["code"] == "correct" {
				return interaction.Step{Result: &interaction.Result{Subject: "user-1", AuthTime: fakeNow()}}, nil
			}
			// Wrong guess on the verify screen: re-show verify, keep scratch.
			return interaction.Step{Prompt: &interaction.Prompt{Type: verifyType}, Scratch: verifyScratch}, wrongCode
		},
	}
	o, err := authn.New(authn.Config{
		Authenticators: []op.Authenticator{otp},
		StateRefSigner: newSigner(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	st := initialState()
	st.Subject = "user-1"

	// Begin -> send prompt.
	st, step, err := o.Tick(context.Background(), st, authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("begin Tick: %v", err)
	}
	if step.Prompt == nil || step.Prompt.Type != sendType {
		t.Fatalf("expected send prompt, got %+v", step.Prompt)
	}

	// Submit email -> verify prompt, scratch stored.
	st, step, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"email": "a@b.c"}},
		Now:        fakeNow(),
	})
	if err != nil {
		t.Fatalf("send Tick: %v", err)
	}
	if step.Prompt == nil || step.Prompt.Type != verifyType {
		t.Fatalf("expected verify prompt after send, got %+v", step.Prompt)
	}
	if !bytes.Equal(st.FactorScratch, verifyScratch) {
		t.Fatalf("FactorScratch = %q, want verify scratch after send", st.FactorScratch)
	}

	// Wrong code -> RE-SHOW verify (not send), scratch preserved, counter up.
	st, step, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"code": "000000"}},
		Now:        fakeNow(),
	})
	if err != nil {
		t.Fatalf("wrong-code Tick: %v", err)
	}
	if step.Prompt == nil || step.Prompt.Type != verifyType {
		t.Fatalf("wrong code must re-show verify prompt, got %+v", step.Prompt)
	}
	if !bytes.Equal(st.FactorScratch, verifyScratch) {
		t.Fatalf("FactorScratch = %q, want verify scratch preserved on retry", st.FactorScratch)
	}
	if st.LastFailures != 1 {
		t.Errorf("LastFailures = %d, want 1", st.LastFailures)
	}

	// Correct code on the still-live verify step -> success.
	_, step, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"code": "correct"}},
		Now:        fakeNow(),
	})
	if err != nil {
		t.Fatalf("correct-code Tick: %v", err)
	}
	if step.Result == nil || step.Result.Subject != "user-1" {
		t.Fatalf("expected success Result, got %+v", step)
	}
	// The factor never returned to the send step: every Continue after the
	// first saw the verify scratch (the retry did not reset it to empty).
	if len(seenScratch) != 3 {
		t.Fatalf("Continue calls = %d, want 3", len(seenScratch))
	}
	for i, s := range seenScratch[1:] {
		if !bytes.Equal(s, verifyScratch) {
			t.Errorf("Continue #%d scratch = %q, want verify scratch", i+2, s)
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
		beginFn: func(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
			return interaction.Step{Prompt: &prompt}, nil
		},
		continueFn: func(_ context.Context, _ op.ContinueInput) (interaction.Step, error) {
			return interaction.Step{Result: &interaction.Result{Subject: "user-1", AuthTime: fakeNow()}}, nil
		},
	}
}

// uvReportingAuthenticator is a stubAuthenticator variant that
// implements [authn.UserVerificationReporter]. The UV bit is set per
// instance so a single test can exercise both the "real UV true" and
// "real UV false" branches without sharing state.
type uvReportingAuthenticator struct {
	*stubAuthenticator
	uv bool
}

func (u *uvReportingAuthenticator) LastUserVerified(_ string) bool { return u.uv }

// TestTickPasskeyUVThreading asserts the orchestrator's appendFactor
// path reads the assertion's real UV bit when the authenticator
// implements [authn.UserVerificationReporter] rather than deriving UV
// from the static AMR string.
func TestTickPasskeyUVThreading(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		uv   bool
		want string
	}{
		{name: "uv-true", uv: true, want: "hwk"},
		{name: "uv-false", uv: false, want: "swk"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pk := &uvReportingAuthenticator{
				stubAuthenticator: &stubAuthenticator{
					typeID:  op.FactorPasskey,
					aal:     op.AAL2,
					amr:     "hwk",
					prompts: []string{"auth.passkey"},
					beginFn: func(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
						return interaction.Step{Prompt: &interaction.Prompt{
							Type: "auth.passkey",
							Data: interaction.PasskeyPromptData{Challenge: []byte("c")},
						}}, nil
					},
					continueFn: func(_ context.Context, in op.ContinueInput) (interaction.Step, error) {
						return interaction.Step{Result: &interaction.Result{Subject: "user-uv", AuthTime: in.AuthTime}}, nil
					},
				},
				uv: tc.uv,
			}
			o, err := authn.New(authn.Config{
				Authenticators: []op.Authenticator{pk},
				StateRefSigner: newSigner(t),
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			st := initialState()
			st.Subject = "user-uv"
			st1, step, err := o.Tick(context.Background(), st, authn.Input{Now: fakeNow()})
			if err != nil {
				t.Fatalf("first Tick: %v", err)
			}
			st2, _, err := o.Tick(context.Background(), st1, authn.Input{
				Submission: &interaction.FormSubmission{StateRef: step.Prompt.StateRef, Values: map[string]string{"response": "{}"}},
				Now:        fakeNow(),
			})
			if err != nil {
				t.Fatalf("second Tick: %v", err)
			}
			if len(st2.Factors) != 1 {
				t.Fatalf("Factors=%d want 1", len(st2.Factors))
			}
			if st2.Factors[0].UserVerified != tc.uv {
				t.Errorf("Factors[0].UserVerified = %v, want %v", st2.Factors[0].UserVerified, tc.uv)
			}
			if got := st2.Factors[0].AMRValue(); got != tc.want {
				t.Errorf("AMRValue() = %q, want %q", got, tc.want)
			}
		})
	}
}

// promptForFactor returns a canonical Prompt for a built-in factor
// type. Tests that exercise custom factor types (e.g.,
// "myorg.custom") receive a generic password-shaped prompt; the
// orchestrator does not validate the prompt namespace.
func promptForFactor(t op.FactorType) interaction.Prompt {
	switch t {
	case op.FactorPassword:
		return interaction.Prompt{Type: "auth.password", Data: interaction.PasswordPromptData{}}
	case op.FactorTOTP:
		return interaction.Prompt{Type: "auth.totp", Data: interaction.TOTPPromptData{}}
	case op.FactorPasskey:
		return interaction.Prompt{Type: "auth.passkey", Data: interaction.PasskeyPromptData{Challenge: []byte("c")}}
	case op.FactorRecoveryCode:
		return interaction.Prompt{Type: "auth.recovery_code", Data: interaction.RecoveryCodePromptData{}}
	case op.FactorEmailOTP:
		return interaction.Prompt{Type: "auth.email_otp.send", Data: interaction.EmailOTPSendPromptData{}}
	default:
		return interaction.Prompt{Type: "auth.password", Data: interaction.PasswordPromptData{}}
	}
}
