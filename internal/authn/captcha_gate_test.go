package authn_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

// captchaMaxFailuresForTest mirrors the orchestrator's internal
// captchaMaxFailures constant. It is redeclared here because the
// constant is unexported and the test lives in the _test package.
const captchaMaxFailuresForTest = 5

// buildCaptchaOrchestrator wires a chain of one always-succeeding
// password factor behind the supplied verifier, with the failure
// counter already at the captcha threshold so the very first Tick
// emits the challenge.
func buildCaptchaOrchestrator(t *testing.T, verify func(context.Context, op.CaptchaInput) error) (*authn.Orchestrator, authn.State) {
	t.Helper()
	o, err := authn.New(authn.Config{
		Authenticators: []op.Authenticator{
			buildSuccessAuthenticator(op.FactorPassword, op.AAL1, "pwd"),
		},
		Captcha:        &stubCaptcha{verify: verify},
		StateRefSigner: newSigner(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	st := initialState()
	st.LastFailures = captchaFailureThresholdForTest
	return o, st
}

// TestCaptchaPromptDeclaresTokenField pins the field contract between
// the orchestrator and every driver: the captcha prompt MUST advertise
// the input the provider's token is submitted under. A prompt with an
// empty Inputs list gives a SPA (and the built-in HTML driver) nowhere
// to put the token, so the challenge can never be answered and the
// chain never leaves the gate.
func TestCaptchaPromptDeclaresTokenField(t *testing.T) {
	t.Parallel()

	o, st := buildCaptchaOrchestrator(t, func(context.Context, op.CaptchaInput) error { return nil })

	_, step, err := o.Tick(context.Background(), st, authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("captcha Tick: %v", err)
	}
	if step.Prompt == nil || step.Prompt.Type != "captcha" {
		t.Fatalf("expected captcha prompt, got %+v", step.Prompt)
	}
	var found *interaction.FieldSpec
	for i := range step.Prompt.Inputs {
		if step.Prompt.Inputs[i].Name == authn.CaptchaTokenField {
			found = &step.Prompt.Inputs[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("captcha prompt Inputs = %+v, want a %q field", step.Prompt.Inputs, authn.CaptchaTokenField)
	}
	if !found.Required {
		t.Error("captcha token field must be Required")
	}
	if found.MaxLen <= 0 {
		t.Error("captcha token field must carry a MaxLen bound")
	}
}

// TestCaptchaTokenReadFromSubmission is the regression for a captcha
// gate that no driver could clear: the verifier must receive the token
// the SPA posted under [authn.CaptchaTokenField], not an empty string.
func TestCaptchaTokenReadFromSubmission(t *testing.T) {
	t.Parallel()

	var seen []string
	o, st := buildCaptchaOrchestrator(t, func(_ context.Context, in op.CaptchaInput) error {
		seen = append(seen, in.Token)
		if in.Token != "provider-token" {
			return errors.New("token invalid")
		}
		return nil
	})

	st, captchaStep, err := o.Tick(context.Background(), st, authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("captcha Tick: %v", err)
	}

	next, step, err := o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{
			StateRef: captchaStep.Prompt.StateRef,
			Values:   map[string]string{authn.CaptchaTokenField: "provider-token"},
		},
		Now: fakeNow(),
	})
	if err != nil {
		t.Fatalf("post-captcha Tick: %v", err)
	}
	if len(seen) != 1 || seen[0] != "provider-token" {
		t.Fatalf("verifier saw tokens %q, want exactly [provider-token]", seen)
	}
	if !next.CaptchaPassed {
		t.Error("CaptchaPassed = false after a valid token")
	}
	if step.Prompt == nil || step.Prompt.Type != "auth.password" {
		t.Fatalf("expected the chain to reach the password prompt, got %+v", step.Prompt)
	}
}

// TestCaptchaFailureAdvancesCounter asserts a rejected token advances
// [authn.State.CaptchaFailures] while leaving the brute-force feed
// ([authn.State.LastFailures]) untouched — captcha is deliberately
// out-of-band from that counter.
func TestCaptchaFailureAdvancesCounter(t *testing.T) {
	t.Parallel()

	o, st := buildCaptchaOrchestrator(t, func(context.Context, op.CaptchaInput) error {
		return errors.New("token invalid")
	})
	wantLastFailures := st.LastFailures

	st, captchaStep, err := o.Tick(context.Background(), st, authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("captcha Tick: %v", err)
	}

	next, step, err := o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{
			StateRef: captchaStep.Prompt.StateRef,
			Values:   map[string]string{authn.CaptchaTokenField: "rejected"},
		},
		Now: fakeNow(),
	})
	if err != nil {
		t.Fatalf("rejected-token Tick: %v", err)
	}
	if step.Prompt == nil || step.Prompt.Type != "captcha" {
		t.Fatalf("expected the captcha prompt to be re-emitted, got %+v", step.Prompt)
	}
	if next.CaptchaFailures != 1 {
		t.Errorf("CaptchaFailures = %d, want 1", next.CaptchaFailures)
	}
	if next.LastFailures != wantLastFailures {
		t.Errorf("LastFailures = %d, want %d (captcha must not feed the brute-force counter)",
			next.LastFailures, wantLastFailures)
	}
	if next.CaptchaPassed {
		t.Error("CaptchaPassed = true after a rejected token")
	}
}

// TestCaptchaInterposesOnLegacySoftRetry is the regression for a gate a
// credential-stuffing loop never reached: on the legacy Authenticators
// chain the soft-retry path re-emitted the factor's prompt directly, so
// the captcha decision — which lives in the chain dispatcher — only ran
// when the browser re-entered through a fresh advance. An attacker
// posting submission after submission against the same prompt never
// re-enters, so the threshold could be crossed arbitrarily far without
// a challenge ever appearing. The miss that reaches the threshold MUST
// answer with the captcha, without a reload.
func TestCaptchaInterposesOnLegacySoftRetry(t *testing.T) {
	t.Parallel()

	wrongPassword := fmt.Errorf("password: invalid credentials: %w", authn.ErrFactorRetry)
	pw := &stubAuthenticator{
		typeID:  op.FactorPassword,
		aal:     op.AAL1,
		amr:     "pwd",
		prompts: []string{"auth.password"},
		beginFn: func(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
			return interaction.Step{Prompt: passwordPrompt()}, nil
		},
		continueFn: func(_ context.Context, _ op.ContinueInput) (interaction.Step, error) {
			return interaction.Step{}, wrongPassword
		},
	}
	o, err := authn.New(authn.Config{
		Authenticators: []op.Authenticator{pw},
		Captcha:        &stubCaptcha{verify: func(context.Context, op.CaptchaInput) error { return nil }},
		StateRefSigner: newSigner(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	st, step, err := o.Tick(context.Background(), initialState(), authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("begin Tick: %v", err)
	}
	if step.Prompt == nil || step.Prompt.Type != "auth.password" {
		t.Fatalf("expected password prompt, got %+v", step.Prompt)
	}

	// Every miss answers the prompt the previous response carried — the
	// SPA never reloads the interaction.
	var stalePasswordRef string
	for miss := 1; miss <= captchaFailureThresholdForTest; miss++ {
		stalePasswordRef = step.Prompt.StateRef
		st, step, err = o.Tick(context.Background(), st, authn.Input{
			Submission: &interaction.FormSubmission{
				StateRef: stalePasswordRef,
				Values:   map[string]string{"password": "guess"},
			},
			Now: fakeNow(),
		})
		if err != nil {
			t.Fatalf("miss %d: %v", miss, err)
		}
		want := "auth.password"
		if miss >= captchaFailureThresholdForTest {
			want = "captcha"
		}
		if step.Prompt == nil || step.Prompt.Type != want {
			t.Fatalf("miss %d: prompt = %+v, want type %q", miss, step.Prompt, want)
		}
	}
	if st.LastFailures != captchaFailureThresholdForTest {
		t.Errorf("LastFailures = %d, want %d", st.LastFailures, captchaFailureThresholdForTest)
	}
	if st.ActiveFactorIdx != -1 {
		t.Errorf("ActiveFactorIdx = %d, want -1 once the factor is retired behind the challenge", st.ActiveFactorIdx)
	}

	// The factor's outstanding StateRef is retired by the challenge, so
	// the attacker cannot keep guessing against the token they already
	// hold while the captcha is pending.
	if _, _, rerr := o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{
			StateRef: stalePasswordRef,
			Values:   map[string]string{"password": "guess"},
		},
		Now: fakeNow(),
	}); !errors.Is(rerr, authn.ErrInvalidStateRef) {
		t.Errorf("replay of the pre-captcha factor token: err = %v, want ErrInvalidStateRef", rerr)
	}

	// Solving the challenge returns the chain to the factor.
	next, resumed, err := o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{
			StateRef: step.Prompt.StateRef,
			Values:   map[string]string{authn.CaptchaTokenField: "provider-token"},
		},
		Now: fakeNow(),
	})
	if err != nil {
		t.Fatalf("captcha solve Tick: %v", err)
	}
	if !next.CaptchaPassed {
		t.Error("CaptchaPassed = false after a valid token")
	}
	if resumed.Prompt == nil || resumed.Prompt.Type != "auth.password" {
		t.Fatalf("expected the chain to resume at the password prompt, got %+v", resumed.Prompt)
	}
}

// TestCaptchaFailuresAbortTheChain pins the liveness bound: a verifier
// that rejects every token must not leave the user cycling through the
// same challenge forever. Once the failure count reaches the ceiling
// the chain terminates with [authn.ErrCaptchaExhausted], which wraps
// [authn.ErrFactorAbort] so the HTTP layer renders a 4xx.
func TestCaptchaFailuresAbortTheChain(t *testing.T) {
	t.Parallel()

	o, st := buildCaptchaOrchestrator(t, func(context.Context, op.CaptchaInput) error {
		return errors.New("token invalid")
	})

	st, step, err := o.Tick(context.Background(), st, authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("captcha Tick: %v", err)
	}

	for attempt := 1; attempt <= captchaMaxFailuresForTest; attempt++ {
		next, retry, terr := o.Tick(context.Background(), st, authn.Input{
			Submission: &interaction.FormSubmission{
				StateRef: step.Prompt.StateRef,
				Values:   map[string]string{authn.CaptchaTokenField: "rejected"},
			},
			Now: fakeNow(),
		})
		if attempt == captchaMaxFailuresForTest {
			if !errors.Is(terr, authn.ErrCaptchaExhausted) {
				t.Fatalf("attempt %d: err = %v, want ErrCaptchaExhausted", attempt, terr)
			}
			if !errors.Is(terr, authn.ErrFactorAbort) {
				t.Errorf("ErrCaptchaExhausted must wrap ErrFactorAbort")
			}
			if next.CaptchaFailures != captchaMaxFailuresForTest {
				t.Errorf("CaptchaFailures = %d, want %d", next.CaptchaFailures, captchaMaxFailuresForTest)
			}
			return
		}
		if terr != nil {
			t.Fatalf("attempt %d: %v", attempt, terr)
		}
		if retry.Prompt == nil || retry.Prompt.Type != "captcha" {
			t.Fatalf("attempt %d: expected a re-emitted captcha prompt, got %+v", attempt, retry.Prompt)
		}
		st, step = next, retry
	}
}
