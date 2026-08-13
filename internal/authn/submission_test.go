package authn_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

// spyFactor is an op.Authenticator that records every dispatch it
// receives. The invariant these tests pin is a negative one — a
// submission the prompt's own [interaction.FieldSpec] list rules out
// never reaches the factor — so the counters have to be observable
// independently of the Step the orchestrator returns. A factor that
// merely rejected the bad value itself would satisfy the error
// assertion while leaving the value in front of embedder code.
type spyFactor struct {
	prompt interaction.Prompt

	mu       sync.Mutex
	receives int
}

func (s *spyFactor) Type() op.FactorType { return op.FactorPassword }
func (s *spyFactor) AAL() op.AAL         { return op.AAL1 }
func (s *spyFactor) AMR() string         { return "pwd" }
func (s *spyFactor) Prompts() []string   { return []string{s.prompt.Type} }

func (s *spyFactor) Begin(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
	prompt := s.prompt
	return interaction.Step{Prompt: &prompt}, nil
}

func (s *spyFactor) Continue(_ context.Context, _ op.ContinueInput) (interaction.Step, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.receives++
	return interaction.Step{Result: &interaction.Result{Subject: "user-1", AuthTime: fakeNow()}}, nil
}

func (s *spyFactor) continueCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.receives
}

// otpFieldPrompt is the prompt shape the rejection tests run against: a
// single six-byte one-time code, the tightest constraint set a built-in
// factor declares.
func otpFieldPrompt(pattern string) interaction.Prompt {
	return interaction.Prompt{
		Type: "auth.password",
		Data: interaction.PasswordPromptData{},
		Inputs: []interaction.FieldSpec{{
			Name:     "code",
			Kind:     interaction.FieldOTPCode,
			Label:    "auth.totp.code",
			Required: true,
			MinLen:   6,
			MaxLen:   6,
			Pattern:  pattern,
		}},
	}
}

// TestTickRejectsSubmissionViolatingFieldSpec covers the constraints
// [interaction.FieldSpec] declares, one violation per case. Each asserts
// the same two things: the tick fails with [authn.ErrSubmissionRejected],
// and the authenticator's Continue was never entered. The second is the
// point of the feature — the documented contract is that an
// Authenticator only has to validate beyond the FieldSpec constraints,
// which holds only if the orchestrator refuses first.
func TestTickRejectsSubmissionViolatingFieldSpec(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		pattern string
		values  map[string]string
	}{
		{
			name:   "value longer than MaxLen",
			values: map[string]string{"code": strings.Repeat("1", 32*1024)},
		},
		{
			name:   "value shorter than MinLen",
			values: map[string]string{"code": "12345"},
		},
		{
			name:   "required field submitted empty",
			values: map[string]string{"code": ""},
		},
		{
			name:   "required field omitted",
			values: map[string]string{},
		},
		{
			name:    "value does not match Pattern",
			pattern: `[0-9]{6}`,
			values:  map[string]string{"code": "12345x"},
		},
		{
			// An unanchored pattern must not accept a conforming
			// substring buried in other input; Go's regexp is
			// unanchored by default, so this is the case that proves
			// the orchestrator applies the pattern as a full match.
			name:    "value only contains a Pattern match",
			pattern: `[0-9]{2}`,
			values:  map[string]string{"code": "ab12cd"},
		},
		{
			// A pattern the embedder mistyped must fail closed. The
			// alternative — skipping an uncompilable pattern — turns a
			// config typo into an unvalidated field.
			name:    "Pattern does not compile",
			pattern: `[0-9`,
			values:  map[string]string{"code": "123456"},
		},
		{
			name: "more fields than the prompt declared",
			values: map[string]string{
				"code": "123456",
				"a":    "1", "b": "2", "c": "3", "d": "4", "e": "5",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			spy := &spyFactor{prompt: otpFieldPrompt(tc.pattern)}
			o, err := authn.New(authn.Config{
				Authenticators: []op.Authenticator{spy},
				StateRefSigner: newSigner(t),
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			st, step, err := o.Tick(context.Background(), initialState(), authn.Input{Now: fakeNow()})
			if err != nil {
				t.Fatalf("first Tick: %v", err)
			}
			if step.Prompt == nil {
				t.Fatalf("expected a prompt, got %+v", step)
			}

			_, step, err = o.Tick(context.Background(), st, authn.Input{
				Submission: &interaction.FormSubmission{
					StateRef: step.Prompt.StateRef,
					Values:   tc.values,
				},
				Now: fakeNow(),
			})
			if got := spy.continueCalls(); got != 0 {
				t.Errorf("Authenticator.Continue ran %d time(s); the orchestrator must reject first", got)
			}
			if !errors.Is(err, authn.ErrSubmissionRejected) {
				t.Fatalf("Tick error = %v, want ErrSubmissionRejected", err)
			}
			// The HTTP layer dispatches on ErrFactorAbort to render a
			// 4xx; a submission that cannot have come from the rendered
			// form is a client fault, not a server fault.
			if !errors.Is(err, authn.ErrFactorAbort) {
				t.Errorf("ErrSubmissionRejected must wrap ErrFactorAbort, got %v", err)
			}
			if step.Prompt != nil || step.Result != nil {
				t.Errorf("rejected submission produced a Step: %+v", step)
			}
		})
	}
}

// TestTickAcceptsConformingSubmission is the positive control for the
// table above: the same prompt with a value that satisfies every
// declared constraint reaches the authenticator unchanged. Without it a
// validator that rejected everything would still pass the rejection
// cases.
func TestTickAcceptsConformingSubmission(t *testing.T) {
	t.Parallel()

	spy := &spyFactor{prompt: otpFieldPrompt(`[0-9]{6}`)}
	o, err := authn.New(authn.Config{
		Authenticators: []op.Authenticator{spy},
		StateRefSigner: newSigner(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	st, step, err := o.Tick(context.Background(), initialState(), authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("first Tick: %v", err)
	}

	_, step, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{
			StateRef: step.Prompt.StateRef,
			// csrf_token is the transport field a server-rendered form
			// round-trips alongside the declared inputs; the field-count
			// allowance exists so it does not count as a violation.
			Values: map[string]string{"code": "123456", "csrf_token": "t"},
		},
		Now: fakeNow(),
	})
	if err != nil {
		t.Fatalf("second Tick: %v", err)
	}
	if step.Result == nil {
		t.Fatalf("expected terminal Result, got %+v", step)
	}
	if got := spy.continueCalls(); got != 1 {
		t.Errorf("Authenticator.Continue ran %d time(s), want 1", got)
	}
}

// TestTickValidatesInteractionSubmission pins the same gate on the
// Interaction dispatch path. The three submission routes share one
// choke point precisely so a route cannot drift; the test fails if the
// interaction branch ever grows its own dispatch.
func TestTickValidatesInteractionSubmission(t *testing.T) {
	t.Parallel()

	var continues int
	ix := &stubInteraction{
		name:    "myorg.gate",
		trigger: op.TriggerBeforeAuthn,
		beginFn: func(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
			return interaction.Step{Prompt: &interaction.Prompt{
				Type: "myorg.gate",
				Inputs: []interaction.FieldSpec{{
					Name:     "acknowledgement",
					Kind:     interaction.FieldText,
					Required: true,
					MaxLen:   6,
				}},
			}}, nil
		},
		continueFn: func(_ context.Context, _ op.ContinueInput) (interaction.Step, error) {
			continues++
			return interaction.Step{Result: &interaction.Result{}}, nil
		},
	}
	pw := buildSuccessAuthenticator(op.FactorPassword, op.AAL1, "pwd")
	o, err := authn.New(authn.Config{
		Authenticators: []op.Authenticator{pw},
		Interactions:   []op.Interaction{ix},
		StateRefSigner: newSigner(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	st, step, err := o.Tick(context.Background(), initialState(), authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("first Tick: %v", err)
	}
	if step.Prompt == nil || step.Prompt.Type != "myorg.gate" {
		t.Fatalf("expected the interaction prompt, got %+v", step)
	}

	_, _, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{
			StateRef: step.Prompt.StateRef,
			Values:   map[string]string{"acknowledgement": strings.Repeat("y", 32*1024)},
		},
		Now: fakeNow(),
	})
	if continues != 0 {
		t.Errorf("Interaction.Continue ran %d time(s); the orchestrator must reject first", continues)
	}
	if !errors.Is(err, authn.ErrSubmissionRejected) {
		t.Fatalf("Tick error = %v, want ErrSubmissionRejected", err)
	}
}

// TestTickValidatesLoginFlowSubmission pins the gate on the LoginFlow
// dispatch path, the third route into an authenticator.
func TestTickValidatesLoginFlowSubmission(t *testing.T) {
	t.Parallel()

	spy := &spyFactor{prompt: otpFieldPrompt("")}
	flow, err := authn.CompileLoginFlow(authn.LoginFlowSpec{
		Primary: authn.LoginFlowStep{Kind: "myorg.code", Authenticator: spy},
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
	if step.Prompt == nil {
		t.Fatalf("expected a prompt, got %+v", step)
	}

	_, _, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{
			StateRef: step.Prompt.StateRef,
			Values:   map[string]string{"code": strings.Repeat("1", 32*1024)},
		},
		Now: fakeNow(),
	})
	if got := spy.continueCalls(); got != 0 {
		t.Errorf("Authenticator.Continue ran %d time(s); the orchestrator must reject first", got)
	}
	if !errors.Is(err, authn.ErrSubmissionRejected) {
		t.Fatalf("Tick error = %v, want ErrSubmissionRejected", err)
	}
}

// TestTickValidatesAgainstIssuedPromptOnly asserts the constraints come
// from the prompt the orchestrator issued rather than from anything the
// client can influence. The submission carries a value that is legal for
// the second factor's field but illegal for the first factor's — the one
// actually outstanding — and must be refused.
func TestTickValidatesAgainstIssuedPromptOnly(t *testing.T) {
	t.Parallel()

	spy := &spyFactor{prompt: otpFieldPrompt("")}
	o, err := authn.New(authn.Config{
		Authenticators: []op.Authenticator{spy},
		StateRefSigner: newSigner(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	st, step, err := o.Tick(context.Background(), initialState(), authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("first Tick: %v", err)
	}
	if len(st.ActiveInputs) != 1 || st.ActiveInputs[0].Name != "code" {
		t.Fatalf("State.ActiveInputs = %+v, want the issued prompt's field list", st.ActiveInputs)
	}

	// Mutating the list the authenticator returned must not relax the
	// bound: the orchestrator validates against its own copy.
	step.Prompt.Inputs[0].MaxLen = 32 * 1024

	_, _, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{
			StateRef: step.Prompt.StateRef,
			Values:   map[string]string{"code": strings.Repeat("1", 1024)},
		},
		Now: fakeNow(),
	})
	if got := spy.continueCalls(); got != 0 {
		t.Errorf("Authenticator.Continue ran %d time(s); the orchestrator must reject first", got)
	}
	if !errors.Is(err, authn.ErrSubmissionRejected) {
		t.Fatalf("Tick error = %v, want ErrSubmissionRejected", err)
	}
}
