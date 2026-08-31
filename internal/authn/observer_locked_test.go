package authn_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authn/emailotp"
	"github.com/libraz/go-oidc-provider/internal/authn/recovery"
	"github.com/libraz/go-oidc-provider/internal/authn/totp"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

// TestTickLockedFactorObservesAttemptLocked pins the reachability of the
// AttemptLocked outcome. A factor that reports the brute-force gate ended
// the attempt must produce an AttemptLocked event on the observer feed:
// an embedder driving its risk counters off this feed otherwise cannot
// tell an attack the OP has already stopped from one still in progress.
func TestTickLockedFactorObservesAttemptLocked(t *testing.T) {
	t.Parallel()

	lockedErr := fmt.Errorf("otp: factor is locked: %w", authn.ErrFactorLocked)
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
			return interaction.Step{}, lockedErr
		},
	}
	obs := &recordingObserver{}
	o, err := authn.New(authn.Config{
		Authenticators: []op.Authenticator{otp},
		Observers:      []op.LoginAttemptObserver{obs},
		StateRefSigner: newSigner(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	st := initialState()
	st.Subject = "user-1"

	st, step, err := o.Tick(context.Background(), st, authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("first Tick: %v", err)
	}
	if step.Prompt == nil {
		t.Fatal("expected the factor prompt on the first Tick")
	}

	_, _, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{
			StateRef: step.Prompt.StateRef,
			Values:   map[string]string{"code": "000000"},
		},
		Now: fakeNow(),
	})
	// A lock is terminal for the attempt, so the error reaches the caller
	// instead of being swallowed into a retry prompt.
	if !errors.Is(err, lockedErr) {
		t.Fatalf("locked Tick err = %v, want the factor's lock error", err)
	}

	events := obs.snapshot()
	if len(events) != 1 {
		t.Fatalf("observer events = %d, want exactly 1: %+v", len(events), events)
	}
	got := events[0]
	if got.Outcome != op.AttemptLocked {
		t.Errorf("Outcome = %v, want op.AttemptLocked", got.Outcome)
	}
	if got.Factor != op.FactorTOTP {
		t.Errorf("Factor = %q, want %q", got.Factor, op.FactorTOTP)
	}
	if got.Reason != "attempt.locked" {
		t.Errorf("Reason = %q, want attempt.locked", got.Reason)
	}
	// The lock confirms the account exists, so the feed withholds the
	// subject for the same reason the failure path does.
	if got.Subject != "" {
		t.Errorf("Subject = %q, want it withheld on the lock path", got.Subject)
	}
}

// TestTickRetryFactorStillObservesFailure guards the classification split:
// adding the lock verdict must not reclassify an ordinary wrong-credential
// rejection, which stays AttemptFailure and stays retryable.
func TestTickRetryFactorStillObservesFailure(t *testing.T) {
	t.Parallel()

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
	o, err := authn.New(authn.Config{
		Authenticators: []op.Authenticator{otp},
		Observers:      []op.LoginAttemptObserver{obs},
		StateRefSigner: newSigner(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	st := initialState()
	st.Subject = "user-1"

	st, step, err := o.Tick(context.Background(), st, authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("first Tick: %v", err)
	}
	if _, _, err = o.Tick(context.Background(), st, authn.Input{
		Submission: &interaction.FormSubmission{
			StateRef: step.Prompt.StateRef,
			Values:   map[string]string{"code": "000000"},
		},
		Now: fakeNow(),
	}); err != nil {
		t.Fatalf("wrong-code Tick: %v", err)
	}

	events := obs.snapshot()
	if len(events) != 1 {
		t.Fatalf("observer events = %d, want exactly 1: %+v", len(events), events)
	}
	if events[0].Outcome != op.AttemptFailure {
		t.Errorf("Outcome = %v, want op.AttemptFailure", events[0].Outcome)
	}
}

// TestFactorLockSentinelsClassifyAsLocked pins the wiring between the
// built-in factors and the classification the orchestrator performs.
// Every factor whose lock the shared counter can trigger must reach the
// observer feed as a lock, and must keep rendering as a 4xx abort.
func TestFactorLockSentinelsClassifyAsLocked(t *testing.T) {
	t.Parallel()

	cases := map[string]error{
		"totp":     totp.ErrLocked,
		"emailotp": emailotp.ErrLocked,
		"recovery": recovery.ErrLocked,
	}
	for name, err := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if !errors.Is(err, authn.ErrFactorLocked) {
				t.Errorf("%v does not wrap authn.ErrFactorLocked", err)
			}
			if !errors.Is(err, authn.ErrFactorAbort) {
				t.Errorf("%v no longer wraps authn.ErrFactorAbort", err)
			}
		})
	}
}
