package authorizeendpoint_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// failingExternal is the credential factor with a Continue that always
// reports failure through err, as an embedder's own factor would.
type failingExternal struct {
	passwordEchoAuthenticator
	err error
}

func (f failingExternal) Continue(context.Context, op.ContinueInput) (interaction.Step, error) {
	return interaction.Step{}, f.err
}

// externalSentinelPrompt starts an attempt whose Primary is an ExternalStep
// failing with err, submits one credential and returns that response.
func externalSentinelPrompt(t *testing.T, err error, rules ...op.Rule) (*reauthDriver, *http.Response, promptStep) {
	t.Helper()
	clock := newMovableClock(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	flow := op.WithLoginFlow(op.LoginFlow{
		Primary: op.ExternalStep{
			Authenticator: failingExternal{passwordEchoAuthenticator{clock: clock}, err},
			KindLabel:     op.StepKind("test.primary"),
		},
		Rules: rules,
	})
	d := newReauthDriver(t, buildFlowFixture(t, "LoginFlow+ExternalSentinel", clock, flow))
	login := d.authorize(map[string][]string{"scope": {"openid"}})
	env, csrf := d.firstPrompt(login.Path)
	ref, _ := env["state_ref"].(string)
	resp := d.submit(login.Path, csrf, ref, map[string]string{testkit.SubjectFieldName: reauthSubject})
	return d, resp, promptStep{env: env, stateRef: ref, csrf: csrf}
}

// TestEndToEnd_ExternalStepSentinel_RetryIsCounted pins that an external
// factor returning a wrapped op.ErrFactorRetry is recorded as a failed
// attempt: with RuleAfterFailedAttempts(1, StepCaptcha) the next prompt is
// the captcha.
func TestEndToEnd_ExternalStepSentinel_RetryIsCounted(t *testing.T) {
	t.Parallel()

	_, resp, first := externalSentinelPrompt(t,
		fmt.Errorf("upstream rejected the credential: %w", op.ErrFactorRetry),
		op.RuleAfterFailedAttempts(1, op.StepCaptcha{Verifier: &rejectingCaptcha{}}))
	defer resp.Body.Close()

	if got, _ := first.env["type"].(string); got != testkit.SubjectPromptType {
		t.Fatalf("first prompt = %q, want %q", got, testkit.SubjectPromptType)
	}
	next := nextPrompt(t, resp, first.csrf)
	if got, _ := next.env["type"].(string); got != "captcha" {
		t.Fatalf("prompt after a retry failure = %q, want captcha (the failure was not counted)", got)
	}
}

// TestEndToEnd_ExternalStepSentinel_AbortIs4xx pins that an external
// factor returning a wrapped op.ErrFactorAbort ends the attempt with a 400.
func TestEndToEnd_ExternalStepSentinel_AbortIs4xx(t *testing.T) {
	t.Parallel()

	_, resp, _ := externalSentinelPrompt(t,
		fmt.Errorf("upstream refused the attempt: %w", op.ErrFactorAbort))
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s, want 400", resp.StatusCode, dump)
	}
}
