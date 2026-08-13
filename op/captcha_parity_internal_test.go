package op

import (
	"context"
	"net/netip"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

// recordingCaptcha captures the CaptchaInput it was handed and
// describes an upstream widget, so one fixture covers both halves of
// the captcha parity contract.
type recordingCaptcha struct {
	seen CaptchaInput
}

func (c *recordingCaptcha) Verify(_ context.Context, in CaptchaInput) error {
	c.seen = in
	return nil
}

func (c *recordingCaptcha) CaptchaWidget() (string, string) { return "hcaptcha", "site-key-42" }

// TestStepCaptcha_PromptCarriesWidget pins the StepCaptcha emission
// point against the same contract the threshold-triggered path honours.
// The two prompts are rendered by one SPA, which cannot tell which path
// produced the one it received, so a descriptor present on one and
// absent on the other is a widget that fails to load on some logins.
func TestStepCaptcha_PromptCarriesWidget(t *testing.T) {
	t.Parallel()

	step, err := projectStepToFlow("Rules[0].Then", StepCaptcha{Verifier: &recordingCaptcha{}}, &config{})
	if err != nil {
		t.Fatalf("projectStepToFlow: %v", err)
	}
	begun, err := step.Authenticator.Begin(context.Background(), authn.BeginInput{})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if begun.Prompt == nil {
		t.Fatalf("Begin returned no prompt: %+v", begun)
	}
	data, ok := begun.Prompt.Data.(interaction.CaptchaPromptData)
	if !ok {
		t.Fatalf("prompt data = %T, want interaction.CaptchaPromptData", begun.Prompt.Data)
	}
	if data.Provider != "hcaptcha" || data.SiteKey != "site-key-42" {
		t.Errorf("prompt data = %+v, want provider=hcaptcha sitekey=site-key-42", data)
	}
}

// TestStepCaptcha_VerifierReceivesRemoteIP pins the input half of the
// same parity. A captcha verifier's whole job is to ask the upstream
// provider whether a token is good, and every major provider scores the
// client address as part of that answer. The StepCaptcha adapter used to
// hand over the token alone, so the identical verifier got a weaker
// signal depending on which path challenged the user.
func TestStepCaptcha_VerifierReceivesRemoteIP(t *testing.T) {
	t.Parallel()

	verifier := &recordingCaptcha{}
	step, err := projectStepToFlow("Rules[0].Then", StepCaptcha{Verifier: verifier}, &config{})
	if err != nil {
		t.Fatalf("projectStepToFlow: %v", err)
	}
	addr := netip.MustParseAddr("198.51.100.7")
	if _, err := step.Authenticator.Continue(context.Background(), authn.ContinueInput{
		Submission: interaction.FormSubmission{
			Values: map[string]string{CaptchaSubmissionFieldName: "token-abc"},
		},
		RemoteIP: addr,
	}); err != nil {
		t.Fatalf("Continue: %v", err)
	}
	if verifier.seen.Token != "token-abc" {
		t.Errorf("Token = %q, want token-abc", verifier.seen.Token)
	}
	if verifier.seen.RemoteIP != addr {
		t.Errorf("RemoteIP = %v, want %v; the verifier cannot score the client without it",
			verifier.seen.RemoteIP, addr)
	}
}
