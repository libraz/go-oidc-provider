package authn_test

import (
	"context"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

// widgetCaptcha is a verifier that also describes its upstream widget,
// which is the seam an SPA needs to bootstrap the provider's challenge.
type widgetCaptcha struct {
	provider string
	siteKey  string
}

func (widgetCaptcha) Verify(_ context.Context, _ op.CaptchaInput) error { return nil }

func (c widgetCaptcha) CaptchaWidget() (string, string) { return c.provider, c.siteKey }

var _ authn.CaptchaWidgetDescriber = widgetCaptcha{}

// plainCaptcha verifies without describing a widget — the shape every
// existing embedder verifier has.
type plainCaptcha struct{}

func (plainCaptcha) Verify(_ context.Context, _ op.CaptchaInput) error { return nil }

// TestCaptchaPrompt_CarriesWidgetFromVerifier pins the data an SPA
// needs on the after-N-failures captcha prompt. Before the widget
// seam existed the prompt shipped a zero-valued CaptchaPromptData, so a
// front end had no provider identifier and no site key and could not
// construct the challenge at all — the shipped reference bundle's
// provider branch was unreachable.
func TestCaptchaPrompt_CarriesWidgetFromVerifier(t *testing.T) {
	t.Parallel()

	pw := successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")
	o, err := authn.New(authn.Config{
		LoginFlow:      captchaFlow(t, pw, widgetCaptcha{provider: "turnstile", siteKey: "0xSITEKEY"}),
		StateRefSigner: newSigner(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Drive past the rule's failure threshold so the captcha step emits
	// its prompt.
	st := initialState()
	st.LastFailures = 99

	_, step, err := o.Tick(context.Background(), st, authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if step.Prompt == nil || step.Prompt.Type != "captcha" {
		t.Fatalf("expected the captcha prompt, got %+v", step)
	}
	data, ok := step.Prompt.Data.(interaction.CaptchaPromptData)
	if !ok {
		t.Fatalf("prompt data = %T, want interaction.CaptchaPromptData", step.Prompt.Data)
	}
	if data.Provider != "turnstile" || data.SiteKey != "0xSITEKEY" {
		t.Errorf("prompt data = %+v, want provider=turnstile sitekey=0xSITEKEY; "+
			"without both the SPA cannot bootstrap the upstream widget", data)
	}
}

// TestCaptchaPrompt_EmptyWidgetWhenVerifierDoesNotDescribeOne pins the
// opt-in half of the contract: a verifier that predates the seam keeps
// working and emits an empty descriptor, which a driver rendering its
// own challenge UI reads as "render your own".
func TestCaptchaPrompt_EmptyWidgetWhenVerifierDoesNotDescribeOne(t *testing.T) {
	t.Parallel()

	pw := successAuth(op.FactorPassword, op.AAL1, "pwd", "user-1")
	o, err := authn.New(authn.Config{
		LoginFlow:      captchaFlow(t, pw, plainCaptcha{}),
		StateRefSigner: newSigner(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	st := initialState()
	st.LastFailures = 99

	_, step, err := o.Tick(context.Background(), st, authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	data, ok := step.Prompt.Data.(interaction.CaptchaPromptData)
	if !ok {
		t.Fatalf("prompt data = %T, want interaction.CaptchaPromptData", step.Prompt.Data)
	}
	if data.Provider != "" || data.SiteKey != "" {
		t.Errorf("prompt data = %+v, want both empty for a verifier that describes no widget", data)
	}
}
