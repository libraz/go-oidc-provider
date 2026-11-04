package authn

import opauthn "github.com/libraz/go-oidc-provider/op/authn"

// CaptchaTokenField is the [interaction.FormSubmission] field name the
// captcha prompt collects the upstream provider's token under. The SPA
// renders the provider's challenge widget (Cloudflare Turnstile, Google
// reCAPTCHA, hCaptcha, …) and posts the resulting token under this key;
// the orchestrator reads it straight off the submission so the HTTP
// layer never has to know the captcha wire shape.
//
//nolint:gosec // G101: a wire field name, not a credential.
const CaptchaTokenField = "captcha_token"

// CaptchaInput is the request a [CaptchaVerifier] receives.
type CaptchaInput = opauthn.CaptchaInput

// CaptchaVerifier validates a captcha token against the upstream provider.
type CaptchaVerifier = opauthn.CaptchaVerifier

// CaptchaWidgetDescriber is the optional interface a [CaptchaVerifier] may
// implement to describe the client-side widget the SPA must bootstrap.
type CaptchaWidgetDescriber = opauthn.CaptchaWidgetDescriber

// CaptchaWidgetFor reads the widget descriptor off v when it
// implements [CaptchaWidgetDescriber]. The [op.StepCaptcha] adapter
// calls it when emitting its prompt. A nil verifier yields empty
// strings.
func CaptchaWidgetFor(v CaptchaVerifier) (provider, siteKey string) {
	d, ok := v.(CaptchaWidgetDescriber)
	if !ok {
		return "", ""
	}
	return d.CaptchaWidget()
}
