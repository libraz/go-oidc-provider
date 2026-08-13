package authn

import (
	"context"
	"net/netip"
)

// CaptchaTokenField is the [interaction.FormSubmission] field name the
// captcha prompt collects the upstream provider's token under. The SPA
// renders the provider's challenge widget (Cloudflare Turnstile, Google
// reCAPTCHA, hCaptcha, …) and posts the resulting token under this key;
// the orchestrator reads it straight off the submission so the HTTP
// layer never has to know the captcha wire shape.
//
//nolint:gosec // G101: a wire field name, not a credential.
const CaptchaTokenField = "captcha_token"

// captchaTokenMaxLen caps the token bytes the captcha prompt accepts in
// a submission. Provider tokens are on the order of 2 KiB; 4 KiB is
// comfortably above the realistic upper bound while keeping the parser
// away from pathological inputs.
const captchaTokenMaxLen = 4 * 1024

// CaptchaInput is the request a [CaptchaVerifier] receives. The fields
// are derived by the orchestrator: the SPA cannot influence them
// beyond the Token bytes itself, which the verifier MUST validate
// against the upstream provider server-side.
//
// The struct deliberately carries no provider-specific context field
// (reCAPTCHA v3's "action", Turnstile's "cdata"). Those are properties
// of the verifier's own upstream configuration, and the verifier is the
// only thing that consumes them, so routing them through the OP would
// hand an implementation back its own settings. A verifier that needs
// such a value holds it directly; one that wants to *check* it needs
// the same string to have reached the client widget, which is the
// embedder's own bootstrap contract with its provider.
type CaptchaInput struct {
	// Token is the captcha token the SPA collected from the upstream
	// provider's client SDK and posted to the orchestrator.
	Token string

	// RemoteIP is the client IP normalised through the trusted-proxy
	// chain. The orchestrator never passes the raw
	// X-Forwarded-* header value here — verifiers can rely on
	// RemoteIP being the post-trust-evaluation address.
	RemoteIP netip.Addr
}

// CaptchaVerifier validates a captcha token against the upstream
// provider. Implementations MUST contact the provider server-side;
// SPA-supplied "captcha passed" flags MUST NOT be trusted.
// Tokens are one-shot, and single use is the upstream provider's
// responsibility: the orchestrator keeps no seen-token set of its own,
// so an implementation that talks to a provider without replay
// protection MUST add its own.
// On failure the orchestrator returns the fixed response
// `challenge_required: true`; the upstream reason is intentionally
// not surfaced to the SPA (enumeration defence).
// CaptchaInput / its result MUST NOT appear in id_token, interaction
// JSON, or anywhere observable by the SPA beyond the literal
// challenge_required flag.
// Implementations MUST be safe for concurrent use by multiple
// goroutines.
type CaptchaVerifier interface {
	// Verify returns nil when the token is valid for the provided
	// CaptchaInput, or a non-nil error otherwise. The orchestrator
	// treats any non-nil error as "challenge failed" without
	// distinguishing the cause to the SPA.
	Verify(ctx context.Context, in CaptchaInput) error
}

// CaptchaWidgetDescriber is the optional interface a
// [CaptchaVerifier] may implement to describe the client-side widget
// the SPA must bootstrap before it can produce a token. The
// orchestrator copies the returned pair onto every captcha
// [interaction.Prompt] it emits, on both the [Config.LoginFlow] and
// the legacy threshold-triggered path.
//
// The verifier is the seam because it is the only object that knows
// which upstream service it talks to: the site key is the public half
// of the same credential pair as the verifier's own secret, so any
// other source could be configured to disagree with it. A verifier
// that does not implement the interface emits a prompt with both
// fields empty, which is what a driver rendering its own challenge
// UI (or a deployment with no widget at all) wants.
type CaptchaWidgetDescriber interface {
	// CaptchaWidget returns the upstream provider identifier
	// (stable values: "turnstile", "hcaptcha", "recaptcha_v3") and
	// the public site key registered with it. Both are copied onto
	// the prompt verbatim; returning empty strings is equivalent to
	// not implementing the interface.
	CaptchaWidget() (provider, siteKey string)
}

// CaptchaWidgetFor reads the widget descriptor off v when it
// implements [CaptchaWidgetDescriber]. Centralising the type assertion
// keeps the two prompt-emission points from drifting: the legacy
// threshold path in this package and the [op.StepCaptcha] adapter in
// op/ both call it, so a verifier that describes a widget describes it
// identically on either path. A nil verifier yields empty strings.
func CaptchaWidgetFor(v CaptchaVerifier) (provider, siteKey string) {
	d, ok := v.(CaptchaWidgetDescriber)
	if !ok {
		return "", ""
	}
	return d.CaptchaWidget()
}
