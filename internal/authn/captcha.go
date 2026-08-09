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
type CaptchaInput struct {
	// Token is the captcha token the SPA collected from the upstream
	// provider's client SDK and posted to the orchestrator.
	Token string

	// RemoteIP is the client IP normalised through the trusted-proxy
	// chain. The orchestrator never passes the raw
	// X-Forwarded-* header value here — verifiers can rely on
	// RemoteIP being the post-trust-evaluation address.
	RemoteIP netip.Addr

	// Action is the upstream-provider-specific action / page
	// context (reCAPTCHA v3 "action", Turnstile "cdata"). Empty when
	// the provider does not consume it.
	Action string
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
