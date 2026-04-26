package authn

import (
	"context"
	"net/netip"
)

// CaptchaInput is the request a [CaptchaVerifier] receives. The fields
// are derived by the orchestrator: the SPA cannot influence them
// beyond the Token bytes itself, which the verifier MUST validate
// against the upstream provider server-side.
//
// See docs/plans/002-product-design.md §M.6.1 for the full design
// rationale.
type CaptchaInput struct {
	// Token is the captcha token the SPA collected from the upstream
	// provider's client SDK and posted to the orchestrator.
	Token string

	// RemoteIP is the client IP normalised through the trusted-proxy
	// chain (§F.5). The orchestrator never passes the raw
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
//
// Tokens are one-shot. Implementations should rely on the upstream
// provider's enforcement; the orchestrator additionally rejects same-
// token re-use within a short window so a leaked token cannot be
// replayed across attempts.
//
// On failure the orchestrator returns the fixed response
// `challenge_required: true`; the upstream reason is intentionally
// not surfaced to the SPA (enumeration defence).
//
// CaptchaInput / its result MUST NOT appear in id_token, interaction
// JSON, or anywhere observable by the SPA beyond the literal
// challenge_required flag.
//
// Implementations MUST be safe for concurrent use by multiple
// goroutines.
type CaptchaVerifier interface {
	// Verify returns nil when the token is valid for the provided
	// CaptchaInput, or a non-nil error otherwise. The orchestrator
	// treats any non-nil error as "challenge failed" without
	// distinguishing the cause to the SPA.
	Verify(ctx context.Context, in CaptchaInput) error
}
