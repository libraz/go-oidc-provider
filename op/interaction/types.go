package interaction

import "time"

// OIDC `prompt` request parameter values (OpenID Connect Core 1.0
// §3.1.2.1). The constants are exported so callers parsing or
// asserting against the request value can do so without a stringly-
// typed copy.
//
// Note: these names live in a different namespace from
// [Prompt.Type] (which uses dotted prefixes like "auth.password").
// Sharing constants between the two would have been ambiguous; the
// orchestrator keeps them deliberately separate per
// docs/plans/002-product-design.md §E.2.3.
const (
	// PromptLogin is the "login" value of the OIDC prompt parameter:
	// the RP asks the OP to re-authenticate the user.
	PromptLogin = "login"

	// PromptConsent is the "consent" value of the OIDC prompt
	// parameter: the RP asks the OP to re-prompt for consent.
	PromptConsent = "consent"

	// PromptSelectAccount is the "select_account" value of the OIDC
	// prompt parameter: the RP asks the OP to surface an account
	// chooser.
	PromptSelectAccount = "select_account"

	// PromptNone is the "none" value of the OIDC prompt parameter:
	// the RP asks the OP to complete silently or fail with one of
	// the *_required errors.
	PromptNone = "none"
)

// Prompt is the unit of UI an [op.Authenticator] or [op.Interaction]
// returns. The SPA reads Prompt verbatim; the [PromptData] type
// projection determines which concrete fields are safe to expose.
//
// Prompt.Type follows the namespace rules in §E.2.3:
//
//   - "auth.*"        — Authenticator-emitted prompts ("auth.password",
//     "auth.totp", "auth.email_otp.send", "auth.email_otp.verify",
//     "auth.passkey", "auth.recovery_code", "auth.<myorg>.<factor>.*").
//   - "consent.*"     — consent screens ("consent.scope").
//   - "captcha"       — bot-detection prompt (§M.6.1).
//   - "interaction.*" — orchestrator-driven non-authn prompts
//     (select_account etc.).
//   - "<myorg>.*"     — user-extension prompts. The first dotted token
//     MUST be the org identifier so library-reserved names do not
//     collide.
//
// The OIDC `prompt` request parameter ("none" / "login" / "consent" /
// "select_account") lives in a different namespace; the prefix rule
// keeps the two from colliding when a custom factor is added.
type Prompt struct {
	// Type is the prompt identifier. See the namespace rules above.
	Type string `json:"type"`

	// Data is the typed payload for this prompt. The concrete type
	// is fixed by Prompt.Type per §E.2 schema.
	Data PromptData `json:"data,omitempty"`

	// Inputs is the form fields the SPA renders. Empty means the
	// prompt is informational (e.g., a captcha that completes via
	// the upstream JS SDK without an explicit form submission).
	Inputs []FieldSpec `json:"inputs,omitempty"`

	// StateRef is an opaque continuation token the SPA echoes back
	// in the next [FormSubmission]. The orchestrator binds it to:
	//
	//   - the interaction uid (cross-uid replay rejected),
	//   - the [op.Authenticator] / [op.Interaction] instance
	//     (cross-factor reuse rejected),
	//   - a short TTL (default 10 minutes; expiry restarts the
	//     factor),
	//   - single-use semantics (a successful Continue invalidates
	//     it).
	//
	// StateRef MUST NOT carry plaintext secrets (OTP codes, TOTP
	// shared secrets, recovery codes, email OTP codes) — the rule
	// applies even when the value is HMAC-signed. See §E.2.1 for
	// the security requirements.
	StateRef string `json:"state_ref"`
}

// Step is the discriminated union an [op.Authenticator] /
// [op.Interaction] returns from Begin / Continue. Exactly one of
// Prompt or Result is populated; an empty Step is invalid and the
// orchestrator rejects it.
type Step struct {
	// Prompt, when non-nil, instructs the orchestrator to render
	// another screen and await the SPA's submission.
	Prompt *Prompt

	// Result, when non-nil, signals the factor (or interaction) is
	// complete.
	Result *Result
}

// Result reports a successful factor or interaction completion. For
// [op.Interaction], Subject is the empty string because the subject
// is already bound by the time the interaction runs.
type Result struct {
	// Subject is the OP-internal identifier the factor authenticated.
	// Empty for [op.Interaction] returns.
	Subject string

	// AuthTime is the wall-clock time at which the factor confirmed
	// the user. Implementations read it from
	// [op.BeginInput.AuthTime] or the orchestrator [op.Clock];
	// direct [time.Now] calls are forbidden by depguard.
	AuthTime time.Time
}

// FormSubmission is the SPA's reply to a [Prompt]. The orchestrator
// validates Values against [FieldSpec] before dispatching to
// [op.Authenticator.Continue]; in particular the orchestrator caps
// the total Values size, the per-field byte length, and the field
// count to prevent denial-of-service through oversized submissions.
type FormSubmission struct {
	// StateRef is the [Prompt.StateRef] from the prompt that
	// produced this submission. The orchestrator validates it
	// matches the active factor's continuation token.
	StateRef string `json:"state_ref"`

	// Values are the SPA-supplied form values keyed by
	// [FieldSpec.Name]. The orchestrator enforces size limits;
	// callers MUST treat the map as read-only.
	Values map[string]string `json:"values,omitempty"`
}
