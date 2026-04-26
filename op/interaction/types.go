package interaction

// Prompt names recognised by the library. The set is closed: a Driver MUST
// switch over the constants below and surface unknowns via the default arm.
const (
	// PromptLogin is presented when the user is not authenticated to the
	// satisfaction of the request (no session, expired session, or
	// max_age violation).
	PromptLogin = "login"

	// PromptConsent is presented when the requested scopes contain at
	// least one not previously granted to the client. It is suppressed
	// for first-party clients per [Client.FirstParty].
	PromptConsent = "consent"

	// PromptSelectAccount is presented when the user has multiple active
	// sessions in the chooser group and the request requires a choice.
	PromptSelectAccount = "select_account"
)

// Hint records why a prompt is being shown. The slice is ordered from most
// to least specific; UIs typically render the first reason as the headline
// and the rest as supplementary detail.
type Hint struct {
	// Prompt is the prompt name (one of [PromptLogin], [PromptConsent],
	// [PromptSelectAccount]). It is set by the library; Driver
	// implementations MUST NOT mutate it.
	Prompt string

	// Reasons enumerates the policy decisions that produced this prompt
	// (e.g. "no_session", "max_age_exceeded", "new_grant"). Reason
	// identifiers are stable strings the library uses in audit logs.
	Reasons []string
}

// Step describes the next user-facing action the OP needs in order to
// progress the interaction. It is the data the SPA renders when polling
// /interaction/{uid}.
//
// The exact field set is intentionally minimal in v0.x; richer detail
// (scope metadata, account chooser entries, authenticator catalogues) is
// rendered by the L2 JSON endpoints, which read from the Provider
// directly. Step is the shape passed across the [Driver] boundary so
// custom drivers can short-circuit UI rendering.
type Step struct {
	// Hint describes why this step is required.
	Hint Hint

	// CSRF is the double-submit token the SPA must echo on the matching
	// POST. It is opaque to the Driver.
	CSRF string

	// ExpiresAtUnix is the wall-clock expiry of the interaction record
	// as a Unix timestamp. Zero means the interaction has no expiry,
	// which the library only emits in tests.
	ExpiresAtUnix int64
}

// Result is the outcome the SPA POSTs back to the OP after the user
// completes a step. It is intentionally a tagged union encoded as a
// struct: only fields relevant to the [Hint.Prompt] kind are read.
type Result struct {
	// SubjectHint is the canonical subject the Driver authenticated.
	// For PromptLogin it is required; for PromptConsent it is informational.
	SubjectHint string

	// GrantedScopes lists the scopes the user agreed to release. It is
	// only consulted on PromptConsent; the library intersects it with
	// the authorization request and the client's registered scopes
	// before issuing tokens.
	GrantedScopes []string

	// AccountID is the chooser-group account identifier picked on
	// PromptSelectAccount. Empty for other prompts.
	AccountID string

	// Aborted is set when the user explicitly cancelled the interaction.
	// The library translates this to access_denied at the authorization
	// endpoint per OpenID Connect Core 1.0 §3.1.2.6.
	Aborted bool
}

// Decision is the verdict the [Driver] returns to the OP after processing
// a [Result]. It is the contract that lets the OP either complete the
// flow or request a follow-up step (for example MFA after a password).
type Decision struct {
	// Continue is true when another [Step] is required. The library will
	// poll the Driver again with the new state.
	Continue bool

	// Next is populated when Continue is true. It is the shape the SPA
	// renders for the follow-up step.
	Next Step

	// Error is set when the Driver wants to surface a domain-level
	// error to the SPA without aborting the interaction. The library
	// forwards the value verbatim; it MUST NOT contain sensitive data.
	Error string
}
