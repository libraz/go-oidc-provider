package op

// LoginFlow is the high-level seam embedders use to compose an OIDC
// login. The struct describes the primary credential, a list of
// conditional [Rule] entries, an optional imperative [Decider], and an
// optional [RiskAssessor] used by [RuleRisk] and the orchestrator's
// risk gates.
// LoginFlow is the recommended embedder seam: it separates the
// orchestration of factors (Rules + Decider) from their implementation
// (Step values). Embedders who need finer control fall back to the
// low-level [Authenticator] / [Interaction] surface, which remains
// supported for the duration of v0.x and into v1.0. See the package
// godoc on [Rule] / [Decider] for the evaluation order the
// orchestrator applies on each pass.
// Experimental: the LoginFlow seam is being introduced in v0.x. Field
// names and evaluation order MAY change before v1.0.
type LoginFlow struct {
	// Primary is the first step the orchestrator runs. It is the step
	// that establishes the [Identity] consumed by every subsequent
	// rule predicate. Primary MUST be non-nil; the orchestrator
	// rejects a LoginFlow with a nil Primary at construction time.
	Primary Step

	// Rules is the ordered list of conditional follow-up steps the
	// orchestrator evaluates after Primary completes. Rules whose
	// [Rule.When] returns true and whose [Rule.Then.Kind] is not
	// already in [LoginContext.CompletedSteps] fire in declaration
	// order. The list MAY be empty for single-factor flows.
	Rules []Rule

	// Decider, when non-nil, is consulted before [Rules] on every
	// evaluation pass. A non-Pass [Decision] short-circuits rule
	// evaluation; [Pass] defers to the rule list. The interface
	// exists so policies that cannot be expressed declaratively (an
	// external policy engine, stateful adaptive authentication) have a
	// single seam rather than forcing a custom [Authenticator].
	Decider Decider

	// Risk, when non-nil, is invoked by the orchestrator at well-
	// defined [RiskStage] points and the resulting score is exposed
	// to rule predicates through [LoginContext.RiskScore]. RuleRisk
	// silently no-ops when Risk is nil, so an embedder can register a
	// [RuleRisk] without first wiring an assessor.
	Risk RiskAssessor
}

// RiskScore is the typed enum [RuleRisk] thresholds against and
// [LoginContext.RiskScore] carries. The values are an ordered scale —
// higher numeric values denote higher risk — so callers can compare
// with `score >= threshold`.
// The mapping from a [RiskAssessor]'s probabilistic output to one of
// the four levels is the embedder's responsibility; the library does
// not prescribe a numeric cut-off.
type RiskScore int

// RiskScore values. The ordering is significant: comparison operators
// rely on RiskScoreNone < RiskScoreLow < RiskScoreMedium <
// RiskScoreHigh.
const (
	// RiskScoreNone is the default zero value: no signal available or
	// the assessor was never invoked.
	RiskScoreNone RiskScore = iota

	// RiskScoreLow is the baseline non-zero level: nothing actionable
	// detected, but at least one signal was observed.
	RiskScoreLow

	// RiskScoreMedium is the threshold at which embedders typically
	// add a non-blocking step (captcha, e-mail OTP).
	RiskScoreMedium

	// RiskScoreHigh is the top of the scale: the assessor recommends
	// blocking strong factors (TOTP, passkey, recovery code) or
	// denying outright.
	RiskScoreHigh
)

// LoginContext is the read-only view a [Rule.When] predicate or a
// [Decider] sees during a LoginFlow evaluation pass. The orchestrator
// rebuilds the value on every pass so a rule that fires advances
// [CompletedSteps] before the next predicate runs.
// LoginContext fields are populated as follows:
//   - Identity is the result of [LoginFlow.Primary] (and any prior
//     step that re-binds the subject). It is the zero [Identity]
//     value before Primary completes.
//   - ClientID is the OAuth client_id of the relying party that
//     started the authorize request.
//   - RequestedScopes is the scope list the relying party asked for.
//   - FailedAttempts is the cumulative count of rejected submissions
//     in this attempt, sourced from the configured login-attempt
//     observer.
//   - RiskScore is the [LoginFlow.Risk] assessor's last verdict; the
//     orchestrator invokes [RiskAssessor.Assess] once per evaluation
//     pass so external API costs stay bounded.
//   - NewDevice is true when the device-trust cookie is absent or
//     does not match a known fingerprint.
//   - CompletedSteps is the ordered list of [StepKind] values that
//     have already produced a [interaction.Result].
//   - ACRValues is the OIDC Core 1.0 §3.1.2.1 acr_values parameter
//     from the authorize request. Used by [RuleACR] for step-up
//     (the related RFC 9470 challenge is the RS→AS direction the
//     library does not implement).
//   - Remote is the request's [ClientHints]: trusted-proxy-resolved
//     IP, user-agent, accept-language header.
//
// The struct is read-only by convention: rule predicates MUST NOT
// mutate slices or maps it carries. A future revision may freeze the
// fields behind methods.
type LoginContext struct {
	// Identity is the subject the primary step produced.
	Identity Identity

	// ClientID is the relying-party client_id.
	ClientID string

	// RequestedScopes is the authorize request's scope list.
	RequestedScopes ScopeSet

	// FailedAttempts is the cumulative failed-submission count for
	// this attempt.
	FailedAttempts int

	// RiskScore is the most recent [RiskAssessor.Assess] verdict.
	RiskScore RiskScore

	// NewDevice reports whether the request originates from a device
	// that has not been trusted before.
	NewDevice bool

	// CompletedSteps is the [StepKind] history of this attempt in
	// completion order.
	CompletedSteps []StepKind

	// ACRValues is the OIDC Core 1.0 §3.1.2.1 acr_values request
	// parameter, parsed into a slice in arrival order. RFC 9470 reuses
	// the parameter name in the RS→AS challenge direction, which the
	// library does not implement; cite OIDC Core when documenting the
	// AS-side intake.
	ACRValues []string

	// Remote is the request's de-proxied client hints.
	Remote ClientHints
}

// ClientHints is the read-only view of request-scoped network and
// agent hints rule predicates may inspect. The orchestrator populates
// the fields after the trusted-proxy chain has been resolved, so a
// predicate sees the post-trust-evaluation address rather than a raw
// X-Forwarded-* value.
type ClientHints struct {
	// RemoteIP is the client IP address as a string. Empty when the
	// orchestrator could not resolve a trusted address.
	RemoteIP string

	// UserAgent is the verbatim User-Agent header value. Empty when
	// the request did not carry one.
	UserAgent string

	// AcceptLanguage is the verbatim Accept-Language header value.
	// Empty when the request did not carry one.
	AcceptLanguage string
}

// (ScopeSet is declared in op/claim.go as map[ScopeName]struct{}
// with Has(ScopeName) bool. LoginContext.RequestedScopes reuses
// that canonical type so callers do not juggle two scope shapes.)
