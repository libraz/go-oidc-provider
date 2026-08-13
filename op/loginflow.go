package op

import "github.com/libraz/go-oidc-provider/internal/authn"

// LoginFlow is the high-level seam embedders use to compose an OIDC
// login. The struct describes the primary credential, a list of
// conditional [Rule] entries, an optional imperative [Decider], and an
// optional [RiskAssessor] used by [RuleRisk] and the orchestrator's
// risk gates.
// LoginFlow is the recommended embedder seam: it separates the
// orchestration of factors (Rules + Decider) from their implementation
// (Step values). Embedders who need finer control fall back to the
// low-level [Authenticator] / [Interaction] surface, which remains
// supported. See the package godoc on [Rule] / [Decider] for the
// evaluation order the orchestrator applies on each pass.
//
// Experimental: field names and evaluation order MAY change in a minor
// release. The seam is young and the shape of a step-ordering policy is
// the part of this library most likely to be wrong in a way only
// deployments will reveal; freezing it now would lock in that guess.
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

	// Risk, when non-nil, is consulted exactly once per login chain,
	// at [RiskAuthorizeEntry], before Primary runs. The resulting
	// score is cached for the lifetime of the attempt and exposed to
	// rule predicates through [LoginContext.RiskScore]; RuleRisk
	// silently no-ops when no assessor is wired, so an embedder can
	// register a [RuleRisk] without first wiring one.
	//
	// The returned [RiskOutcome] is applied as follows: [RiskDeny]
	// terminates the chain, [RiskRequire] raises the cached score and
	// — when it names [RiskOutcome.RequiredFactors] — obliges the chain
	// to complete a Step whose [Authenticator] reports one of those
	// factor types before authentication is granted. A flow that
	// declares no such Step fails the attempt closed rather than
	// granting at the assurance the assessor refused.
	//
	// Risk and [WithRiskAssessor] are two spellings of the same seam.
	// Setting both fails [New]; setting either one alone wires it here.
	Risk RiskAssessor
}

// RiskScore is the typed enum [RuleRisk] thresholds against and
// [LoginContext.RiskScore] carries. The values are an ordered scale —
// higher numeric values denote higher risk — so callers can compare
// with `score >= threshold`.
// The mapping from a [RiskAssessor]'s probabilistic output to one of
// the four levels is the embedder's responsibility; the library does
// not prescribe a numeric cut-off. An assessor that wants to emit
// [RiskScoreMedium] populates [RiskOutcome.Score] explicitly; the
// Decision-only path can only reach Low or High.
type RiskScore = authn.RiskScore

// RiskScore values re-exported from the authn package. The ordering
// is significant: comparison operators rely on RiskScoreNone <
// RiskScoreLow < RiskScoreMedium < RiskScoreHigh.
const (
	RiskScoreNone   = authn.RiskScoreNone
	RiskScoreLow    = authn.RiskScoreLow
	RiskScoreMedium = authn.RiskScoreMedium
	RiskScoreHigh   = authn.RiskScoreHigh
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
//   - RiskScore is the [LoginFlow.Risk] assessor's verdict; the
//     orchestrator invokes [RiskAssessor.Assess] once per login chain
//     (at chain start, before Primary) and every subsequent evaluation
//     pass reads the cached value, so external API costs stay bounded
//     and a predicate cannot see the score change mid-attempt.
//   - NewDevice is the [RiskOutcome.NewDevice] verdict from the same
//     once-per-chain consult that produced RiskScore, cached alongside
//     it. The assessor is its only source; false when none is wired.
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
	// the user has not been seen on before, as reported by the
	// configured [RiskAssessor] through [RiskOutcome.NewDevice]. False
	// when no assessor is wired; see [RuleNewDevice].
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
