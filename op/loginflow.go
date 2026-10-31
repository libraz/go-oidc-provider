package op

import "github.com/libraz/go-oidc-provider/internal/authn"

// LoginFlow is the high-level seam embedders use to compose an OIDC
// login. The struct describes the primary credential, a list of
// conditional [Rule] entries, an optional imperative [Decider], and an
// optional [RiskAssessor] used by [RuleRisk] and the orchestrator's
// risk gates.
// LoginFlow is the only embedder seam for composing authentication: it
// separates the orchestration of factors (Rules + Decider) from their
// implementation (Step values). A factor this package does not
// implement plugs in as an [ExternalStep] wrapping an [Authenticator];
// non-factor prompts go through [WithInteractions]. See the package
// godoc on [Rule] / [Decider] for the evaluation order the orchestrator
// applies on each pass.
//
// Stable since v1.5.
type LoginFlow struct {
	// Primary is the first step the orchestrator runs. It is the step
	// that establishes the [Identity] consumed by every subsequent
	// rule predicate. Primary MUST be non-nil; the orchestrator
	// rejects a LoginFlow with a nil Primary at construction time, and
	// one whose Primary is a built-in step that needs a subject already
	// bound ([StepTOTP], [StepEmailOTP], [StepRecoveryCode]). A
	// [PrimaryPasskey] here runs passwordless and must require user
	// verification; a [StepOneOf] here may hold only steps that can
	// stand first.
	Primary Step

	// Registration, when non-nil, is the step the orchestrator runs in
	// place of Primary for an authorization request carrying
	// prompt=create (OpenID Connect Prompt Create 1.0). Its
	// [Authenticator] creates the account and binds the new subject;
	// Rules, Decider, consent and the session write then follow exactly
	// as after Primary, and [LoginContext.CompletedSteps] carries its
	// KindLabel so a rule can tell a registration from a login. Leaving
	// it nil keeps prompt=create rejected as invalid_request.
	//
	// Registration MUST be an [ExternalStep] whose CountFailures is false
	// and whose KindLabel no other step in the flow uses; [New] rejects
	// a built-in Step, a [StepOneOf], and a Rule whose Then names the
	// Registration kind. The step never sees the subject of an existing
	// session, runs only for prompt=create, and cannot be demanded by a
	// [Decider] Require or a risk step-up. A completion that binds no
	// subject ends the attempt.
	//
	// Stable since v1.5.
	Registration Step

	// Rules is the ordered list of conditional follow-up steps the
	// orchestrator evaluates after Primary completes. Rules whose
	// [Rule.When] returns true and whose [Rule.Then.Kind] is not
	// already in [LoginContext.CompletedSteps] fire in declaration
	// order. The list MAY be empty for single-factor flows.
	//
	// Rules and [Decider] are evaluated per authorization request. A
	// request /authorize could serve from an existing session is first
	// checked against them with the steps the session stands in for
	// taken as complete (see [LoginContext.CompletedSteps]); if one
	// demands a step, the chain runs from the session's subject
	// (prompt=none yields interaction_required). Risk is not consulted
	// for that check, so risk-driven rules fire only inside the chain.
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
//   - FailedAttempts is this attempt's rejected submissions.
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
//   - AAL, SessionReused and Identity.AuthenticationContext describe the
//     authentication the attempt stands on so far.
//
// The struct is read-only by convention: rule predicates MUST NOT
// mutate slices or maps it carries.
//
// An [ACRPolicy] receives a LoginContext too. Its Resolve sees the same
// AAL, SessionReused and Identity.AuthenticationContext a rule predicate
// sees for the authentication being reported.
type LoginContext struct {
	// Identity is the subject the primary step produced.
	//
	// Identity.AuthenticationContext carries the amr and acr of the
	// authentication so far — the inherited session's merged with the
	// factors run in this attempt — and, when the session is reused, the
	// session's auth_time. While the attempt authenticates afresh
	// AuthTime is zero: auth_time is fixed only when the session is
	// written. Factors carry no completion time of their own.
	Identity Identity

	// ClientID is the relying-party client_id.
	ClientID string

	// RequestedScopes is the authorize request's scope list.
	RequestedScopes ScopeSet

	// FailedAttempts is this attempt's rejected submissions.
	FailedAttempts int

	// RiskScore is the most recent [RiskAssessor.Assess] verdict.
	RiskScore RiskScore

	// NewDevice reports whether the request originates from a device
	// the user has not been seen on before, as reported by the
	// configured [RiskAssessor] through [RiskOutcome.NewDevice]. False
	// when no assessor is wired; see [RuleNewDevice].
	NewDevice bool

	// CompletedSteps is the [StepKind] history of this attempt in
	// completion order. When the request is served from an existing
	// session, the kinds the session stands in for lead the list:
	// Primary's, plus each rule step whose amr the session carries —
	// "pwd" for [PrimaryPassword], "otp" for [StepTOTP],
	// [StepRecoveryCode] and [StepEmailOTP], "hwk" for [PrimaryPasskey]
	// ("swk" too unless it requires user verification), and for a
	// [StepOneOf] the amr of any of its steps. [ExternalStep] and
	// [StepCaptcha] leave no amr of their own and are never counted, so
	// they run again on every authorization their rule fires for.
	//
	// The otp factors share one amr value, so a session made with email
	// OTP also stands in for a TOTP rule; the id_token does not tell them
	// apart either, and both reach the same level. A relying party that
	// needs a specific factor re-run sends max_age or acr_values.
	CompletedSteps []StepKind

	// ACRValues is the OIDC Core 1.0 §3.1.2.1 acr_values request
	// parameter, parsed into a slice in arrival order. RFC 9470 reuses
	// the parameter name in the RS→AS challenge direction, which the
	// library does not implement; cite OIDC Core when documenting the
	// AS-side intake.
	ACRValues []string

	// Remote is the request's de-proxied client hints.
	Remote ClientHints

	// AAL is the assurance level the authentication has reached so far:
	// the higher of the reused session's level and the factors run in
	// this attempt.
	//
	// Stable since v1.5.
	AAL AAL

	// SessionReused reports that an existing session's authentication
	// stands in for [LoginFlow.Primary] in this attempt.
	//
	// Stable since v1.5.
	SessionReused bool
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
