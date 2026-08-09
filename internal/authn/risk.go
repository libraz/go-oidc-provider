package authn

import (
	"context"
	"net/netip"
	"time"
)

// RiskStage identifies the orchestrator stage at which a
// [RiskAssessor.Assess] call is being made. The values are stable;
// callers MAY persist them in audit logs or correlate them with
// metrics.
type RiskStage int

// RiskStage values. The set is closed by design — orchestrator
// callsites are bounded — so adding a new stage is a v1.x extension
// rather than an embedder concern.
const (
	// RiskAuthorizeEntry fires immediately on /authorize receipt,
	// before the user is identified. Suitable for client_id x IP
	// denylists and region blocks.
	RiskAuthorizeEntry RiskStage = iota

	// RiskPreFactor fires before each factor's [Authenticator.Begin].
	// Suitable for dynamic factor selection ("anomalous IP -> require
	// SMS OTP instead of TOTP").
	RiskPreFactor

	// RiskPostFactor fires after each factor's [Authenticator.Continue]
	// completes. Suitable for step-up evaluation ("password alone
	// is insufficient at this risk level — append passkey").
	RiskPostFactor

	// RiskTokenExchange fires on /token receipt. Suitable for
	// unusual-location refresh detection.
	RiskTokenExchange
)

// RiskInput is the orchestrator-curated input a [RiskAssessor]
// receives. The fields are deliberately a flat data carrier: the
// orchestrator owns trust evaluation (RemoteIP normalisation through
// the trusted-proxy chain, UserAgent truncation) and the
// assessor consumes only the post-trust values.
// RiskInput MUST NOT be serialised to the SPA, id_token, or any
// user-observable surface. It lives only in the server boundary.
type RiskInput struct {
	// Stage identifies which orchestrator callsite this is.
	Stage RiskStage

	// Subject is the OP-internal subject identifier when known,
	// or "" when authentication has not yet bound a sub.
	Subject string

	// ClientID is the OAuth client_id of the relying party.
	ClientID string

	// RemoteIP is the client IP after trusted-proxy normalisation
	// The orchestrator never hands raw X-Forwarded-* values
	// to the assessor.
	RemoteIP netip.Addr

	// UserAgent is the request's User-Agent header truncated to a
	// sane bound by the orchestrator. Implementations MUST treat
	// it as untrusted input.
	UserAgent string

	// AMRSoFar is the list of RFC 8176 §2 registered values the
	// session has accumulated so far. Foreign values are filtered
	// before this slice is built.
	AMRSoFar []string

	// ACRValues echoes the original /authorize request's
	// space-separated acr_values parameter as a slice. Empty when the
	// caller did not request any specific ACR. Implementations may
	// inspect it to gate risk policy on requested strength (e.g.
	// require step-up factors only when acr_values names a high
	// assurance class). The slice is a defensive copy: assessors MUST
	// NOT retain references across calls.
	ACRValues []string

	// LastFactor is populated only when [RiskInput.Stage] is
	// [RiskPostFactor]; it identifies the factor that just
	// completed. Empty otherwise.
	LastFactor FactorType

	// AuthTime is the orchestrator's reference time for the attempt.
	AuthTime time.Time
}

// RiskDecision is the outcome a [RiskAssessor] returns.
type RiskDecision int

// RiskDecision values.
const (
	// RiskAllow lets the orchestrator proceed without modification.
	RiskAllow RiskDecision = iota

	// RiskRequire instructs the orchestrator to insert additional
	// factors before continuing. The candidates are listed in
	// [RiskOutcome.RequiredFactors] (OR semantics); the orchestrator
	// selects whichever candidate is available for the user.
	RiskRequire

	// RiskDeny terminates the chain. The audit reason flows to the
	// log; the SPA receives only a fixed error response.
	RiskDeny
)

// RiskScore is the typed enum that rule predicates threshold against
// and that the orchestrator caches once per chain. Higher numeric
// values denote higher risk; comparison operators rely on the
// ordering RiskScoreNone < RiskScoreLow < RiskScoreMedium <
// RiskScoreHigh.
//
// The op package re-exports this type as [op.RiskScore] so embedders
// write `op.RiskScoreMedium` etc.
type RiskScore int

// RiskScore values. The ordering is significant.
const (
	// RiskScoreNone is the default zero value: no signal available or
	// the assessor was never invoked. Reserved for short-circuiting
	// rule predicates on missing-signal — never reached on the
	// orchestrator's cached path once an assessor has run.
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

// RiskOutcome is the shape a [RiskAssessor] returns to the
// orchestrator. Output is a *factor specification*, not an AAL bump:
// returning RequiredFactors=["sms_otp"] tells the orchestrator to
// require that factor next, and AAL emerges naturally from
// [Authenticator.AAL] of whichever factor satisfies it.
// RiskOutcome MUST NOT be serialised to the SPA, id_token, or any
// user-observable surface. Reason is a stable enum-like code used
// only in audit logs (e.g., "anomaly.geoip_mismatch",
// "anomaly.new_device") — SPA receives only the resulting [Prompt]
// sequence.
type RiskOutcome struct {
	// Decision is the orchestrator action to take.
	Decision RiskDecision

	// RequiredFactors is the OR-set of [FactorType] candidates the
	// orchestrator must satisfy when [RiskOutcome.Decision] is
	// [RiskRequire]. Ignored otherwise.
	RequiredFactors []FactorType

	// MinAAL filters [RiskOutcome.RequiredFactors]: only factors
	// whose [Authenticator.AAL] meets MinAAL are admissible. When
	// RequiredFactors is empty and MinAAL > AAL0, the orchestrator
	// reads the directive as "any factor that meets MinAAL".
	//
	// MinAAL is honoured only on the legacy [Config.Authenticators]
	// chain path (the orchestrator's eligible-authenticator filter).
	// The [Config.LoginFlow] path does not consult MinAAL: factor
	// selection there is driven by the compiled rules / decider, and
	// the once-per-chain Risk consult reads only Decision and Score.
	// A deployment that needs an assurance floor under LoginFlow
	// encodes it as an explicit rule (a step whose Authenticator meets
	// the floor) rather than through this field.
	MinAAL AAL

	// Reason is the audit reason code. Free-form is forbidden by
	// convention — pick a stable enum-like prefix
	// ("anomaly.<class>", "policy.<rule>"). Reason MUST NOT leak to
	// the SPA.
	Reason string

	// Score is the optional explicit risk grade. When non-zero, it
	// overrides the orchestrator's Decision-derived default
	// (Allow→Low, Require→High) so an assessor can emit any of the
	// four levels — most importantly [RiskScoreMedium], which is not
	// reachable through Decision alone. Leave Score zero to keep the
	// simple-case path; rule predicates `score >= threshold` then
	// see the Decision-derived value.
	Score RiskScore
}

// RiskAssessor is the engine the orchestrator consults at each
// [RiskStage] of a chain run. Implementations are stateless across
// calls; per-attempt state lives in the assessor's own backing store.
// Implementations MUST be safe for concurrent use by multiple
// goroutines.
// [RiskInput], [RiskOutcome] and the assessor's reasoning stay
// server-side: they are never serialised into the interaction JSON,
// an id_token claim, or any other SPA-visible surface. The SPA only
// ever observes the resulting prompt sequence.
type RiskAssessor interface {
	// Assess evaluates the RiskInput and returns the orchestrator
	// directive. A non-nil error fails the request closed (the
	// orchestrator surfaces a fixed server error to the SPA).
	Assess(ctx context.Context, in RiskInput) (RiskOutcome, error)
}
