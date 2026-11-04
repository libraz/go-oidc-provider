package authn

import opauthn "github.com/libraz/go-oidc-provider/op/authn"

// RiskStage identifies the orchestrator stage at which a [RiskAssessor]
// call is being made.
type RiskStage = opauthn.RiskStage

// RiskStage values.
const (
	RiskAuthorizeEntry = opauthn.RiskAuthorizeEntry
	RiskPreFactor      = opauthn.RiskPreFactor
	RiskPostFactor     = opauthn.RiskPostFactor
	RiskTokenExchange  = opauthn.RiskTokenExchange
)

// RiskInput is the orchestrator-curated input a [RiskAssessor] receives.
type RiskInput = opauthn.RiskInput

// RiskDecision is the outcome a [RiskAssessor] returns.
type RiskDecision = opauthn.RiskDecision

// RiskDecision values.
const (
	RiskAllow   = opauthn.RiskAllow
	RiskRequire = opauthn.RiskRequire
	RiskDeny    = opauthn.RiskDeny
)

// RiskScore is the typed enum that rule predicates threshold against and
// that the orchestrator caches once per chain.
type RiskScore = opauthn.RiskScore

// RiskScore values; the ordering is significant.
const (
	RiskScoreNone   = opauthn.RiskScoreNone
	RiskScoreLow    = opauthn.RiskScoreLow
	RiskScoreMedium = opauthn.RiskScoreMedium
	RiskScoreHigh   = opauthn.RiskScoreHigh
)

// RiskOutcome is the shape a [RiskAssessor] returns to the orchestrator.
type RiskOutcome = opauthn.RiskOutcome

// RiskAssessor is the engine the orchestrator consults at each
// [RiskStage] of a chain run.
type RiskAssessor = opauthn.RiskAssessor
