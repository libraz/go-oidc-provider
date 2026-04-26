package op

import "github.com/libraz/go-oidc-provider/internal/authn"

// RiskStage / RiskDecision / RiskInput / RiskOutcome / RiskAssessor
// are aliases for the canonical types in [internal/authn]. The op
// package re-exports them so embedders write `op.RiskAssessor` etc.

// RiskStage is an alias for [authn.RiskStage].
type RiskStage = authn.RiskStage

// RiskStage values re-exported from the authn package.
const (
	RiskAuthorizeEntry = authn.RiskAuthorizeEntry
	RiskPreFactor      = authn.RiskPreFactor
	RiskPostFactor     = authn.RiskPostFactor
	RiskTokenExchange  = authn.RiskTokenExchange
)

// RiskDecision is an alias for [authn.RiskDecision].
type RiskDecision = authn.RiskDecision

// RiskDecision values re-exported from the authn package.
const (
	RiskAllow   = authn.RiskAllow
	RiskRequire = authn.RiskRequire
	RiskDeny    = authn.RiskDeny
)

// RiskInput is an alias for [authn.RiskInput].
type RiskInput = authn.RiskInput

// RiskOutcome is an alias for [authn.RiskOutcome].
type RiskOutcome = authn.RiskOutcome

// RiskAssessor is an alias for [authn.RiskAssessor].
type RiskAssessor = authn.RiskAssessor
