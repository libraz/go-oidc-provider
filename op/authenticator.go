package op

import "github.com/libraz/go-oidc-provider/internal/authn"

// FactorType / Authenticator-related symbols are re-exported from
// their canonical home in the orchestrator package. The op surface is
// the public-API contract embedders consume; internal/authn carries
// the orchestrator wiring that consumes the same types. Aliasing
// keeps both sides referencing one canonical declaration so there is
// no schema drift between the public surface and the internal
// machinery.

// FactorType is an alias for [authn.FactorType].
type FactorType = authn.FactorType

// Built-in [FactorType] values re-exported from the authn package.
const (
	FactorPassword     = authn.FactorPassword
	FactorTOTP         = authn.FactorTOTP
	FactorPasskey      = authn.FactorPasskey
	FactorRecoveryCode = authn.FactorRecoveryCode
	FactorEmailOTP     = authn.FactorEmailOTP
)

// BeginInput is an alias for [authn.BeginInput].
type BeginInput = authn.BeginInput

// ContinueInput is an alias for [authn.ContinueInput].
type ContinueInput = authn.ContinueInput

// Authenticator is an alias for [authn.Authenticator].
type Authenticator = authn.Authenticator

// Interaction is an alias for [authn.Interaction].
type Interaction = authn.Interaction

// InteractionTrigger is an alias for [authn.InteractionTrigger].
type InteractionTrigger = authn.InteractionTrigger

// InteractionTrigger values re-exported from the authn package.
const (
	TriggerBeforeAuthn = authn.TriggerBeforeAuthn
	TriggerAfterAuthn  = authn.TriggerAfterAuthn
	TriggerBeforeToken = authn.TriggerBeforeToken
	TriggerAlways      = authn.TriggerAlways
)
