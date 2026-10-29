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
//
// Error contract for Begin and Continue, as seen from an [ExternalStep]:
//   - An error wrapping [ErrFactorRetry] reports a wrong credential. The
//     failure is counted (login context, audit, observer) and the same
//     prompt is presented again.
//   - An error wrapping [ErrFactorAbort] ends the attempt for a reason the
//     user caused; the response is a 4xx.
//   - Any other error is treated as a server fault (5xx).
//   - Returning the prompt again with a nil error is not counted as a
//     failure.
type Authenticator = authn.Authenticator

var (
	// ErrFactorRetry is the sentinel an [Authenticator] wraps to report a
	// rejected credential. It is the same value the built-in factors use,
	// so [errors.Is] matches across the boundary.
	//
	// Stable since v1.5.
	ErrFactorRetry = authn.ErrFactorRetry

	// ErrFactorAbort is the sentinel an [Authenticator] wraps to end the
	// attempt with a 4xx for a failure the user caused. It is the same
	// value the built-in factors use.
	//
	// Stable since v1.5.
	ErrFactorAbort = authn.ErrFactorAbort
)

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
