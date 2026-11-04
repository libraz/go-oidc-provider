package op

import "github.com/libraz/go-oidc-provider/op/authn"

// FactorType / Authenticator-related symbols are declared in the public
// leaf package [github.com/libraz/go-oidc-provider/op/authn], where their
// fields and methods are documented, and re-exported here so embedders
// stay on the op surface. The internal orchestrator aliases the same
// declarations, so there is one type on both sides.

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

// EnrollmentChecker is the optional interface an [Authenticator] wrapped
// in an [ExternalStep] implements to tell a [StepOneOf] whether a subject
// can complete it. Enrolled reports (true, nil) for a subject that has
// the factor set up and (false, nil) for one that does not; a StepOneOf
// offers only the steps that report true. A non-nil error ends the
// attempt as a server error rather than counting the factor either way.
// An authenticator that does not implement it counts as enrolled.
//
// Implementations MUST be safe for concurrent use.
//
// Stable since v1.5.
type EnrollmentChecker = authn.EnrollmentProber

// Interaction is an alias for [authn.Interaction], the non-factor step an
// embedder registers through [WithInteractions]; it is neither the persisted
// authorize-transaction record [store.Interaction] nor the UI contract of
// package op/interaction.
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
