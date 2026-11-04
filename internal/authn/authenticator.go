package authn

import (
	opauthn "github.com/libraz/go-oidc-provider/op/authn"
)

// The authenticator contract types are declared in the public package
// [github.com/libraz/go-oidc-provider/op/authn]; they are aliased here so
// the orchestrator and the factor packages share one declaration.

// FactorType is the typed identifier for an [Authenticator] method.
type FactorType = opauthn.FactorType

// Built-in [FactorType] values.
const (
	FactorPassword     = opauthn.FactorPassword
	FactorTOTP         = opauthn.FactorTOTP
	FactorPasskey      = opauthn.FactorPasskey
	FactorRecoveryCode = opauthn.FactorRecoveryCode
	FactorEmailOTP     = opauthn.FactorEmailOTP
)

// BeginInput carries the per-attempt context an [Authenticator] needs to
// start a ceremony.
type BeginInput = opauthn.BeginInput

// ContinueInput carries the per-submission context an [Authenticator]
// needs to advance a ceremony.
type ContinueInput = opauthn.ContinueInput

// Authenticator is the protocol-side state machine for a single
// authentication factor.
type Authenticator = opauthn.Authenticator

// UserVerificationReporter is an optional interface an [Authenticator]
// MAY implement to surface the WebAuthn-equivalent UV bit observed on
// the most recently completed Continue.
//
// Deprecated: stamp the bit on
// [interaction.Result.UserVerified] instead. The Result-borne path is
// request-scoped and replica-safe (no shared cache); the legacy
// reporter required a process-local cache that lost coverage in
// multi-replica deployments without sticky sessions. The
// built-in passkey adapter no longer implements this interface; the
// orchestrator continues to consult it only for embedder-supplied
// adapters that have not migrated, and only when the matching
// [interaction.Result.UserVerified] is false.
//
// Implementations MUST be safe for concurrent use. The orchestrator
// dispatches a single Continue at a time per State, but the same
// Authenticator value is shared across goroutines for different
// attempts; a stateful "last UV bit" cache MUST guard the field with
// a mutex (or store the value on a per-attempt scratch payload).
type UserVerificationReporter interface {
	// LastUserVerified reports the UV bit of the most recent
	// successful Continue made under the supplied subject. Returns
	// false when no successful Continue has run for the subject in
	// this process, when the most recent attempt did not surface a
	// UV bit, or when the implementation cannot recover the value.
	LastUserVerified(subject string) bool
}

// EnrollmentProber is an optional interface an [Authenticator] MAY
// implement to report whether a subject can complete it at all.
type EnrollmentProber = opauthn.EnrollmentProber

// Interaction is a non-authentication screen unit (T&C acceptance, KYC
// gate, device-trust prompt...).
type Interaction = opauthn.Interaction

// InteractionTrigger declares when the orchestrator inserts an
// [Interaction] into the chain.
type InteractionTrigger = opauthn.InteractionTrigger

// InteractionTrigger values.
const (
	TriggerBeforeAuthn = opauthn.TriggerBeforeAuthn
	TriggerAfterAuthn  = opauthn.TriggerAfterAuthn
	TriggerBeforeToken = opauthn.TriggerBeforeToken
	TriggerAlways      = opauthn.TriggerAlways
)
