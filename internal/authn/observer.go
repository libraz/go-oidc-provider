package authn

import opauthn "github.com/libraz/go-oidc-provider/op/authn"

// AttemptOutcome enumerates the possible terminal states for a
// [LoginAttempt].
type AttemptOutcome = opauthn.AttemptOutcome

// AttemptOutcome values.
const (
	AttemptSuccess = opauthn.AttemptSuccess
	AttemptFailure = opauthn.AttemptFailure
	AttemptLocked  = opauthn.AttemptLocked
)

// LoginAttempt is the brute-force / risk-counter feed event the
// orchestrator emits at every login attempt.
type LoginAttempt = opauthn.LoginAttempt

// LoginAttemptObserver is the brute-force / risk feed sink.
type LoginAttemptObserver = opauthn.LoginAttemptObserver
