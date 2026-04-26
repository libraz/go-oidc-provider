package op

import "github.com/libraz/go-oidc-provider/internal/authn"

// AttemptOutcome / LoginAttempt / LoginAttemptObserver are aliases
// for the canonical types in [internal/authn]. The op package
// re-exports them so embedders write `op.LoginAttemptObserver` etc.

// AttemptOutcome is an alias for [authn.AttemptOutcome].
type AttemptOutcome = authn.AttemptOutcome

// AttemptOutcome values re-exported from the authn package.
const (
	AttemptSuccess = authn.AttemptSuccess
	AttemptFailure = authn.AttemptFailure
)

// LoginAttempt is an alias for [authn.LoginAttempt].
type LoginAttempt = authn.LoginAttempt

// LoginAttemptObserver is an alias for [authn.LoginAttemptObserver].
type LoginAttemptObserver = authn.LoginAttemptObserver
