package authn

import "errors"

// Sentinel errors an [Authenticator] wraps to steer the login flow. The
// built-in factors wrap the same values, so [errors.Is] matches across the
// package boundary.
var (
	// ErrFactorRetry signals "the user-supplied credential was
	// rejected; the orchestrator MUST observe the failure and
	// re-emit the current factor's prompt rather than terminating
	// the chain." Authenticators that cannot resolve the failure to
	// a fresh Prompt themselves (the password adapter, for instance,
	// has no in-flight per-attempt state to amend) wrap their
	// soft-failure sentinel in [ErrFactorRetry] so the orchestrator
	// can route the response uniformly. Hard errors — store outage,
	// codec misconfiguration, lockout — MUST NOT wrap this sentinel;
	// they continue to flow to the HTTP layer as 500 / 4xx.
	ErrFactorRetry = errors.New("authn: factor retry")

	// ErrFactorAbort marks a terminal, user-input-driven factor failure
	// that the HTTP layer renders as a 4xx (not a 500). Unlike
	// [ErrFactorRetry] — a soft failure the orchestrator re-prompts — an
	// abort means the factor cannot continue in this interaction: an
	// expired or already-consumed one-time code, an active brute-force
	// lockout, a required factor reset, a rejected consent or chooser
	// submission, or a factor result the chain refuses to record.
	// Per-factor adapters and built-in interactions wrap their terminal
	// sentinels with it so internal/authorizeendpoint can dispatch on the
	// authn-level class without importing each factor's sentinels.
	ErrFactorAbort = errors.New("authn: factor aborted")
)
