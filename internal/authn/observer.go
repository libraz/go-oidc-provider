package authn

import (
	"context"
	"net/netip"
	"time"
)

// AttemptOutcome enumerates the possible terminal states for a
// [LoginAttempt]. The values are stable across versions; callers MAY
// persist them in audit logs.
type AttemptOutcome int

// AttemptOutcome values.
const (
	// AttemptSuccess reports a factor verified the user.
	AttemptSuccess AttemptOutcome = iota

	// AttemptFailure reports the factor rejected the submission
	// (wrong password, wrong OTP, signature mismatch, captcha
	// failure).
	AttemptFailure

	// AttemptLocked reports the orchestrator refused the attempt
	// before the factor ran because the rate limiter / brute-force
	// counter has the actor locked out.
	AttemptLocked
)

// LoginAttempt is the brute-force / risk-counter feed event the
// orchestrator emits at every login attempt. The shape is independent
// from the §N.2 audit slog: the audit logger receives general events
// and is the stream operators read; this stream feeds backend logic
// (counters, denylist updates, ML ingest) and is intended to be
// consumed by code, not humans.
// LoginAttempt MUST NEVER carry plaintext credentials (passwords,
// OTP codes, recovery codes, email OTP codes, WebAuthn signatures).
// On failure paths Subject is empty or a salted hash to avoid
// enumeration through the observer feed.
// 02-product-design.md §M.6.3.
type LoginAttempt struct {
	// Subject is the OP-internal subject identifier on success
	// paths; empty or a salted hash on failure paths to avoid
	// enumeration.
	Subject string

	// ClientID is the OAuth client_id of the relying party.
	ClientID string

	// RemoteIP is the client IP after trusted-proxy normalisation
	// (§F.5).
	RemoteIP netip.Addr

	// UserAgent is the request's User-Agent header truncated to a
	// sane bound.
	UserAgent string

	// Outcome is the terminal state for this attempt.
	Outcome AttemptOutcome

	// Factor identifies the factor that ran. For [AttemptLocked]
	// before any factor began, the orchestrator sets it to the
	// factor that would have run.
	Factor FactorType

	// Reason is a stable enum-like reason code with the "attempt.*"
	// prefix (e.g., "attempt.invalid_credentials",
	// "attempt.rate_limited", "attempt.captcha_failed",
	// "attempt.locked"). The namespace is disjoint from RFC 6749
	// §5.2 OAuth error codes so a reason cannot accidentally leak
	// into RP-facing error_description fields.
	Reason string

	// At is the wall-clock time at which the attempt completed.
	At time.Time
}

// LoginAttemptObserver is the brute-force / risk feed sink. The
// orchestrator fans out every [LoginAttempt] to every registered
// observer in registration order; observers are expected to be
// non-blocking (push-to-channel / increment-counter style).
// Implementations MUST be safe for concurrent use by multiple
// goroutines. Long-running work belongs in a worker the observer
// hands off to; the orchestrator does not retry on observer errors
// (this is the brute-force / risk-counter feed, not general audit —
// general audit events are emitted by the library to slog per §N.2,
// so do not duplicate them here).
type LoginAttemptObserver interface {
	// Observe is invoked once per attempt. The implementation
	// MUST return promptly; the orchestrator does not wait for
	// background work.
	Observe(ctx context.Context, evt LoginAttempt)
}
