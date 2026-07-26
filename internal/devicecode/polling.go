package devicecode

import "time"

// Default polling discipline parameters, per RFC 8628 §3.5. The token
// endpoint clamps incoming polls below [DefaultInterval] to slow_down,
// doubles the effective interval on each violation (no upper cap; the
// record's TTL is the hard stop), and rejects sub-[FastPollFloor]
// repeats once per offence even when the previous response was
// authorization_pending.
const (
	// DefaultInterval is the seed value of the slow_down doubling
	// rule and the value the OP advertises in the
	// device-authorization response so a well-behaved device never
	// triggers slow_down on its first poll.
	DefaultInterval = 5 * time.Second

	// FastPollFloor is the absolute minimum gap between two polls
	// the OP tolerates regardless of the slow_down ladder. A poll
	// arriving inside this window collapses to a single slow_down
	// response per offence, distinguishing a misconfigured client
	// from a brute-force loop.
	FastPollFloor = 500 * time.Millisecond

	// DefaultExpiresIn is the device_code lifetime advertised on the
	// device-authorization response and stamped on the substore record.
	// RFC 8628 §3.4 leaves the value unspecified; 600 s (10 minutes)
	// is the smallest interval that still accommodates a distracted
	// user finding a secondary device.
	DefaultExpiresIn = 600 * time.Second

	// MaxPollViolations is the default number of slow_down offences
	// tolerated before the token endpoint locks the record with
	// reason="poll_abuse".
	MaxPollViolations uint8 = 5
)

// PollDecision is the closed sum returned by [DecidePoll] naming
// the response the token endpoint should write for this poll. The
// type is closed: callers exhaustively switch on it and the
// linter flags any new case the caller forgets to handle.
type PollDecision uint8

const (
	// PollDecisionInvalid is the zero value. It is not a legitimate
	// decision; callers that observe it have a bug in their
	// dispatch.
	PollDecisionInvalid PollDecision = iota

	// PollDecisionEmit means the device passed every gate and the
	// token endpoint may proceed to consume the device_code and
	// emit credentials.
	PollDecisionEmit

	// PollDecisionAuthorizationPending means the user has not yet
	// completed the verification ceremony. The wire form is
	// authorization_pending per RFC 8628 §3.5.
	PollDecisionAuthorizationPending

	// PollDecisionSlowDown means the device polled inside the
	// current interval and MUST back off. The wire form is
	// slow_down per RFC 8628 §3.5; the token endpoint also doubles
	// the device's effective interval before the next poll.
	PollDecisionSlowDown

	// PollDecisionAccessDenied means the user explicitly rejected
	// the request, or the user_code brute-force gate terminated
	// the record. The wire form is access_denied per RFC 8628 §3.5.
	PollDecisionAccessDenied

	// PollDecisionExpiredToken means the device_code's TTL has
	// elapsed, the record has already been consumed by a previous
	// successful poll, or the record disappeared from the
	// substore. The wire form is expired_token per RFC 8628 §3.5.
	PollDecisionExpiredToken
)

// String returns the wire-friendly mnemonic for d, suitable for
// audit and log output. Unknown values surface as "invalid".
func (d PollDecision) String() string {
	switch d {
	case PollDecisionEmit:
		return "emit"
	case PollDecisionAuthorizationPending:
		return "authorization_pending"
	case PollDecisionSlowDown:
		return "slow_down"
	case PollDecisionAccessDenied:
		return "access_denied"
	case PollDecisionExpiredToken:
		return "expired_token"
	case PollDecisionInvalid:
		return "invalid"
	default:
		return "invalid"
	}
}

// PollInput is the parameter bundle [DecidePoll] consumes. The
// caller resolves the substore record, then projects only the
// fields the discipline cares about.
type PollInput struct {
	// Now is the wall-clock reading the caller anchors the gate
	// against. The caller MUST NOT use [time.Now] directly: every
	// call site routes through [internal/timex.Clock] so the
	// discipline is testable without sleep loops.
	Now time.Time

	// LastPolledAt is the wall-clock time of the previous poll
	// against this record, or the zero value when the device has
	// not polled yet. The caller obtains this from the substore;
	// after [DecidePoll] returns the caller stamps the record's
	// LastPolledAt to Now.
	LastPolledAt time.Time

	// EffectiveInterval is the interval the device is currently
	// expected to observe. It starts at the value the
	// device-authorization response advertised
	// ([DefaultInterval] in v0.9.1) and doubles each time
	// [DecidePoll] returns [PollDecisionSlowDown]. Callers MAY
	// persist the doubled value alongside the record; the
	// reference implementation keeps it in [DeviceCode.Interval]
	// so a later poll observes the elevated bar.
	EffectiveInterval time.Duration

	// ExpiresAt is the wall-clock time the record becomes invalid.
	// A poll arriving at or after this point yields
	// [PollDecisionExpiredToken].
	ExpiresAt time.Time

	// Approved reports whether the user has approved the
	// verification ceremony.
	Approved bool

	// Denied reports whether the user has explicitly denied the
	// request or the brute-force gate terminated the record.
	Denied bool

	// Consumed reports whether a previous poll already minted
	// tokens against this record. Subsequent polls collapse to
	// expired_token to prevent token-replay across the
	// approve→consume race window.
	Consumed bool

	// PollViolations is the current slow_down strike count from the
	// substore record. When it reaches [MaxPollViolations],
	// [DecidePoll] returns access_denied.
	PollViolations uint8

	// MaxPollViolations overrides the default strike threshold. Zero
	// falls back to [MaxPollViolations].
	MaxPollViolations uint8
}

// PollOutput captures the decision plus the next-interval the token
// endpoint stamps on the record before responding to the device.
// NextInterval is meaningful only when Decision is
// [PollDecisionSlowDown]; it is the doubled value the next poll's
// gate compares against.
type PollOutput struct {
	Decision             PollDecision
	NextInterval         time.Duration
	CountThisAsViolation bool
}

// DecidePoll applies the polling discipline described on the default
// parameters above. The decision tree:
//
//  1. Consumed → expired_token (token-replay guard).
//  2. ExpiresAt ≤ Now → expired_token (TTL hard stop).
//  3. Denied → access_denied.
//  4. PollViolations ≥ [MaxPollViolations] → access_denied.
//  5. Now − LastPolledAt < FastPollFloor (only when a previous
//     poll exists) → slow_down (doubling applies).
//  6. Now − LastPolledAt < EffectiveInterval (only when a previous
//     poll exists) → slow_down (doubling applies).
//  7. Approved → emit.
//  8. Otherwise → authorization_pending.
//
// The order matters: the TTL gate runs before the deny gate so a
// late poll on a denied-then-expired record still surfaces as
// expired_token (the latest observable state on the wire),
// matching RFC 8628 §3.5's "MUST" sequencing on token-endpoint
// errors.
func DecidePoll(in PollInput) PollOutput {
	if in.Consumed {
		return PollOutput{Decision: PollDecisionExpiredToken}
	}
	if !in.ExpiresAt.IsZero() && !in.Now.Before(in.ExpiresAt) {
		return PollOutput{Decision: PollDecisionExpiredToken}
	}
	if in.Denied {
		return PollOutput{Decision: PollDecisionAccessDenied}
	}
	threshold := in.MaxPollViolations
	if threshold == 0 {
		threshold = MaxPollViolations
	}
	if in.PollViolations >= threshold {
		return PollOutput{Decision: PollDecisionAccessDenied}
	}
	if !in.LastPolledAt.IsZero() {
		gap := in.Now.Sub(in.LastPolledAt)
		if gap < FastPollFloor || gap < in.EffectiveInterval {
			return PollOutput{
				Decision:             PollDecisionSlowDown,
				NextInterval:         nextInterval(in.EffectiveInterval),
				CountThisAsViolation: true,
			}
		}
	}
	if in.Approved {
		return PollOutput{Decision: PollDecisionEmit}
	}
	return PollOutput{Decision: PollDecisionAuthorizationPending}
}

// nextInterval doubles current. A zero or negative current value
// falls back to [DefaultInterval] so the discipline recovers from an
// embedder that mis-seeded the substore record.
func nextInterval(current time.Duration) time.Duration {
	if current <= 0 {
		return DefaultInterval
	}
	return current * 2
}
