package ciba

import "time"

// Default polling discipline parameters per OIDC CIBA Core 1.0 §11.
// The token endpoint clamps incoming polls below [DefaultInterval]
// to slow_down, doubles the effective interval on each violation
// (no upper cap; the record's TTL is the hard stop), rejects
// sub-[FastPollFloor] repeats once per offence even when the
// previous response was authorization_pending, and locks the record
// to access_denied once the violation counter reaches
// [MaxPollViolations].
const (
	// DefaultInterval is the seed value of the slow_down doubling
	// rule and the value the OP advertises in the bc-authorize
	// response so a well-behaved client never triggers slow_down on
	// its first poll.
	DefaultInterval = 5 * time.Second

	// DefaultExpiresIn is the auth_req_id lifetime advertised on the
	// bc-authorize response and stamped on the substore record.
	// CIBA Core leaves the value unspecified; 600 s (10 minutes) is
	// the smallest interval that still accommodates a user reaching
	// for a secondary authentication device.
	DefaultExpiresIn = 600 * time.Second

	// FastPollFloor is the absolute minimum gap between two polls
	// the OP tolerates regardless of the slow_down ladder. A poll
	// arriving inside this window collapses to a single slow_down
	// response per offence, distinguishing a misconfigured client
	// from a brute-force loop.
	FastPollFloor = 500 * time.Millisecond
)

// MaxPollViolations is the hard cap on the poll-violation strike
// counter. When the counter reaches this value the token endpoint
// locks the record by calling CIBARequestStore.Deny with
// reason="poll_abuse" and surfaces access_denied on the wire.
const MaxPollViolations uint8 = 5

// PollDecision is the closed sum returned by [DecidePoll] naming the
// response the token endpoint should write for this poll. The type
// is closed: callers exhaustively switch on it and the linter flags
// any new case the caller forgets to handle.
type PollDecision uint8

const (
	// PollDecisionInvalid is the zero value. It is not a legitimate
	// decision; callers that observe it have a bug in their
	// dispatch.
	PollDecisionInvalid PollDecision = iota

	// PollDecisionEmit means the client passed every gate and the
	// token endpoint may proceed to consume the auth_req_id and
	// emit credentials.
	PollDecisionEmit

	// PollDecisionAuthorizationPending means the user has not yet
	// completed the authentication device interaction. The wire
	// form is authorization_pending per CIBA Core §11.
	PollDecisionAuthorizationPending

	// PollDecisionSlowDown means the client polled inside the
	// current interval and MUST back off. The wire form is
	// slow_down per CIBA Core §11; the token endpoint also doubles
	// the client's effective interval before the next poll.
	PollDecisionSlowDown

	// PollDecisionAccessDenied means the user explicitly rejected
	// the request, the authentication device timed out, or the
	// poll-abuse strike counter reached the cap. The wire form is
	// access_denied per CIBA Core §11.
	PollDecisionAccessDenied

	// PollDecisionExpiredToken means the auth_req_id's TTL has
	// elapsed or the record disappeared from the substore. The wire
	// form is expired_token per CIBA Core §11.
	PollDecisionExpiredToken

	// PollDecisionAlreadyRedeemed means a previous successful poll
	// already minted tokens against this record. The wire form is
	// invalid_grant per RFC 6749 §5.2 (reuse of an already-issued
	// grant); CIBA Core §11 reserves expired_token for TTL elapse
	// only, and OFCS' fapi-ciba CIBA-11 assertion pins the two wire
	// codes apart.
	PollDecisionAlreadyRedeemed
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
	case PollDecisionAlreadyRedeemed:
		return "invalid_grant"
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
	// against this record, or the zero value when the client has
	// not polled yet. The caller obtains this from the substore;
	// after [DecidePoll] returns the caller stamps the record's
	// LastPolledAt to Now via CIBARequestStore.RecordPoll.
	LastPolledAt time.Time

	// EffectiveInterval is the interval the client is currently
	// expected to observe. It starts at the value the bc-authorize
	// response advertised ([DefaultInterval] in v0.9.x) and doubles
	// each time [DecidePoll] returns [PollDecisionSlowDown].
	// Callers persist the doubled value alongside the record; the
	// substore keeps it in [CIBARequest.Interval] so a later poll
	// observes the elevated bar.
	EffectiveInterval time.Duration

	// ExpiresAt is the wall-clock time the record becomes invalid.
	// A poll arriving at or after this point yields
	// [PollDecisionExpiredToken].
	ExpiresAt time.Time

	// Approved reports whether the embedder's authentication device
	// has approved the request via CIBARequestStore.Approve.
	Approved bool

	// Denied reports whether the user has explicitly denied the
	// request, the authentication device timed out, or the
	// poll-abuse counter has already locked the record.
	Denied bool

	// Consumed reports whether a previous poll already minted
	// tokens against this record. Subsequent polls collapse to
	// expired_token to prevent token-replay across the
	// approve→consume race window.
	Consumed bool

	// PollViolations is the current strike count from the
	// substore record. The discipline locks the record when the
	// value reaches [MaxPollViolations]; the caller is responsible
	// for invoking CIBARequestStore.Deny with reason="poll_abuse"
	// in the same step.
	PollViolations uint8
}

// PollOutput captures the decision plus the next-interval the token
// endpoint stamps on the record before responding to the client and
// the should-count-as-violation flag the caller uses to drive the
// substore's IncrementPollViolation call.
//
// NextInterval is meaningful only when Decision is
// [PollDecisionSlowDown]; it is the doubled value the next poll's
// gate compares against.
//
// CountThisAsViolation is true exactly when slow_down fires; the
// caller MUST increment the substore's poll-violation counter only
// when the flag is set.
type PollOutput struct {
	Decision             PollDecision
	NextInterval         time.Duration
	CountThisAsViolation bool
}

// DecidePoll applies the polling discipline documented in the
// package godoc. The decision tree:
//
//  1. Consumed → already_redeemed (token-replay guard,
//     wire invalid_grant per RFC 6749 §5.2).
//  2. ExpiresAt ≤ Now → expired_token (TTL hard stop,
//     wire expired_token per CIBA Core §11).
//  3. Denied → access_denied.
//  4. PollViolations ≥ [MaxPollViolations] → access_denied
//     (lockout — the caller MUST also Deny the record with
//     reason="poll_abuse").
//  5. Now − LastPolledAt < [FastPollFloor] (only when a previous
//     poll exists) → slow_down (CountThisAsViolation=true,
//     NextInterval=double of EffectiveInterval).
//  6. Now − LastPolledAt < EffectiveInterval (only when a previous
//     poll exists) → slow_down (same).
//  7. Approved → emit.
//  8. Otherwise → authorization_pending.
//
// The order matters: the TTL gate runs before the deny gate so a
// late poll on a denied-then-expired record still surfaces as
// expired_token (the latest observable state on the wire), matching
// CIBA Core §11's "MUST" sequencing on token-endpoint errors.
func DecidePoll(in PollInput) PollOutput {
	if in.Consumed {
		return PollOutput{Decision: PollDecisionAlreadyRedeemed}
	}
	if !in.ExpiresAt.IsZero() && !in.Now.Before(in.ExpiresAt) {
		return PollOutput{Decision: PollDecisionExpiredToken}
	}
	if in.Denied {
		return PollOutput{Decision: PollDecisionAccessDenied}
	}
	if in.PollViolations >= MaxPollViolations {
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

// nextInterval doubles current per the CIBA Core §11 doubling rule.
// A zero or negative current value falls back to [DefaultInterval]
// so the discipline recovers from an embedder that mis-seeded the
// substore record.
func nextInterval(current time.Duration) time.Duration {
	if current <= 0 {
		return DefaultInterval
	}
	return current * 2
}
