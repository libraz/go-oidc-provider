package ciba

import (
	"time"

	"github.com/libraz/go-oidc-provider/internal/pollinterval"
)

// Polling discipline parameters per OIDC CIBA Core 1.0 §11. They are defined once in
// [pollinterval] and re-exported here under this package's names.
const (
	// DefaultInterval is the seed value of the slow_down ladder.
	DefaultInterval = pollinterval.DefaultInterval

	// SlowDownIncrement is the amount the effective interval grows by
	// on every slow_down.
	SlowDownIncrement = pollinterval.SlowDownIncrement

	// IntervalTolerance is how far a poll may undershoot the effective
	// interval without earning slow_down.
	IntervalTolerance = pollinterval.IntervalTolerance

	// DefaultExpiresIn is the auth_req_id lifetime advertised on the
	// bc-authorize response and stamped on the substore record.
	DefaultExpiresIn = pollinterval.DefaultExpiresIn

	// FastPollFloor is the absolute minimum gap between two polls
	// regardless of the slow_down ladder.
	FastPollFloor = pollinterval.FastPollFloor

	// MaxPollViolations is the default number of slow_down strikes
	// tolerated before the record is locked with access_denied.
	MaxPollViolations = pollinterval.MaxPollViolations
)

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
	// slow_down per CIBA Core §11; the token endpoint also raises
	// the client's effective interval by [SlowDownIncrement] before
	// the next poll, matching the increase the spec asks the client
	// to apply.
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

// PollInput is the parameter bundle [DecidePoll] consumes. The caller
// resolves the substore record, then projects only the fields the
// discipline cares about; see [pollinterval.Input] for each field.
type PollInput = pollinterval.Input

// PollOutput captures the decision plus the next-interval the token
// endpoint stamps on the record before responding to the client and
// the should-count-as-violation flag the caller uses to drive the
// substore's IncrementPollViolation call.
//
// NextInterval is meaningful only when Decision is
// [PollDecisionSlowDown]; it is the raised value the next poll's
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

// DecidePoll applies the shared polling discipline ([pollinterval.Decide])
// and maps the outcome onto this flow's wire decisions. A consumed record
// maps to [PollDecisionAlreadyRedeemed].
func DecidePoll(in PollInput) PollOutput {
	res := pollinterval.Decide(in)
	out := PollOutput{
		NextInterval:         res.NextInterval,
		CountThisAsViolation: res.CountThisAsViolation,
	}
	switch res.Outcome {
	case pollinterval.OutcomeEmit:
		out.Decision = PollDecisionEmit
	case pollinterval.OutcomePending:
		out.Decision = PollDecisionAuthorizationPending
	case pollinterval.OutcomeSlowDown:
		out.Decision = PollDecisionSlowDown
	case pollinterval.OutcomeDenied:
		out.Decision = PollDecisionAccessDenied
	case pollinterval.OutcomeExpired:
		out.Decision = PollDecisionExpiredToken
	case pollinterval.OutcomeConsumed:
		out.Decision = PollDecisionAlreadyRedeemed
	case pollinterval.OutcomeInvalid:
		out.Decision = PollDecisionInvalid
	}
	return out
}
