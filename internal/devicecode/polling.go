package devicecode

import (
	"time"

	"github.com/libraz/go-oidc-provider/internal/pollinterval"
)

// Polling discipline parameters, per RFC 8628 §3.5. They are defined once in
// [pollinterval] and re-exported here under this package's names.
const (
	// DefaultInterval is the seed value of the slow_down ladder.
	DefaultInterval = pollinterval.DefaultInterval

	// SlowDownIncrement is the amount the effective interval grows by
	// on every slow_down.
	SlowDownIncrement = pollinterval.SlowDownIncrement

	// DefaultExpiresIn is the device_code lifetime advertised on the
	// device-authorization response and stamped on the substore record.
	DefaultExpiresIn = pollinterval.DefaultExpiresIn

	// MaxPollViolations is the default number of slow_down strikes
	// tolerated before the record is locked with access_denied.
	MaxPollViolations = pollinterval.MaxPollViolations
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
	// slow_down per RFC 8628 §3.5; the token endpoint also raises
	// the device's effective interval by [SlowDownIncrement] before
	// the next poll, matching the increase the RFC asks the device
	// to apply.
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

// PollInput is the parameter bundle [DecidePoll] consumes. The caller
// resolves the substore record, then projects only the fields the
// discipline cares about; see [pollinterval.Input] for each field.
type PollInput = pollinterval.Input

// PollOutput captures the decision plus the next-interval the token
// endpoint stamps on the record before responding to the device.
// NextInterval is meaningful only when Decision is
// [PollDecisionSlowDown]; it is the raised value the next poll's
// gate compares against.
type PollOutput struct {
	Decision             PollDecision
	NextInterval         time.Duration
	CountThisAsViolation bool
}

// DecidePoll applies the shared polling discipline ([pollinterval.Decide])
// and maps the outcome onto this flow's wire decisions. A consumed record
// maps to [PollDecisionExpiredToken].
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
		out.Decision = PollDecisionExpiredToken
	case pollinterval.OutcomeInvalid:
		out.Decision = PollDecisionInvalid
	}
	return out
}
