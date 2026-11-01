package devicecode

import (
	"github.com/libraz/go-oidc-provider/internal/pollinterval"
)

// Polling discipline parameters, per RFC 8628 §3.5. They are defined once in
// [pollinterval] and re-exported here under this package's names.
const (
	// DefaultInterval is the seed value of the slow_down ladder.
	DefaultInterval = pollinterval.DefaultInterval

	// DefaultExpiresIn is the device_code lifetime advertised on the
	// device-authorization response and stamped on the substore record.
	DefaultExpiresIn = pollinterval.DefaultExpiresIn

	// MaxPollViolations is the default number of slow_down strikes
	// tolerated before the record is locked with access_denied.
	MaxPollViolations = pollinterval.MaxPollViolations
)

// PollDecision names the response the token endpoint should write for
// a poll. Callers switch on it exhaustively.
type PollDecision = pollinterval.Outcome

// Wire decisions of the device-code poll (RFC 8628 §3.5).
const (
	// PollDecisionInvalid is the zero value; observing it is a dispatch bug.
	PollDecisionInvalid = pollinterval.OutcomeInvalid

	// PollDecisionEmit means every gate passed and the token endpoint
	// may consume the device_code and emit credentials.
	PollDecisionEmit = pollinterval.OutcomeEmit

	// PollDecisionAuthorizationPending means the user has not yet
	// completed the verification ceremony.
	PollDecisionAuthorizationPending = pollinterval.OutcomePending

	// PollDecisionSlowDown means the device polled inside the current
	// interval and MUST back off; the endpoint also raises the stored
	// interval by [pollinterval.SlowDownIncrement].
	PollDecisionSlowDown = pollinterval.OutcomeSlowDown

	// PollDecisionAccessDenied means the user rejected the request or
	// the user_code brute-force gate terminated the record.
	PollDecisionAccessDenied = pollinterval.OutcomeDenied

	// PollDecisionExpiredToken means the device_code's TTL has elapsed,
	// a previous poll already consumed it, or the record disappeared
	// from the substore.
	PollDecisionExpiredToken = pollinterval.OutcomeExpired
)

// PollInput is the parameter bundle [DecidePoll] consumes; see
// [pollinterval.Input] for each field.
type PollInput = pollinterval.Input

// PollOutput is the decision plus the next interval and the
// should-count-as-violation flag; see [pollinterval.Output].
type PollOutput = pollinterval.Output

// DecidePoll applies the shared polling discipline ([pollinterval.Decide])
// and maps a consumed record to [PollDecisionExpiredToken].
func DecidePoll(in PollInput) PollOutput {
	return pollinterval.DecideAs(in, PollDecisionExpiredToken)
}
