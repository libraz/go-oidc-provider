package ciba

import (
	"github.com/libraz/go-oidc-provider/internal/pollinterval"
)

// Polling discipline parameters per OIDC CIBA Core 1.0 §11. They are defined once in
// [pollinterval] and re-exported here under this package's names.
const (
	// DefaultInterval is the seed value of the slow_down ladder.
	DefaultInterval = pollinterval.DefaultInterval

	// DefaultExpiresIn is the auth_req_id lifetime advertised on the
	// bc-authorize response and stamped on the substore record.
	DefaultExpiresIn = pollinterval.DefaultExpiresIn

	// MaxPollViolations is the default number of slow_down strikes
	// tolerated before the record is locked with access_denied.
	MaxPollViolations = pollinterval.MaxPollViolations
)

// PollDecision names the response the token endpoint should write for
// a poll. Callers switch on it exhaustively.
type PollDecision = pollinterval.Outcome

// Wire decisions of the CIBA poll (CIBA Core §11).
const (
	// PollDecisionInvalid is the zero value; observing it is a dispatch bug.
	PollDecisionInvalid = pollinterval.OutcomeInvalid

	// PollDecisionEmit means every gate passed and the token endpoint
	// may consume the auth_req_id and emit credentials.
	PollDecisionEmit = pollinterval.OutcomeEmit

	// PollDecisionAuthorizationPending means the user has not yet
	// completed the authentication device interaction.
	PollDecisionAuthorizationPending = pollinterval.OutcomePending

	// PollDecisionSlowDown means the client polled inside the current
	// interval and MUST back off; the endpoint also raises the stored
	// interval by [pollinterval.SlowDownIncrement].
	PollDecisionSlowDown = pollinterval.OutcomeSlowDown

	// PollDecisionAccessDenied means the user rejected the request, the
	// authentication device timed out, or the strike cap was reached.
	PollDecisionAccessDenied = pollinterval.OutcomeDenied

	// PollDecisionExpiredToken means the auth_req_id's TTL has elapsed
	// or the record disappeared from the substore.
	PollDecisionExpiredToken = pollinterval.OutcomeExpired

	// PollDecisionAlreadyRedeemed means a previous poll already minted
	// tokens against this record. The wire form is invalid_grant (RFC
	// 6749 §5.2); CIBA Core §11 reserves expired_token for TTL elapse
	// only, and the conformance suite pins the two codes apart.
	PollDecisionAlreadyRedeemed = pollinterval.OutcomeConsumed
)

// PollInput is the parameter bundle [DecidePoll] consumes; see
// [pollinterval.Input] for each field.
type PollInput = pollinterval.Input

// PollOutput is the decision plus the next interval and the
// should-count-as-violation flag; see [pollinterval.Output].
type PollOutput = pollinterval.Output

// DecidePoll applies the shared polling discipline ([pollinterval.Decide])
// and maps a consumed record to [PollDecisionAlreadyRedeemed].
func DecidePoll(in PollInput) PollOutput {
	return pollinterval.DecideAs(in, PollDecisionAlreadyRedeemed)
}
