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

// PollInput is the parameter bundle [DecidePoll] consumes; see
// [pollinterval.Input] for each field.
type PollInput = pollinterval.Input

// PollOutput is the decision plus the next interval and the
// should-count-as-violation flag; see [pollinterval.Output].
type PollOutput = pollinterval.Output

// DecidePoll applies the shared polling discipline ([pollinterval.Decide])
// and maps a consumed record to [pollinterval.OutcomeExpired].
func DecidePoll(in PollInput) PollOutput {
	return pollinterval.DecideAs(in, pollinterval.OutcomeExpired)
}
