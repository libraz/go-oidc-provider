// Package pollinterval is the polling discipline shared by the two
// grants a client drives by repeatedly polling the token endpoint: the
// device authorization grant (RFC 8628 §3.5) and CIBA poll mode
// (OIDC CIBA Core 1.0 §11). Both specs prescribe the same slow_down
// ladder; each flow maps the [Outcome] onto its own wire decision.
package pollinterval

import "time"

const (
	// DefaultInterval is the seed value of the slow_down ladder and
	// the value the OP advertises on the authorization response so a
	// well-behaved client never triggers slow_down on its first poll.
	DefaultInterval = 5 * time.Second

	// SlowDownIncrement is the amount the effective interval grows by
	// on every slow_down. Both specs instruct the client to increase
	// its own interval by five seconds, so the OP's bar must grow by
	// the same amount or a compliant client is strike-counted out of
	// the flow for polling exactly as instructed.
	SlowDownIncrement = 5 * time.Second

	// IntervalTolerance is how far a poll may undershoot the effective
	// interval without earning slow_down. The OP measures the gap
	// between arrivals while the client measures the gap between
	// sends, so jitter routinely lands an on-time poll marginally
	// early. [FastPollFloor] stays an absolute floor, so the tolerance
	// cannot admit a tight polling loop.
	IntervalTolerance = 1 * time.Second

	// DefaultExpiresIn is the lifetime advertised on the authorization
	// response and stamped on the record. Both specs leave the value
	// unspecified; 600 s accommodates a user reaching for a secondary
	// device.
	DefaultExpiresIn = 600 * time.Second

	// FastPollFloor is the absolute minimum gap between two polls
	// regardless of the slow_down ladder.
	FastPollFloor = 500 * time.Millisecond
)

// MaxPollViolations is the default number of slow_down strikes
// tolerated before the record is locked with access_denied.
const MaxPollViolations uint8 = 5

// Outcome is the closed set of results [Decide] reports.
type Outcome uint8

const (
	// OutcomeInvalid is the zero value and never returned by [Decide].
	OutcomeInvalid Outcome = iota
	// OutcomeEmit means every gate passed and credentials may be issued.
	OutcomeEmit
	// OutcomePending means the user has not completed the interaction.
	OutcomePending
	// OutcomeSlowDown means the client polled too fast.
	OutcomeSlowDown
	// OutcomeDenied means the record was denied or the strike cap was reached.
	OutcomeDenied
	// OutcomeExpired means the record's TTL has elapsed.
	OutcomeExpired
	// OutcomeConsumed means a previous poll already redeemed the record.
	OutcomeConsumed
)

// Input is the parameter bundle [Decide] consumes.
type Input struct {
	// Now is the clock reading the gate is anchored against.
	Now time.Time
	// LastPolledAt is the previous poll time, or zero when none.
	LastPolledAt time.Time
	// EffectiveInterval is the interval the client is expected to observe.
	EffectiveInterval time.Duration
	// ExpiresAt is when the record becomes invalid; zero disables the check.
	ExpiresAt time.Time
	// Approved reports whether the user approved the request.
	Approved bool
	// Denied reports whether the record was denied or locked.
	Denied bool
	// Consumed reports whether a previous poll already redeemed the record.
	Consumed bool
	// PollViolations is the current strike count.
	PollViolations uint8
	// MaxPollViolations overrides [MaxPollViolations] when non-zero.
	MaxPollViolations uint8
}

// Result is the outcome plus the ladder state the caller persists.
type Result struct {
	Outcome Outcome
	// NextInterval is meaningful only for [OutcomeSlowDown].
	NextInterval time.Duration
	// CountThisAsViolation is true exactly when slow_down fires.
	CountThisAsViolation bool
}

// Decide applies the gates in a fixed order: consumed, expired, denied,
// strike cap, fast poll, interval bar, approved, pending. The TTL gate
// runs before the deny gate so a late poll on a denied-then-expired
// record surfaces as expired.
func Decide(in Input) Result {
	if in.Consumed {
		return Result{Outcome: OutcomeConsumed}
	}
	if !in.ExpiresAt.IsZero() && !in.Now.Before(in.ExpiresAt) {
		return Result{Outcome: OutcomeExpired}
	}
	if in.Denied {
		return Result{Outcome: OutcomeDenied}
	}
	threshold := in.MaxPollViolations
	if threshold == 0 {
		threshold = MaxPollViolations
	}
	if in.PollViolations >= threshold {
		return Result{Outcome: OutcomeDenied}
	}
	if !in.LastPolledAt.IsZero() {
		gap := in.Now.Sub(in.LastPolledAt)
		if gap < FastPollFloor || gap < IntervalBar(in.EffectiveInterval) {
			return Result{
				Outcome:              OutcomeSlowDown,
				NextInterval:         NextInterval(in.EffectiveInterval),
				CountThisAsViolation: true,
			}
		}
	}
	if in.Approved {
		return Result{Outcome: OutcomeEmit}
	}
	return Result{Outcome: OutcomePending}
}

// NextInterval raises current by [SlowDownIncrement]. A zero or negative
// current value falls back to [DefaultInterval] so the ladder recovers
// from a mis-seeded record.
func NextInterval(current time.Duration) time.Duration {
	if current <= 0 {
		return DefaultInterval
	}
	return current + SlowDownIncrement
}

// IntervalBar returns the shortest gap that clears the interval gate:
// the effective interval less [IntervalTolerance], floored at zero so a
// mis-seeded interval leaves [FastPollFloor] as the only gate.
func IntervalBar(effective time.Duration) time.Duration {
	return max(effective-IntervalTolerance, 0)
}
