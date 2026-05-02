// Package audit centralises the orchestrator's login-attempt fan-out.
// It defines its own [Event] / [Outcome] / [Observer] surface so the
// parent internal/authn package can import this sub-package without
// introducing a cycle (the parent's LoginAttempt / LoginAttemptObserver
// would otherwise need to be visible here, which would require this
// package to import internal/authn).
//
// The orchestrator wraps each registered [LoginAttemptObserver] in a
// thin adapter at construction time so this package's [FanOut] can
// dispatch without re-touching the parent's type surface on every
// event.
package audit

import (
	"context"
	"net/netip"
	"time"
)

// Outcome enumerates the terminal states for an [Event]. Mirrors the
// parent authn.AttemptOutcome.
type Outcome int

// Outcome values.
const (
	// Success reports a factor verified the user.
	Success Outcome = iota
	// Failure reports the factor rejected the submission.
	Failure
	// Locked reports the orchestrator refused the attempt before the
	// factor ran.
	Locked
)

// Event is the value the orchestrator emits at every login attempt.
// It mirrors authn.LoginAttempt; the orchestrator constructs an Event
// from its State plus the outcome and hands it to [FanOut].
type Event struct {
	Subject   string
	ClientID  string
	RemoteIP  netip.Addr
	UserAgent string
	Outcome   Outcome
	Factor    string
	Reason    string
	At        time.Time
}

// Observer is the duck-typed sink the orchestrator dispatches to. The
// orchestrator wraps each public LoginAttemptObserver in a private
// adapter at construction time so the slice handed to [FanOut] is a
// pure []Observer.
type Observer interface {
	Observe(ctx context.Context, evt Event)
}

// FanOut delivers evt to every observer in registration order. Nil
// entries are skipped. The orchestrator's contract is "non-blocking"
// fan-out; this helper does not retry or recover from observer panics
// — the parent package wraps each observer earlier when the public
// API contract requires panic isolation.
func FanOut(ctx context.Context, observers []Observer, evt Event) {
	for _, obs := range observers {
		if obs == nil {
			continue
		}
		obs.Observe(ctx, evt)
	}
}
