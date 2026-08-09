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
	"log/slog"
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
// fan-out; this helper does not retry.
//
// Each observer runs under its own recover() so a panicking embedder
// sink neither fails the login it was reporting on nor stops the
// remaining observers from being fed — a brute-force counter that sits
// behind a broken risk-feed sink must keep advancing.
func FanOut(ctx context.Context, logger *slog.Logger, observers []Observer, evt Event) {
	for _, obs := range observers {
		if obs == nil {
			continue
		}
		safeObserve(ctx, logger, obs, evt)
	}
}

// safeObserve dispatches one event to one observer under a recover().
// The panic is reported on the OP's configured logger, the same sink
// the other embedder-callback seams in this subsystem use for the same
// class of fault; a nil logger falls back to slog.Default so a caller
// that has not wired one still gets the report.
//
// The record deliberately carries only the non-identifying part of the
// event (the factor); Subject / RemoteIP / UserAgent stay out so a
// broken observer cannot turn the operational log into an enumeration
// surface.
func safeObserve(ctx context.Context, logger *slog.Logger, obs Observer, evt Event) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		if logger == nil {
			logger = slog.Default()
		}
		logger.Error("authn audit: login-attempt observer panicked",
			slog.String("factor", evt.Factor),
			slog.Any("panic", r),
		)
	}()
	obs.Observe(ctx, evt)
}
