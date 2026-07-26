package timex

import (
	"context"
	"time"
)

// PadUntil blocks until at least target has elapsed since start as
// reported by clock. It is the constant-latency primitive the email-OTP
// authenticator uses to defend against the user-enumeration timing
// channel: the matched branch (which invokes the mailer) and
// the unmatched branch (which skips it) must both return after the
// same wall-clock floor regardless of the subject's bound state.
//
// The function never sleeps for longer than target; a clock reading
// already past start+target returns immediately. It honours
// ctx.Done(): a cancelled context aborts the wait so a request whose
// upstream client has hung up does not block the goroutine. The
// cancellation path returns ctx.Err() so the caller can propagate the
// failure (typically as a transport error) instead of pretending the
// pad completed.
//
// PadUntil reads the wall clock through the supplied [Clock] so tests
// can drive a deterministic schedule. Production callers pass
// [SystemClock]; the elapsed-time check resolves against the same
// clock the [Clock]-aware caller already uses for token TTLs and
// rate-limit windows so a test that freezes time also freezes the
// pad.
func PadUntil(ctx context.Context, clock Clock, start time.Time, target time.Duration) error {
	if target <= 0 {
		return nil
	}
	if clock == nil {
		clock = SystemClock
	}
	now := clock.Now()
	elapsed := now.Sub(start)
	remaining := target - elapsed
	if remaining <= 0 {
		return nil
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
