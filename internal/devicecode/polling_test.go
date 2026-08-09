package devicecode_test

import (
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/devicecode"
)

func TestDecidePoll_TTLGate(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	out := devicecode.DecidePoll(devicecode.PollInput{
		Now:               now,
		LastPolledAt:      time.Time{},
		EffectiveInterval: 5 * time.Second,
		ExpiresAt:         now.Add(-time.Second),
		Approved:          true,
	})
	if out.Decision != devicecode.PollDecisionExpiredToken {
		t.Errorf("expired record: got %v, want expired_token", out.Decision)
	}
}

func TestDecidePoll_ConsumedShadowsApproved(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	out := devicecode.DecidePoll(devicecode.PollInput{
		Now:               now,
		EffectiveInterval: 5 * time.Second,
		ExpiresAt:         now.Add(time.Minute),
		Approved:          true,
		Consumed:          true,
	})
	if out.Decision != devicecode.PollDecisionExpiredToken {
		t.Errorf("consumed record: got %v, want expired_token (replay guard)", out.Decision)
	}
}

func TestDecidePoll_Denied(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	out := devicecode.DecidePoll(devicecode.PollInput{
		Now:               now,
		EffectiveInterval: 5 * time.Second,
		ExpiresAt:         now.Add(time.Minute),
		Denied:            true,
	})
	if out.Decision != devicecode.PollDecisionAccessDenied {
		t.Errorf("denied: got %v, want access_denied", out.Decision)
	}
}

func TestDecidePoll_FirstPollAuthPending(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	out := devicecode.DecidePoll(devicecode.PollInput{
		Now:               now,
		EffectiveInterval: 5 * time.Second,
		ExpiresAt:         now.Add(time.Minute),
	})
	if out.Decision != devicecode.PollDecisionAuthorizationPending {
		t.Errorf("first poll, not approved: got %v, want authorization_pending", out.Decision)
	}
}

func TestDecidePoll_FirstPollEmitWhenApproved(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	out := devicecode.DecidePoll(devicecode.PollInput{
		Now:               now,
		EffectiveInterval: 5 * time.Second,
		ExpiresAt:         now.Add(time.Minute),
		Approved:          true,
	})
	if out.Decision != devicecode.PollDecisionEmit {
		t.Errorf("first poll, approved: got %v, want emit", out.Decision)
	}
}

// TestDecidePoll_SlowDownRaisesIntervalByIncrement pins the ladder step
// to the increase RFC 8628 §3.5 instructs the device to apply. The 10s
// row matters most: a 5s seed cannot tell an additive ladder apart from
// a multiplicative one, and only the additive form keeps the OP's bar
// equal to the interval a compliant device observes.
func TestDecidePoll_SlowDownRaisesIntervalByIncrement(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name     string
		current  time.Duration
		wantNext time.Duration
	}{
		{name: "seed interval", current: 5 * time.Second, wantNext: 10 * time.Second},
		{name: "already raised once", current: 10 * time.Second, wantNext: 15 * time.Second},
		{name: "already raised twice", current: 15 * time.Second, wantNext: 20 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out := devicecode.DecidePoll(devicecode.PollInput{
				Now:               now,
				LastPolledAt:      now.Add(-100 * time.Millisecond),
				EffectiveInterval: tc.current,
				ExpiresAt:         now.Add(time.Minute),
				Approved:          true,
			})
			if out.Decision != devicecode.PollDecisionSlowDown {
				t.Errorf("poll inside interval: got %v, want slow_down", out.Decision)
			}
			if out.NextInterval != tc.wantNext {
				t.Errorf("next interval: got %v, want %v (%v + %v)",
					out.NextInterval, tc.wantNext, tc.current, devicecode.SlowDownIncrement)
			}
			if !out.CountThisAsViolation {
				t.Error("slow_down should count as a poll violation")
			}
		})
	}
}

// TestDecidePoll_OnTimePollWithinToleranceIsNotAViolation pins the
// jitter allowance: the OP times arrivals while the device times sends,
// so an on-time poll routinely lands marginally early and MUST NOT be
// treated as an offence.
func TestDecidePoll_OnTimePollWithinToleranceIsNotAViolation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	out := devicecode.DecidePoll(devicecode.PollInput{
		Now:               now,
		LastPolledAt:      now.Add(-(devicecode.DefaultInterval - 100*time.Millisecond)),
		EffectiveInterval: devicecode.DefaultInterval,
		ExpiresAt:         now.Add(time.Minute),
	})
	if out.Decision != devicecode.PollDecisionAuthorizationPending {
		t.Errorf("poll 100ms early: got %v, want authorization_pending", out.Decision)
	}
	if out.CountThisAsViolation {
		t.Error("a poll inside the jitter tolerance must not count as a violation")
	}
}

// pollWalkResult reports what a [pollWalk] run observed.
type pollWalkResult struct {
	violations uint8
	denied     bool
	expired    bool
}

// pollWalk replays a device polling against the discipline. The device
// obeys RFC 8628 §3.5 to the letter: it starts at the advertised
// interval and adds five seconds to its own timer for every slow_down
// it receives. jitter is subtracted from every gap so each poll arrives
// marginally early, which is what a real timer plus network latency
// produces. The clock is driven entirely from the computed intervals,
// so the walk never reads wall time.
func pollWalk(
	start time.Time,
	advertised, jitter, firstGap time.Duration,
	polls int,
) pollWalkResult {
	var out pollWalkResult
	deviceInterval := advertised
	opInterval := advertised
	now := start
	var last time.Time
	for range polls {
		decision := devicecode.DecidePoll(devicecode.PollInput{
			Now:               now,
			LastPolledAt:      last,
			EffectiveInterval: opInterval,
			ExpiresAt:         start.Add(devicecode.DefaultExpiresIn),
			PollViolations:    out.violations,
		})
		switch decision.Decision {
		case devicecode.PollDecisionAccessDenied:
			out.denied = true
			return out
		case devicecode.PollDecisionExpiredToken:
			out.expired = true
			return out
		case devicecode.PollDecisionSlowDown:
			opInterval = decision.NextInterval
			// The device applies the increase RFC 8628 §3.5 mandates.
			deviceInterval += devicecode.SlowDownIncrement
		case devicecode.PollDecisionAuthorizationPending,
			devicecode.PollDecisionEmit,
			devicecode.PollDecisionInvalid:
			// The bar is unchanged; the device keeps its current timer.
		}
		if decision.CountThisAsViolation {
			out.violations++
		}
		gap := deviceInterval - jitter
		if last.IsZero() && firstGap > 0 {
			gap = firstGap
		}
		last = now
		now = now.Add(gap)
	}
	return out
}

// TestDecidePoll_SpecCompliantDeviceIsNeverLockedOut is the property
// that matters for the ladder: a device that polls exactly as RFC 8628
// §3.5 instructs must never be strike-counted out of its own flow. Both
// rows walk a full device_code lifetime; a ladder that outruns the
// device's own timer drives the second row to access_denied on timer
// jitter alone.
func TestDecidePoll_SpecCompliantDeviceIsNeverLockedOut(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name           string
		firstGap       time.Duration
		wantViolations uint8
	}{
		{
			// Every poll lands 100 ms early, which is inside the
			// tolerance: the device never earns a strike at all.
			name:           "steady jitter only",
			wantViolations: 0,
		},
		{
			// One genuinely early poll (a retry after a dropped
			// response, say) earns a single strike. From there the
			// device and the OP hold the same interval, so no further
			// strike can accrue.
			name:           "one early poll then compliant",
			firstGap:       time.Second,
			wantViolations: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := pollWalk(start, devicecode.DefaultInterval, 100*time.Millisecond, tc.firstGap, 40)
			if got.denied {
				t.Fatalf("a spec-compliant device was locked out after %d strikes", got.violations)
			}
			if got.expired {
				t.Fatal("the walk outran the device_code TTL; shorten it so every poll is observed")
			}
			if got.violations != tc.wantViolations {
				t.Errorf("violations = %d, want %d", got.violations, tc.wantViolations)
			}
		})
	}
}

func TestDecidePoll_PollViolationLockout(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	out := devicecode.DecidePoll(devicecode.PollInput{
		Now:               now,
		EffectiveInterval: 5 * time.Second,
		ExpiresAt:         now.Add(time.Minute),
		Approved:          true,
		PollViolations:    devicecode.MaxPollViolations,
	})
	if out.Decision != devicecode.PollDecisionAccessDenied {
		t.Errorf("poll violations at cap: got %v, want access_denied", out.Decision)
	}
}

func TestDecidePoll_FastPollFloor(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	in := devicecode.PollInput{
		Now:               now,
		LastPolledAt:      now.Add(-200 * time.Millisecond),
		EffectiveInterval: 1 * time.Millisecond, // far below FastPollFloor
		ExpiresAt:         now.Add(time.Minute),
		Approved:          true,
	}
	out := devicecode.DecidePoll(in)
	if out.Decision != devicecode.PollDecisionSlowDown {
		t.Errorf("sub-FastPollFloor poll: got %v, want slow_down even when EffectiveInterval is small", out.Decision)
	}
}

func TestDecidePoll_ExpiredOverridesDenied(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	out := devicecode.DecidePoll(devicecode.PollInput{
		Now:               now,
		EffectiveInterval: 5 * time.Second,
		ExpiresAt:         now.Add(-time.Second),
		Denied:            true,
	})
	if out.Decision != devicecode.PollDecisionExpiredToken {
		t.Errorf("expired AND denied: got %v, want expired_token (TTL gate runs first)", out.Decision)
	}
}

func TestPollDecision_String(t *testing.T) {
	t.Parallel()
	cases := map[devicecode.PollDecision]string{
		devicecode.PollDecisionEmit:                 "emit",
		devicecode.PollDecisionAuthorizationPending: "authorization_pending",
		devicecode.PollDecisionSlowDown:             "slow_down",
		devicecode.PollDecisionAccessDenied:         "access_denied",
		devicecode.PollDecisionExpiredToken:         "expired_token",
		devicecode.PollDecisionInvalid:              "invalid",
		devicecode.PollDecision(99):                 "invalid",
	}
	for d, want := range cases {
		if got := d.String(); got != want {
			t.Errorf("PollDecision(%d).String() = %q, want %q", uint8(d), got, want)
		}
	}
}
