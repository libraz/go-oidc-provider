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

func TestDecidePoll_SlowDownDoubles(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	in := devicecode.PollInput{
		Now:               now,
		LastPolledAt:      now.Add(-2 * time.Second),
		EffectiveInterval: 5 * time.Second,
		ExpiresAt:         now.Add(time.Minute),
		Approved:          true,
	}
	out := devicecode.DecidePoll(in)
	if out.Decision != devicecode.PollDecisionSlowDown {
		t.Errorf("poll inside interval: got %v, want slow_down", out.Decision)
	}
	if out.NextInterval != 10*time.Second {
		t.Errorf("next interval: got %v, want 10s (double of 5s)", out.NextInterval)
	}
	if !out.CountThisAsViolation {
		t.Error("slow_down should count as a poll violation")
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
