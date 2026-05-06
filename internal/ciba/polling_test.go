package ciba_test

import (
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/ciba"
)

func TestDecidePoll(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name string
		in   ciba.PollInput
		want ciba.PollOutput
	}{
		{
			name: "consumed shadows approved",
			in: ciba.PollInput{
				Now:               now,
				EffectiveInterval: 5 * time.Second,
				ExpiresAt:         now.Add(time.Minute),
				Approved:          true,
				Consumed:          true,
			},
			want: ciba.PollOutput{Decision: ciba.PollDecisionAlreadyRedeemed},
		},
		{
			name: "ttl gate fires before deny",
			in: ciba.PollInput{
				Now:               now,
				EffectiveInterval: 5 * time.Second,
				ExpiresAt:         now.Add(-time.Second),
				Denied:            true,
			},
			want: ciba.PollOutput{Decision: ciba.PollDecisionExpiredToken},
		},
		{
			name: "denied",
			in: ciba.PollInput{
				Now:               now,
				EffectiveInterval: 5 * time.Second,
				ExpiresAt:         now.Add(time.Minute),
				Denied:            true,
			},
			want: ciba.PollOutput{Decision: ciba.PollDecisionAccessDenied},
		},
		{
			name: "lockout when violations equal max",
			in: ciba.PollInput{
				Now:               now,
				EffectiveInterval: 5 * time.Second,
				ExpiresAt:         now.Add(time.Minute),
				Approved:          true,
				PollViolations:    ciba.MaxPollViolations,
			},
			want: ciba.PollOutput{Decision: ciba.PollDecisionAccessDenied},
		},
		{
			name: "lockout when violations exceed max",
			in: ciba.PollInput{
				Now:               now,
				EffectiveInterval: 5 * time.Second,
				ExpiresAt:         now.Add(time.Minute),
				PollViolations:    ciba.MaxPollViolations + 3,
			},
			want: ciba.PollOutput{Decision: ciba.PollDecisionAccessDenied},
		},
		{
			name: "lockout sits below cap leaves pending",
			in: ciba.PollInput{
				Now:               now,
				EffectiveInterval: 5 * time.Second,
				ExpiresAt:         now.Add(time.Minute),
				PollViolations:    ciba.MaxPollViolations - 1,
			},
			want: ciba.PollOutput{Decision: ciba.PollDecisionAuthorizationPending},
		},
		{
			name: "slow_down via fast-poll floor",
			in: ciba.PollInput{
				Now:               now,
				LastPolledAt:      now.Add(-200 * time.Millisecond),
				EffectiveInterval: 1 * time.Millisecond, // far below FastPollFloor
				ExpiresAt:         now.Add(time.Minute),
				Approved:          true,
			},
			want: ciba.PollOutput{
				Decision:             ciba.PollDecisionSlowDown,
				NextInterval:         2 * time.Millisecond,
				CountThisAsViolation: true,
			},
		},
		{
			name: "slow_down via interval doubles",
			in: ciba.PollInput{
				Now:               now,
				LastPolledAt:      now.Add(-2 * time.Second),
				EffectiveInterval: 5 * time.Second,
				ExpiresAt:         now.Add(time.Minute),
				Approved:          true,
			},
			want: ciba.PollOutput{
				Decision:             ciba.PollDecisionSlowDown,
				NextInterval:         10 * time.Second,
				CountThisAsViolation: true,
			},
		},
		{
			name: "first poll authorization_pending",
			in: ciba.PollInput{
				Now:               now,
				EffectiveInterval: 5 * time.Second,
				ExpiresAt:         now.Add(time.Minute),
			},
			want: ciba.PollOutput{Decision: ciba.PollDecisionAuthorizationPending},
		},
		{
			name: "first poll emit when approved",
			in: ciba.PollInput{
				Now:               now,
				EffectiveInterval: 5 * time.Second,
				ExpiresAt:         now.Add(time.Minute),
				Approved:          true,
			},
			want: ciba.PollOutput{Decision: ciba.PollDecisionEmit},
		},
		{
			name: "second poll past interval emits when approved",
			in: ciba.PollInput{
				Now:               now,
				LastPolledAt:      now.Add(-10 * time.Second),
				EffectiveInterval: 5 * time.Second,
				ExpiresAt:         now.Add(time.Minute),
				Approved:          true,
			},
			want: ciba.PollOutput{Decision: ciba.PollDecisionEmit},
		},
		{
			name: "second poll past interval pending when not approved",
			in: ciba.PollInput{
				Now:               now,
				LastPolledAt:      now.Add(-10 * time.Second),
				EffectiveInterval: 5 * time.Second,
				ExpiresAt:         now.Add(time.Minute),
			},
			want: ciba.PollOutput{Decision: ciba.PollDecisionAuthorizationPending},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := ciba.DecidePoll(tc.in)
			if got.Decision != tc.want.Decision {
				t.Errorf("Decision: got %v, want %v", got.Decision, tc.want.Decision)
			}
			if got.NextInterval != tc.want.NextInterval {
				t.Errorf("NextInterval: got %v, want %v", got.NextInterval, tc.want.NextInterval)
			}
			if got.CountThisAsViolation != tc.want.CountThisAsViolation {
				t.Errorf("CountThisAsViolation: got %v, want %v", got.CountThisAsViolation, tc.want.CountThisAsViolation)
			}
		})
	}
}

// TestDecidePoll_MaxPollViolationsOverride confirms a non-zero
// [PollInput.MaxPollViolations] takes precedence over the package
// default. The override exists so token-endpoint callers (and through
// them, op-layer embedders) can raise or lower the lockout cap
// without forking the polling discipline. The check exercises both
// directions: a higher cap admits a strike count that would lock
// under the default, and a lower cap locks earlier.
func TestDecidePoll_MaxPollViolationsOverride(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)

	// Higher cap: 6 strikes, raised cap of 8 → no lockout.
	hi := ciba.DecidePoll(ciba.PollInput{
		Now:               now,
		LastPolledAt:      now.Add(-10 * time.Second),
		EffectiveInterval: ciba.DefaultInterval,
		ExpiresAt:         now.Add(time.Minute),
		PollViolations:    ciba.MaxPollViolations + 1,
		MaxPollViolations: ciba.MaxPollViolations + 3,
	})
	if hi.Decision == ciba.PollDecisionAccessDenied {
		t.Errorf("higher cap: got access_denied, want authorization_pending")
	}

	// Lower cap: 2 strikes, lowered cap of 2 → lockout fires before
	// the default (5) would have triggered.
	lo := ciba.DecidePoll(ciba.PollInput{
		Now:               now,
		LastPolledAt:      now.Add(-10 * time.Second),
		EffectiveInterval: ciba.DefaultInterval,
		ExpiresAt:         now.Add(time.Minute),
		PollViolations:    2,
		MaxPollViolations: 2,
	})
	if lo.Decision != ciba.PollDecisionAccessDenied {
		t.Errorf("lower cap: got %v, want access_denied", lo.Decision)
	}
}

func TestDecidePoll_NextIntervalFallback(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	// EffectiveInterval=0 forces the FastPollFloor branch, and
	// nextInterval falls back to DefaultInterval.
	out := ciba.DecidePoll(ciba.PollInput{
		Now:               now,
		LastPolledAt:      now.Add(-100 * time.Millisecond),
		EffectiveInterval: 0,
		ExpiresAt:         now.Add(time.Minute),
	})
	if out.Decision != ciba.PollDecisionSlowDown {
		t.Fatalf("decision: got %v, want slow_down", out.Decision)
	}
	if out.NextInterval != ciba.DefaultInterval {
		t.Errorf("next interval fallback: got %v, want %v", out.NextInterval, ciba.DefaultInterval)
	}
	if !out.CountThisAsViolation {
		t.Error("CountThisAsViolation: got false, want true")
	}
}

func TestPollDecision_String(t *testing.T) {
	t.Parallel()
	cases := map[ciba.PollDecision]string{
		ciba.PollDecisionEmit:                 "emit",
		ciba.PollDecisionAuthorizationPending: "authorization_pending",
		ciba.PollDecisionSlowDown:             "slow_down",
		ciba.PollDecisionAccessDenied:         "access_denied",
		ciba.PollDecisionExpiredToken:         "expired_token",
		ciba.PollDecisionAlreadyRedeemed:      "invalid_grant",
		ciba.PollDecisionInvalid:              "invalid",
		ciba.PollDecision(99):                 "invalid",
	}
	for d, want := range cases {
		if got := d.String(); got != want {
			t.Errorf("PollDecision(%d).String() = %q, want %q", uint8(d), got, want)
		}
	}
}
