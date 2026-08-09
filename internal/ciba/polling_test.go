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
				NextInterval:         time.Millisecond + ciba.SlowDownIncrement,
				CountThisAsViolation: true,
			},
		},
		{
			name: "slow_down raises the interval by the increment",
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

// TestDecidePoll_OnTimePollWithinToleranceIsNotAViolation pins the
// jitter allowance: the OP times arrivals while the client times sends,
// so an on-time poll routinely lands marginally early and MUST NOT be
// treated as an offence.
func TestDecidePoll_OnTimePollWithinToleranceIsNotAViolation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	out := ciba.DecidePoll(ciba.PollInput{
		Now:               now,
		LastPolledAt:      now.Add(-(ciba.DefaultInterval - 100*time.Millisecond)),
		EffectiveInterval: ciba.DefaultInterval,
		ExpiresAt:         now.Add(time.Minute),
	})
	if out.Decision != ciba.PollDecisionAuthorizationPending {
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

// pollWalk replays a client polling against the discipline. The client
// obeys CIBA Core §11 to the letter: it starts at the advertised
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
	clientInterval := advertised
	opInterval := advertised
	now := start
	var last time.Time
	for range polls {
		decision := ciba.DecidePoll(ciba.PollInput{
			Now:               now,
			LastPolledAt:      last,
			EffectiveInterval: opInterval,
			ExpiresAt:         start.Add(ciba.DefaultExpiresIn),
			PollViolations:    out.violations,
		})
		switch decision.Decision {
		case ciba.PollDecisionAccessDenied:
			out.denied = true
			return out
		case ciba.PollDecisionExpiredToken:
			out.expired = true
			return out
		case ciba.PollDecisionSlowDown:
			opInterval = decision.NextInterval
			// The client applies the increase CIBA Core §11 mandates.
			clientInterval += ciba.SlowDownIncrement
		case ciba.PollDecisionAuthorizationPending,
			ciba.PollDecisionEmit,
			ciba.PollDecisionAlreadyRedeemed,
			ciba.PollDecisionInvalid:
			// The bar is unchanged; the client keeps its current timer.
		}
		if decision.CountThisAsViolation {
			out.violations++
		}
		gap := clientInterval - jitter
		if last.IsZero() && firstGap > 0 {
			gap = firstGap
		}
		last = now
		now = now.Add(gap)
	}
	return out
}

// TestDecidePoll_SpecCompliantClientIsNeverLockedOut is the property
// that matters for the ladder: a client that polls exactly as CIBA Core
// §11 instructs must never be strike-counted out of its own flow. Both
// rows walk a full auth_req_id lifetime; a ladder that outruns the
// client's own timer drives the second row to access_denied on timer
// jitter alone.
func TestDecidePoll_SpecCompliantClientIsNeverLockedOut(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name           string
		firstGap       time.Duration
		wantViolations uint8
	}{
		{
			// Every poll lands 100 ms early, which is inside the
			// tolerance: the client never earns a strike at all.
			name:           "steady jitter only",
			wantViolations: 0,
		},
		{
			// One genuinely early poll (a retry after a dropped
			// response, say) earns a single strike. From there the
			// client and the OP hold the same interval, so no further
			// strike can accrue.
			name:           "one early poll then compliant",
			firstGap:       time.Second,
			wantViolations: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := pollWalk(start, ciba.DefaultInterval, 100*time.Millisecond, tc.firstGap, 40)
			if got.denied {
				t.Fatalf("a spec-compliant client was locked out after %d strikes", got.violations)
			}
			if got.expired {
				t.Fatal("the walk outran the auth_req_id TTL; shorten it so every poll is observed")
			}
			if got.violations != tc.wantViolations {
				t.Errorf("violations = %d, want %d", got.violations, tc.wantViolations)
			}
		})
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
