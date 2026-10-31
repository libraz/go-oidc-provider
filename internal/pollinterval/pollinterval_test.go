package pollinterval_test

import (
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/pollinterval"
)

func TestDecide(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	base := pollinterval.Input{
		Now:               now,
		EffectiveInterval: pollinterval.DefaultInterval,
		ExpiresAt:         now.Add(time.Minute),
	}
	with := func(f func(*pollinterval.Input)) pollinterval.Input {
		in := base
		f(&in)
		return in
	}
	tests := []struct {
		name string
		in   pollinterval.Input
		want pollinterval.Outcome
	}{
		{"consumed wins over expired", with(func(i *pollinterval.Input) { i.Consumed = true; i.ExpiresAt = now }), pollinterval.OutcomeConsumed},
		{"expired wins over denied", with(func(i *pollinterval.Input) { i.Denied = true; i.ExpiresAt = now }), pollinterval.OutcomeExpired},
		{"denied", with(func(i *pollinterval.Input) { i.Denied = true }), pollinterval.OutcomeDenied},
		{"strike cap", with(func(i *pollinterval.Input) { i.PollViolations = pollinterval.MaxPollViolations }), pollinterval.OutcomeDenied},
		{"strike cap override", with(func(i *pollinterval.Input) { i.PollViolations = 2; i.MaxPollViolations = 2 }), pollinterval.OutcomeDenied},
		{"fast poll", with(func(i *pollinterval.Input) { i.LastPolledAt = now.Add(-100 * time.Millisecond) }), pollinterval.OutcomeSlowDown},
		{"inside tolerance", with(func(i *pollinterval.Input) {
			i.LastPolledAt = now.Add(-(pollinterval.DefaultInterval - 100*time.Millisecond))
		}), pollinterval.OutcomePending},
		{"approved", with(func(i *pollinterval.Input) { i.Approved = true }), pollinterval.OutcomeEmit},
		{"pending", base, pollinterval.OutcomePending},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := pollinterval.Decide(tc.in).Outcome; got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSlowDownLadder(t *testing.T) {
	t.Parallel()
	if got := pollinterval.NextInterval(0); got != pollinterval.DefaultInterval {
		t.Errorf("NextInterval(0) = %v, want default", got)
	}
	if got := pollinterval.NextInterval(10 * time.Second); got != 10*time.Second+pollinterval.SlowDownIncrement {
		t.Errorf("NextInterval(10s) = %v", got)
	}
	if got := pollinterval.IntervalBar(0); got != 0 {
		t.Errorf("IntervalBar(0) = %v, want 0", got)
	}
	if got := pollinterval.IntervalBar(5 * time.Second); got != 4*time.Second {
		t.Errorf("IntervalBar(5s) = %v, want 4s", got)
	}
}
