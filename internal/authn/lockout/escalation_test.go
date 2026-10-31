package lockout_test

import (
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn/lockout"
)

func TestEscalate_Boundaries(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	cases := []struct {
		count     int
		wantLock  time.Duration
		wantReset bool
	}{
		{0, 0, false},
		{29, 0, false},
		{30, time.Hour, false},
		{31, time.Hour, false},
		{89, time.Hour, false},
		{90, 24 * time.Hour, true},
		{91, 24 * time.Hour, true},
	}
	for _, tc := range cases {
		lockedUntil, reset := lockout.Escalate(tc.count, now)
		if tc.wantLock == 0 {
			if !lockedUntil.IsZero() {
				t.Errorf("count %d: lockedUntil = %v, want zero", tc.count, lockedUntil)
			}
		} else if !lockedUntil.Equal(now.Add(tc.wantLock)) {
			t.Errorf("count %d: lockedUntil = %v, want %v", tc.count, lockedUntil, now.Add(tc.wantLock))
		}
		if reset != tc.wantReset {
			t.Errorf("count %d: resetRequired = %v, want %v", tc.count, reset, tc.wantReset)
		}
	}
}

func TestWindowExpired_Boundaries(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	cases := []struct {
		name  string
		first time.Time
		want  bool
	}{
		{"zero first failure", time.Time{}, false},
		{"just opened", now, false},
		{"exactly at window", now.Add(-lockout.CounterWindow), false},
		{"one nanosecond past window", now.Add(-lockout.CounterWindow - time.Nanosecond), true},
		{"long past", now.Add(-72 * time.Hour), true},
	}
	for _, tc := range cases {
		if got := lockout.WindowExpired(tc.first, now); got != tc.want {
			t.Errorf("%s: WindowExpired = %v, want %v", tc.name, got, tc.want)
		}
	}
}
