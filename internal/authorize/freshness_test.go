package authorize_test

import (
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authorize"
)

// TestAuthenticationIsStale_MonotoneAcrossTheDurationBoundary pins the
// property every max_age gate in the OP depends on: raising max_age
// never turns a fresh authentication stale.
//
// The values straddle the point where a second count no longer fits in a
// [time.Duration] (about 9.2e9 seconds). Widening max_age into a
// duration wraps there, which flips the comparison and makes a request
// asking for a centuries-long window stricter than one asking for a day.
func TestAuthenticationIsStale_MonotoneAcrossTheDurationBoundary(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	// A 72-hour-old authentication: 259200 seconds.
	authTime := now.Add(-72 * time.Hour)

	rows := []struct {
		maxAge    int64
		wantStale bool
	}{
		{maxAge: 0, wantStale: true},
		{maxAge: 60, wantStale: true},
		{maxAge: 259199, wantStale: true},
		{maxAge: 259200, wantStale: false},
		{maxAge: 259201, wantStale: false},
		// The last max_age whose nanosecond widening still fits in a
		// time.Duration, and the first one that does not.
		{maxAge: 9223372036, wantStale: false},
		{maxAge: 9223372037, wantStale: false},
		// A value whose widening wraps to a fraction of a second.
		{maxAge: 18446744074, wantStale: false},
		{maxAge: 99999999999, wantStale: false},
	}

	staleUntil := int64(-1)
	for _, row := range rows {
		got := authorize.AuthenticationIsStale(authTime, now, row.maxAge)
		if got != row.wantStale {
			t.Errorf("AuthenticationIsStale(max_age=%d) = %v, want %v", row.maxAge, got, row.wantStale)
		}
		if got {
			staleUntil = row.maxAge
			continue
		}
		if row.maxAge < staleUntil {
			t.Errorf("max_age=%d is fresh while the smaller %d was stale: the predicate is not monotone",
				row.maxAge, staleUntil)
		}
	}
}

// TestAuthenticationIsStale_Edges covers the two inputs that are stale
// regardless of elapsed time, and the clock skew case where the
// authentication is timestamped after now.
func TestAuthenticationIsStale_Edges(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	if !authorize.AuthenticationIsStale(now, now, 0) {
		t.Error("max_age=0 must demand a fresh authentication")
	}
	if !authorize.AuthenticationIsStale(time.Time{}, now, 99999999999) {
		t.Error("an authentication that never happened must not satisfy any max_age")
	}
	if authorize.AuthenticationIsStale(now.Add(time.Minute), now, 1) {
		t.Error("an authentication timestamped ahead of now must not read as stale")
	}
	if authorize.AuthenticationIsStale(now.Add(-time.Second), now, 1) {
		t.Error("elapsed exactly at the bound is within max_age")
	}
	if !authorize.AuthenticationIsStale(now.Add(-2*time.Second), now, 1) {
		t.Error("elapsed past the bound must read as stale")
	}
}
