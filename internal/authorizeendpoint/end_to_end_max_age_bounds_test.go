package authorizeendpoint_test

import (
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/testkit"
)

// TestEndToEnd_MaxAgeIsMonotoneAtEveryAcceptedValue drives /authorize
// with a live session and walks max_age across the whole range the
// parser accepts.
//
// max_age is a relaxation the relying party controls, so the only thing
// the OP owes it is a monotone reading: raising the value must never
// make the gate stricter. Widening it into a [time.Duration] breaks
// that — the nanosecond product wraps past roughly 9.2e9 seconds, and
// the bands beyond it alternate between "everything is stale" and
// "nothing is", so an RP asking for a decade is refused while one asking
// for a day is served.
//
// The observable is the /authorize outcome itself: a session the request
// may be served from mints a code without an interaction, and a stale
// one redirects to the credential ceremony.
func TestEndToEnd_MaxAgeIsMonotoneAtEveryAcceptedValue(t *testing.T) {
	t.Parallel()

	const sessionAge = 72 * time.Hour
	rows := []struct {
		maxAge    int64
		wantFresh bool
	}{
		{maxAge: 60},
		{maxAge: int64(sessionAge.Seconds()) - 1},
		{maxAge: int64(sessionAge.Seconds()), wantFresh: true},
		// The last value whose widening still fits in a time.Duration,
		// and the first one that does not.
		{maxAge: 9223372036, wantFresh: true},
		{maxAge: 9223372037, wantFresh: true},
		// A value whose widening wraps to a fraction of a second.
		{maxAge: 18446744074, wantFresh: true},
		{maxAge: 99999999999, wantFresh: true},
	}

	clock := newMovableClock(time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC))
	f := newE2EFlow(t, "rp-max-age-bounds", testkit.WithClock(clock))
	f.completeLogin(t, f.authorize(t, f.values()), "user-max-age")
	clock.Advance(sessionAge)

	staleUntil := int64(-1)
	for _, row := range rows {
		values := f.values()
		values.Set("max_age", strconv.FormatInt(row.maxAge, 10))
		loc := f.authorize(t, values)
		fresh := loc.Query().Get("code") != ""
		if fresh != row.wantFresh {
			t.Errorf("max_age=%d served from the %v-old session = %v, want %v (redirect %s)",
				row.maxAge, sessionAge, fresh, row.wantFresh, loc)
		}
		if !fresh {
			staleUntil = row.maxAge
			continue
		}
		if row.maxAge < staleUntil {
			t.Errorf("max_age=%d was served while the smaller %d demanded re-authentication",
				row.maxAge, staleUntil)
		}
	}
}

// TestEndToEnd_MaxAgeZeroAlwaysReauthenticates keeps the other end of
// the range pinned: max_age=0 asks for an authentication performed just
// now, which no existing session can satisfy.
func TestEndToEnd_MaxAgeZeroAlwaysReauthenticates(t *testing.T) {
	t.Parallel()

	clock := newMovableClock(time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC))
	f := newE2EFlow(t, "rp-max-age-zero", testkit.WithClock(clock))
	f.completeLogin(t, f.authorize(t, f.values()), "user-max-age-zero")

	values := f.values()
	values.Set("max_age", "0")
	loc := f.authorize(t, url.Values(values))
	if code := loc.Query().Get("code"); code != "" {
		t.Fatalf("max_age=0 was served from the existing session: %s", loc)
	}
}
