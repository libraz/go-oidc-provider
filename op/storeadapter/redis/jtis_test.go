package oidcredis //nolint:testpackage // tests exercise unexported JTI marker helpers.

import (
	"strconv"
	"testing"
	"time"
)

// TestDecodeJTIExpiry covers the marker encoding Mark writes and Has
// reads back. The round trip has to be exact at microsecond resolution,
// because Has compares the decoded instant against the adapter clock to
// decide whether a marker is still live, and it has to be fail-secure
// for anything it does not recognise: a value that decodes to "no
// expiry" keeps reporting the jti consumed, whereas one that wrongly
// decoded to a past instant would let a replay through.
func TestDecodeJTIExpiry(t *testing.T) {
	t.Parallel()

	expiresAt := time.Date(2026, 5, 4, 12, 0, 0, 123456000, time.UTC)
	encoded := expiringJTIPrefix + strconv.FormatInt(expiresAt.UnixMicro(), 10)
	if got := decodeJTIExpiry(encoded); !got.Equal(expiresAt) {
		t.Fatalf("round trip = %v, want %v", got, expiresAt)
	}

	// Every value that is not an encoded expiry means "never expires",
	// which keeps the marker live on every read.
	for _, raw := range []string{
		persistentJTIValue,
		"1",         // a value this adapter did not write
		"e",         // prefix with no digits
		"enotanint", // prefix with a non-numeric payload
		"",
	} {
		if got := decodeJTIExpiry(raw); !got.IsZero() {
			t.Errorf("decodeJTIExpiry(%q) = %v, want the zero time", raw, got)
		}
	}
}

// TestCeilMillisNeverShortensTheTTL pins that a sub-millisecond remainder
// rounds up: a truncated PX would let Redis reclaim a replay marker while
// the adapter clock still reads it live.
func TestCeilMillisNeverShortensTheTTL(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		ttl  time.Duration
		want int64
	}{
		{time.Nanosecond, 1},
		{time.Millisecond, 1},
		{time.Millisecond + time.Nanosecond, 2},
		{1500 * time.Microsecond, 2},
		{time.Second, 1000},
	} {
		if got := ceilMillis(tc.ttl); got != tc.want {
			t.Errorf("ceilMillis(%v) = %d, want %d", tc.ttl, got, tc.want)
		}
	}
}
