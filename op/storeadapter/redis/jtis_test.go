package oidcredis

import (
	"testing"
	"time"
)

func TestJTITTLFloorsShortFutureExpiry(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	if got := jtiTTL(now, now.Add(time.Second)); got != minJTITTL {
		t.Fatalf("jtiTTL short future = %v, want %v", got, minJTITTL)
	}
	if got := jtiTTL(now, now.Add(2*time.Minute)); got != 2*time.Minute {
		t.Fatalf("jtiTTL long future = %v, want 2m", got)
	}
	if got := jtiTTL(now, now.Add(-time.Second)); got > 0 {
		t.Fatalf("jtiTTL past = %v, want non-positive", got)
	}
}
