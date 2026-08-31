package tokenendpoint

import (
	"testing"
	"time"
)

func TestTombstoneRetention_DefaultsWhenAccessTokenTTLUnset(t *testing.T) {
	t.Parallel()

	got := tombstoneRetention(Deps{})
	want := defaultAccessTokenTTL + tombstoneGrace
	if got != want {
		t.Fatalf("tombstoneRetention=%v want %v", got, want)
	}
}

func TestTombstoneRetention_AddsGraceToConfiguredTTL(t *testing.T) {
	t.Parallel()

	got := tombstoneRetention(Deps{AccessTokenTTL: 42 * time.Minute})
	want := 42*time.Minute + tombstoneGrace
	if got != want {
		t.Fatalf("tombstoneRetention=%v want %v", got, want)
	}
}
