package tokenendpoint

import (
	"testing"
	"time"
)

func TestRefreshChainTombstoneTTL_DefaultsWhenAccessTokenTTLUnset(t *testing.T) {
	t.Parallel()

	got := refreshChainTombstoneTTL(Deps{})
	want := defaultAccessTokenTTL + 5*time.Minute
	if got != want {
		t.Fatalf("refreshChainTombstoneTTL=%v want %v", got, want)
	}
}
