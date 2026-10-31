package tokenendpoint

import (
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/revocation"
)

// The token endpoint's replay cascades must write tombstones with the same
// retention /revoke, /end_session and grant management do, unset TTL included.
func TestGrantTeardown_RetentionMatchesSharedFormula(t *testing.T) {
	t.Parallel()

	for _, ttl := range []time.Duration{0, -time.Second, 42 * time.Minute} {
		got := grantTeardown(Deps{AccessTokenTTL: ttl}, teardownReasonRefreshReplay).TombstoneRetention
		if want := revocation.TombstoneRetention(ttl); got != want {
			t.Errorf("AccessTokenTTL=%v: TombstoneRetention=%v want %v", ttl, got, want)
		}
	}
}
