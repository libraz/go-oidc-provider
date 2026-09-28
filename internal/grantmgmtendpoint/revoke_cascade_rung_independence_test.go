package grantmgmtendpoint_test

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/grantmgmtendpoint"
	"github.com/libraz/go-oidc-provider/op/store"
)

// spyOpaqueAccessTokenStore records whether RevokeByGrant was invoked, so
// a test can tell "attempted" from "skipped" independently of the call's
// outcome.
type spyOpaqueAccessTokenStore struct {
	store.OpaqueAccessTokenStore
	called atomic.Bool
}

func (s *spyOpaqueAccessTokenStore) RevokeByGrant(ctx context.Context, grantID string) (int, error) {
	s.called.Store(true)
	return s.OpaqueAccessTokenStore.RevokeByGrant(ctx, grantID)
}

// spyRefreshTokenStore is the refresh-token analogue of
// [spyOpaqueAccessTokenStore].
type spyRefreshTokenStore struct {
	store.RefreshTokenStore
	called atomic.Bool
}

func (s *spyRefreshTokenStore) RevokeByGrant(ctx context.Context, grantID string) error {
	s.called.Store(true)
	return s.RefreshTokenStore.RevokeByGrant(ctx, grantID)
}

// TestHandler_RevokeJWTFailureStillAttemptsOtherRungs pins the
// attempt-each-rung-independently invariant [teardown.Revoker.Run]
// shares with /revoke and /end_session: a JWT-cascade fault must not
// skip the opaque or refresh rungs. The old revokeGrantCascade returned
// on the first error, so the opaque and refresh spies below would never
// have observed a call.
func TestHandler_RevokeJWTFailureStillAttemptsOtherRungs(t *testing.T) {
	t.Parallel()

	var opaque *spyOpaqueAccessTokenStore
	var refresh *spyRefreshTokenStore
	f := newFixture(t, func(d *grantmgmtendpoint.Deps) {
		d.RevokeEnabled = true
		d.RevocationStrategy = store.RevocationStrategyJTIRegistry
		d.AccessTokens = revokeFailsAccessTokenRegistry{}
		opaque = &spyOpaqueAccessTokenStore{OpaqueAccessTokenStore: d.OpaqueAccessTokens}
		d.OpaqueAccessTokens = opaque
		refresh = &spyRefreshTokenStore{RefreshTokenStore: d.RefreshTokens}
		d.RefreshTokens = refresh
	})
	f.seedGrant(t, "grant-stuck")

	resp := f.do(t, http.MethodDelete, "grant-stuck")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500", resp.StatusCode)
	}
	if !opaque.called.Load() {
		t.Error("opaque access-token rung was skipped after the JWT rung failed")
	}
	if !refresh.called.Load() {
		t.Error("refresh-token rung was skipped after the JWT rung failed")
	}
}
