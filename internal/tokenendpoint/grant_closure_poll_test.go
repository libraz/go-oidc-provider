package tokenendpoint_test

import (
	"context"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/revocation"
	"github.com/libraz/go-oidc-provider/internal/tokenendpoint"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// revokeSubjectGrants performs the teardown RevokeSubject runs: every grant
// the subject holds is listed and revoked under strategy.
func revokeSubjectGrants(tb testing.TB, s *inmem.Store, strategy store.AccessTokenRevocationStrategy, now time.Time, subject string) int {
	tb.Helper()
	ctx := context.Background()
	list, err := s.Grants().ListBySubject(ctx, subject)
	if err != nil {
		tb.Fatalf("ListBySubject: %v", err)
	}
	revoker := revocation.Revoker{
		RefreshTokens:      s.RefreshTokens(),
		OpaqueAccessTokens: s.OpaqueAccessTokens(),
		AccessTokens:       s.AccessTokens(),
		GrantRevocations:   s.GrantRevocations(),
		Strategy:           strategy,
		Now:                now,
		TombstoneRetention: revocation.TombstoneRetention(time.Hour),
		Reason:             "subject_revoked",
	}
	for _, g := range list {
		if err := revoker.RevokeGrant(ctx, s.Grants(), g.ID); err != nil {
			tb.Fatalf("RevokeGrant %s: %v", g.ID, err)
		}
	}
	return len(list)
}

// TestPolledGrant_SubjectRevokedDuringRefreshSave_LeavesNoLiveRefreshToken
// drives a subject revocation that lands after a device_code or CIBA poll
// recorded its grant but before its refresh token was written, so the
// teardown cannot see that refresh token. Whatever the JWT revocation
// strategy, the poll must not hand out a chain that outlives the revocation.
func TestPolledGrant_SubjectRevokedDuringRefreshSave_LeavesNoLiveRefreshToken(t *testing.T) {
	t.Parallel()

	const subject = "user-poll-race"
	type polled struct {
		store *inmem.Store
		deps  *tokenendpoint.Deps
		now   time.Time
		poll  func(t *testing.T) int
	}
	grants := map[string]func(t *testing.T) polled{
		"device_code": func(t *testing.T) polled {
			f := newDeviceCodeFixture(t)
			const deviceCode = "device-code-revoke-race"
			f.seedDeviceCode(t, &store.DeviceCode{ID: deviceCode, UserCode: "WXYZ-RACE", Scope: []string{"openid"}})
			if err := f.store.DeviceCodes().Approve(context.Background(), deviceCode, subject, time.Time{}); err != nil {
				t.Fatalf("Approve: %v", err)
			}
			form := url.Values{"grant_type": {devCodeGrantURN}, "device_code": {deviceCode}}
			return polled{store: f.store, deps: &f.deps, now: f.clock.now, poll: func(t *testing.T) int { return f.post(t, form).Code }}
		},
		"ciba": func(t *testing.T) polled {
			f := newCIBAFixture(t)
			const authReqID = "auth-req-revoke-race"
			f.seedCIBARequest(t, &store.CIBARequest{ID: authReqID, Scope: []string{"openid"}})
			if err := f.store.CIBARequests().Approve(context.Background(), authReqID, subject, "", time.Time{}); err != nil {
				t.Fatalf("Approve: %v", err)
			}
			form := url.Values{"grant_type": {"urn:openid:params:grant-type:ciba"}, "auth_req_id": {authReqID}}
			return polled{store: f.store, deps: &f.deps, now: f.clock.now, poll: func(t *testing.T) int { return f.post(t, form).Code }}
		},
	}
	strategies := map[string]store.AccessTokenRevocationStrategy{
		"grant_tombstone": store.RevocationStrategyGrantTombstone,
		"jti_registry":    store.RevocationStrategyJTIRegistry,
		"none":            store.RevocationStrategyNone,
	}
	for grantName, build := range grants {
		for strategyName, strategy := range strategies {
			t.Run(grantName+"/"+strategyName, func(t *testing.T) {
				t.Parallel()
				p := build(t)
				seedSubject(t, p.store, subject)
				p.deps.RevocationStrategy = strategy
				p.deps.GrantRevocations = p.store.GrantRevocations()
				p.deps.OpaqueAccessTokens = p.store.OpaqueAccessTokens()

				var (
					saved   string
					revoked int
					fired   atomic.Bool
				)
				p.deps.RefreshTokens = beforeSaveRefreshStore{
					RefreshTokenStore: p.store.RefreshTokens(),
					beforeSave: func(rt *store.RefreshToken) {
						if fired.Swap(true) {
							return
						}
						saved = rt.ID
						revoked = revokeSubjectGrants(t, p.store, strategy, p.now.Add(time.Second), subject)
					},
				}

				if code := p.poll(t); code != http.StatusBadRequest {
					t.Fatalf("poll status = %d, want 400 invalid_grant", code)
				}
				if revoked == 0 {
					t.Fatal("the revocation listed no grant; the race was never exercised")
				}
				requireRefreshRevoked(t, p.store, saved, "polled refresh token")
			})
		}
	}
}
