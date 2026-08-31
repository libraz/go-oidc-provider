package tokenendpoint

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/op/store"
)

// grantBoundRefreshStore resolves every presented value to one record
// carrying grantID, so a replay cascade run against it has a grant to
// key its access-token half on. The mutating methods are no-ops: the
// chain half of the cascade is not what these tests observe.
type grantBoundRefreshStore struct {
	grantID string
}

func (s grantBoundRefreshStore) Save(context.Context, *store.RefreshToken) error { return nil }

func (s grantBoundRefreshStore) Find(_ context.Context, id string) (*store.RefreshToken, error) {
	return &store.RefreshToken{ID: id, GrantID: s.grantID}, nil
}

func (s grantBoundRefreshStore) Consume(context.Context, string) (*store.RefreshToken, error) {
	return nil, store.ErrNotFound
}

func (s grantBoundRefreshStore) RevokeChain(context.Context, string) error { return nil }

func (s grantBoundRefreshStore) RevokeByGrant(context.Context, string) error { return nil }

// faultyOpaqueAccessTokenStore fails the grant-scoped revoke and nothing
// else, so a test can observe how the cascade reports a substore that
// cannot be reached.
type faultyOpaqueAccessTokenStore struct {
	err error
}

func (s faultyOpaqueAccessTokenStore) Save(context.Context, *store.OpaqueAccessToken) error {
	return nil
}

func (s faultyOpaqueAccessTokenStore) Find(context.Context, string) (*store.OpaqueAccessToken, error) {
	return nil, store.ErrNotFound
}

func (s faultyOpaqueAccessTokenStore) RevokeByID(context.Context, string) error { return nil }

func (s faultyOpaqueAccessTokenStore) RevokeByGrant(context.Context, string) (int, error) {
	return 0, s.err
}

func (s faultyOpaqueAccessTokenStore) GC(context.Context, time.Time) (int, error) { return 0, nil }

// findWarn returns the first warn-level event named name, or nil.
func findWarn(events []audit.Event, name string) *audit.Event {
	for i := range events {
		if events[i].Name == name && events[i].Level == audit.LevelWarn {
			return &events[i]
		}
	}
	return nil
}

// TestReplayCascade_UnresolvedGrantIsReported pins the state the replay
// cascade must never pass over in silence: it confirmed a replay, and
// then found no grant to retire the access tokens of.
//
// "Nothing was revoked because the grant is unknown" and "nothing was
// revoked because there was nothing to revoke" are indistinguishable on
// the wire — both answer invalid_grant — and only the first leaves an
// attacker's access token live. The audit record is the only place the
// difference exists.
func TestReplayCascade_UnresolvedGrantIsReported(t *testing.T) {
	t.Parallel()

	capture := &captureEmitter{}
	deps := Deps{
		Clock:              fixedClock{now: time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)},
		Audit:              capture,
		RefreshTokens:      &captureRefreshStore{},
		RevocationStrategy: store.RevocationStrategyGrantTombstone,
	}
	cascade := &replayCascade{}
	cascade.arm("stolen-refresh-token")

	cascade.run(context.Background(), deps)

	ev := findWarn(capture.events, auditRefreshGrantRevokeFailed)
	if ev == nil {
		t.Fatalf("no warn-level %s event; capture=%+v", auditRefreshGrantRevokeFailed, capture.events)
	}
	if got := ev.Extras["surface"]; got != teardownReasonRefreshReplay {
		t.Errorf("extras.surface=%v want %q", got, teardownReasonRefreshReplay)
	}
	if got := ev.Extras["err"]; got != "grant_unresolved" {
		t.Errorf("extras.err=%v want grant_unresolved", got)
	}
}

// TestReplayCascade_SubstoreFaultIsReported pins the other half: the
// grant resolved, so the cascade knew exactly which access tokens to
// retire, and the substore refused. The request keeps its invalid_grant
// answer either way, which is precisely why the failure has to reach
// the audit stream.
func TestReplayCascade_SubstoreFaultIsReported(t *testing.T) {
	t.Parallel()

	capture := &captureEmitter{}
	deps := Deps{
		Clock:              fixedClock{now: time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)},
		Audit:              capture,
		RefreshTokens:      grantBoundRefreshStore{grantID: "grant-1"},
		OpaqueAccessTokens: faultyOpaqueAccessTokenStore{err: errors.New("synthetic opaque substore fault")},
		RevocationStrategy: store.RevocationStrategyNone,
	}
	cascade := &replayCascade{}
	cascade.arm("stolen-refresh-token")

	cascade.run(context.Background(), deps)

	ev := findWarn(capture.events, auditRefreshGrantRevokeFailed)
	if ev == nil {
		t.Fatalf("no warn-level %s event; capture=%+v", auditRefreshGrantRevokeFailed, capture.events)
	}
	if got := ev.Extras["surface"]; got != teardownReasonRefreshReplay+"_opaque_access_tokens" {
		t.Errorf("extras.surface=%v want %q", got, teardownReasonRefreshReplay+"_opaque_access_tokens")
	}
	if got := ev.Extras["grant_id"]; got != "grant-1" {
		t.Errorf("extras.grant_id=%v want grant-1", got)
	}
}
