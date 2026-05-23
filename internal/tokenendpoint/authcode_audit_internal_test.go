package tokenendpoint

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/op/store"
)

type captureEmitter struct {
	events []audit.Event
}

func (e *captureEmitter) Emit(_ context.Context, ev audit.Event) {
	e.events = append(e.events, ev)
}

type faultyGrantRevocationStore struct {
	err error
}

func (f faultyGrantRevocationStore) RevokeGrant(context.Context, store.GrantTombstone) error {
	return f.err
}

func (f faultyGrantRevocationStore) RevokeJTI(context.Context, store.RevokedJTI) error {
	return nil
}

func (f faultyGrantRevocationStore) IsRevoked(context.Context, string, string, time.Time) (bool, error) {
	return false, nil
}

func (f faultyGrantRevocationStore) GC(context.Context, time.Time) (int, error) { return 0, nil }

func TestRevokeJWTAccessTokensForGrant_StoreFault_EmitsAudit(t *testing.T) {
	t.Parallel()

	const grantID = "grant-replay-audit-1"
	capture := &captureEmitter{}
	deps := Deps{
		Clock: fixedClock{now: time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)},
		Audit: capture,
		GrantRevocations: faultyGrantRevocationStore{
			err: errors.New("simulated grant revocation fault"),
		},
		RevocationStrategy: store.RevocationStrategyGrantTombstone,
		AccessTokenTTL:     5 * time.Minute,
	}

	revokeJWTAccessTokensForGrant(context.Background(), deps, grantID)

	if len(capture.events) != 1 {
		t.Fatalf("events=%d want 1", len(capture.events))
	}
	ev := capture.events[0]
	if ev.Name != auditTokenRevokeFailed {
		t.Fatalf("event=%q want %q", ev.Name, auditTokenRevokeFailed)
	}
	if ev.Level != audit.LevelWarn {
		t.Fatalf("level=%v want %v", ev.Level, audit.LevelWarn)
	}
	if got := ev.Extras["surface"]; got != "code_replay_jwt_access_tokens" {
		t.Fatalf("extras.surface=%v want code_replay_jwt_access_tokens", got)
	}
	if got := ev.Extras["grant_id"]; got != grantID {
		t.Fatalf("extras.grant_id=%v want %q", got, grantID)
	}
	if got := ev.Extras["err"]; got != "simulated grant revocation fault" {
		t.Fatalf("extras.err=%v want simulated grant revocation fault", got)
	}
}

func TestRevokeChainForCode_UsesReplayGrantIDWhenFindCannotRecoverConsumedCode(t *testing.T) {
	t.Parallel()

	refreshes := &captureRefreshStore{}
	deps := Deps{
		Codes:              panicFindCodeStore{},
		RefreshTokens:      refreshes,
		RevocationStrategy: store.RevocationStrategyNone,
	}

	revokeChainForCode(context.Background(), deps, "code-1", "grant-1")

	if got := refreshes.revokedGrantID(); got != "grant-1" {
		t.Fatalf("revoked grant=%q want grant-1", got)
	}
}

type fixedClock struct{ now time.Time }

func (f fixedClock) Now() time.Time { return f.now }

type panicFindCodeStore struct{}

func (panicFindCodeStore) Save(context.Context, *store.AuthorizationCode) error { return nil }

func (panicFindCodeStore) Find(context.Context, string) (*store.AuthorizationCode, error) {
	panic("Find should not be needed when replay error carries GrantID")
}

func (panicFindCodeStore) Consume(context.Context, string) (*store.AuthorizationCode, error) {
	return nil, store.ErrAlreadyConsumed
}

type captureRefreshStore struct {
	mu      sync.Mutex
	grantID string
}

func (s *captureRefreshStore) Save(context.Context, *store.RefreshToken) error { return nil }

func (s *captureRefreshStore) Find(context.Context, string) (*store.RefreshToken, error) {
	return nil, store.ErrNotFound
}

func (s *captureRefreshStore) Consume(context.Context, string) (*store.RefreshToken, error) {
	return nil, store.ErrNotFound
}

func (s *captureRefreshStore) RevokeChain(context.Context, string) error { return nil }

func (s *captureRefreshStore) RevokeByGrant(_ context.Context, grantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.grantID = grantID
	return nil
}

func (s *captureRefreshStore) revokedGrantID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.grantID
}
