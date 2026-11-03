package tokenendpoint_test

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/revocation"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// beforeSaveRefreshStore runs a hook immediately before a refresh token is
// persisted, so a test can complete a revocation inside the window between
// the endpoint's last closure check and the write that revocation cannot see.
type beforeSaveRefreshStore struct {
	store.RefreshTokenStore
	beforeSave func(saved *store.RefreshToken)
}

func (s beforeSaveRefreshStore) Save(ctx context.Context, rt *store.RefreshToken) error {
	s.beforeSave(rt)
	return s.RefreshTokenStore.Save(ctx, rt)
}

func (s beforeSaveRefreshStore) SaveRotationWithRetry(ctx context.Context, successor *store.RefreshToken, sealed []byte) error {
	s.beforeSave(successor)
	return s.RefreshTokenStore.(store.RefreshRetryResponseStore).SaveRotationWithRetry(ctx, successor, sealed)
}

func (s beforeSaveRefreshStore) LoadRetryResponse(ctx context.Context, predecessorID string) ([]byte, error) {
	return s.RefreshTokenStore.(store.RefreshRetryResponseStore).LoadRetryResponse(ctx, predecessorID)
}

// grantClosureStore swaps the non-transactional refresh substore for a
// hooked one and lets a hook run once each transaction has committed.
type grantClosureStore struct {
	store.Store
	refreshTokens store.RefreshTokenStore
	beforeSave    func(saved *store.RefreshToken)
	afterCommit   func()
}

func (s grantClosureStore) RefreshTokens() store.RefreshTokenStore { return s.refreshTokens }

func (s grantClosureStore) BeginTx(ctx context.Context) (store.Tx, error) {
	inner, err := s.Store.(store.Transactional).BeginTx(ctx)
	if err != nil {
		return nil, err
	}
	return grantClosureTx{Tx: inner, s: s}, nil
}

type grantClosureTx struct {
	store.Tx
	s grantClosureStore
}

func (t grantClosureTx) RefreshTokens() store.RefreshTokenStore {
	return beforeSaveRefreshStore{RefreshTokenStore: t.Tx.RefreshTokens(), beforeSave: t.s.beforeSave}
}

func (t grantClosureTx) Commit() error {
	if err := t.Tx.Commit(); err != nil {
		return err
	}
	t.s.afterCommit()
	return nil
}

// grantClosureFixture builds a provider over a hooked reference store.
// beforeSave fires before every refresh-token write; afterCommit after every
// committed transaction.
func grantClosureFixture(
	tb testing.TB,
	beforeSave func(saved *store.RefreshToken),
	afterCommit func(),
	opts ...op.Option,
) (*fixture, *inmem.Store) {
	tb.Helper()
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	backing := inmem.New(inmem.WithClock(clock))
	decorated := grantClosureStore{
		Store:         backing,
		refreshTokens: beforeSaveRefreshStore{RefreshTokenStore: backing.RefreshTokens(), beforeSave: beforeSave},
		beforeSave:    beforeSave,
		afterCommit:   afterCommit,
	}
	prov := testkit.NewProvider(tb,
		testkit.WithClock(clock),
		testkit.WithOptions(append([]op.Option{op.WithStore(decorated), op.WithUserStore(backing.Users())}, opts...)...),
	)
	prov.Store = backing
	return &fixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/token",
		clock:    clock,
	}, backing
}

// requireRefusedWithoutCredentials asserts an RFC 6749 §5.2 invalid_grant
// that hands out nothing.
func requireRefusedWithoutCredentials(tb testing.TB, resp *http.Response, label string) {
	tb.Helper()
	body := decodeJSON(tb, resp)
	if resp.StatusCode != http.StatusBadRequest || body["error"] != "invalid_grant" {
		tb.Fatalf("%s: status=%d body=%v, want 400 invalid_grant", label, resp.StatusCode, body)
	}
	for _, member := range []string{"access_token", "refresh_token"} {
		if _, ok := body[member]; ok {
			tb.Errorf("%s: refused response carries %s", label, member)
		}
	}
}

// requireRefreshRevoked asserts the persisted refresh token can no longer be
// redeemed.
func requireRefreshRevoked(tb testing.TB, backing *inmem.Store, token, label string) {
	tb.Helper()
	if token == "" {
		tb.Fatalf("%s: no refresh token was persisted; the race was never exercised", label)
	}
	rec, err := backing.RefreshTokens().Find(context.Background(), token)
	if err != nil {
		tb.Fatalf("%s: Find: %v", label, err)
	}
	if !rec.Revoked {
		tb.Errorf("%s: the refresh token persisted after the revocation is still redeemable", label)
	}
}

// TestAuthCode_CodeReplayDuringRefreshSave_LeavesNoLiveRefreshToken drives the
// RFC 6749 §4.1.2 race: the legitimate client replays the code while the
// winning redemption is between its last check and its refresh-token write,
// so the replay's grant teardown cannot see that refresh token. Whatever the
// JWT revocation strategy, the winner must not walk away with a live chain.
func TestAuthCode_CodeReplayDuringRefreshSave_LeavesNoLiveRefreshToken(t *testing.T) {
	t.Parallel()

	for name, strategy := range map[string]op.AccessTokenRevocationStrategy{
		"grant_tombstone": op.RevocationStrategyGrantTombstone,
		"jti_registry":    op.RevocationStrategyJTIRegistry,
		"none":            op.RevocationStrategyNone,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			const codeID = "code-replay-race"
			const grantID = "grant-replay-race"
			const redirect = "https://rp.example/cb"
			verifier, challenge := pkcePair()
			var (
				f        *fixture
				client   *store.Client
				secret   string
				saved    string
				replayed atomic.Bool
			)
			f, backing := grantClosureFixture(t, func(rt *store.RefreshToken) {
				if replayed.Swap(true) {
					return
				}
				saved = rt.ID
				replay := f.post(t, authCodeForm(codeID, redirect, verifier), client.ID, secret)
				defer func() { _ = replay.Body.Close() }()
				if replay.StatusCode != http.StatusBadRequest {
					t.Errorf("replay status=%d want 400", replay.StatusCode)
				}
			}, func() {}, op.WithAccessTokenRevocationStrategy(strategy))
			client, secret = f.confidentialClientFixture(t)
			f.seedGrant(t, &store.Grant{
				ID: grantID, Subject: "user-1", ClientID: client.ID,
				Scope: []string{"openid", "offline_access"},
			})
			f.seedAuthCode(t, &store.AuthorizationCode{
				ID:                  codeID,
				ClientID:            client.ID,
				Subject:             "user-1",
				GrantID:             grantID,
				RedirectURI:         redirect,
				Scope:               []string{"openid", "offline_access"},
				CodeChallenge:       challenge,
				CodeChallengeMethod: "S256",
			})

			resp := f.post(t, authCodeForm(codeID, redirect, verifier), client.ID, secret)
			defer func() { _ = resp.Body.Close() }()
			requireRefusedWithoutCredentials(t, resp, "winning redemption")
			requireRefreshRevoked(t, backing, saved, "winning redemption")
		})
	}
}

// TestRefresh_GrantRevokedAfterRotationCheck_RetiresSuccessor covers a grant
// revocation that lands while a rotation is in flight and cannot see its
// uncommitted successor: its refresh-token rung ran before the successor
// committed, and only its closure record is visible afterwards. Whatever the
// JWT revocation strategy, the rotation must then refuse and retire the
// successor rather than hand out a chain that outlives the revocation.
func TestRefresh_GrantRevokedAfterRotationCheck_RetiresSuccessor(t *testing.T) {
	t.Parallel()

	for name, strategy := range map[string]op.AccessTokenRevocationStrategy{
		"grant_tombstone": op.RevocationStrategyGrantTombstone,
		"jti_registry":    op.RevocationStrategyJTIRegistry,
		"none":            op.RevocationStrategyNone,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			const grantID = "grant-rotation-race"
			const presented = "rt-rotation-race"
			var (
				successor string
				armed     atomic.Bool
				backing   *inmem.Store
				f         *fixture
			)
			f, backing = grantClosureFixture(t, func(rt *store.RefreshToken) {
				if armed.Load() {
					successor = rt.ID
				}
			}, func() {
				if !armed.Swap(false) {
					return
				}
				out := revocation.NewRevoker(backing.RefreshTokens(), backing.OpaqueAccessTokens(),
					backing.AccessTokens(), backing.GrantRevocations(), strategy, time.Hour, f.clock.now, "operator").
					Run(context.Background(), revocation.CompromisedGrantAccessTokens(grantID))
				if !out.Complete() {
					t.Errorf("revocation: %v", out.Err())
				}
			}, op.WithAccessTokenRevocationStrategy(strategy))
			client, secret := f.confidentialClientFixture(t)
			f.seedGrant(t, &store.Grant{
				ID: grantID, Subject: "user-1", ClientID: client.ID,
				Scope: []string{"openid", "offline_access"},
			})
			f.seedUser(t, "user-1")
			f.seedRefreshToken(t, &store.RefreshToken{
				ID:        presented,
				ClientID:  client.ID,
				Subject:   "user-1",
				GrantID:   grantID,
				Scope:     []string{"openid", "offline_access"},
				CreatedAt: f.clock.now.Add(-time.Minute),
			})

			armed.Store(true)
			resp := f.post(t, refreshForm(presented, ""), client.ID, secret)
			defer func() { _ = resp.Body.Close() }()
			requireRefusedWithoutCredentials(t, resp, "rotation racing the revocation")
			requireRefreshRevoked(t, backing, successor, "rotated successor")
		})
	}
}
