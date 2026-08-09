package tokenendpoint_test

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

var (
	errInjectedTxCommit    = errors.New("injected transaction commit failure")
	errInjectedChainRevoke = errors.New("injected chain revoke failure")
)

// cascadeFaultRefreshStore decorates the reference refresh substore so a test
// can fail the RFC 9700 §2.2.2 chain cascade's own write while every other
// refresh-token operation keeps working. The explicit forwards preserve the
// optional capabilities the token endpoint requires: an embedded interface
// alone would hide them and op.New would refuse to build the provider.
type cascadeFaultRefreshStore struct {
	store.RefreshTokenStore
	failRevokeChain *atomic.Bool
}

func (s cascadeFaultRefreshStore) RevokeChain(ctx context.Context, rootID string) error {
	if s.failRevokeChain.Load() {
		return errInjectedChainRevoke
	}
	return s.RefreshTokenStore.RevokeChain(ctx, rootID)
}

func (s cascadeFaultRefreshStore) SaveRotationWithRetry(
	ctx context.Context,
	successor *store.RefreshToken,
	sealed []byte,
) error {
	return s.RefreshTokenStore.(store.RefreshRetryResponseStore).SaveRotationWithRetry(ctx, successor, sealed)
}

func (s cascadeFaultRefreshStore) LoadRetryResponse(ctx context.Context, predecessorID string) ([]byte, error) {
	return s.RefreshTokenStore.(store.RefreshRetryResponseStore).LoadRetryResponse(ctx, predecessorID)
}

// replayCascadeStore decorates the reference Store so a test can steer the
// settle direction of the refresh transaction independently of the cascade
// that has to survive it.
type replayCascadeStore struct {
	store.Store
	refreshTokens store.RefreshTokenStore
	failCommit    *atomic.Bool
}

func (s replayCascadeStore) RefreshTokens() store.RefreshTokenStore { return s.refreshTokens }

func (s replayCascadeStore) BeginTx(ctx context.Context) (store.Tx, error) {
	inner, err := s.Store.(store.Transactional).BeginTx(ctx)
	if err != nil {
		return nil, err
	}
	return replayCascadeTx{Tx: inner, failCommit: s.failCommit}, nil
}

// replayCascadeTx fails Commit on demand WITHOUT settling the underlying
// transaction, so the handler's own deferred Rollback is what discards and
// releases it. That is the rollback direction the cascade has to survive.
type replayCascadeTx struct {
	store.Tx
	failCommit *atomic.Bool
}

func (t replayCascadeTx) Commit() error {
	if t.failCommit.Load() {
		return errInjectedTxCommit
	}
	return t.Tx.Commit()
}

// replayCascadeFixture bundles a provider whose store can be steered into the
// two faults the replay cascade must survive — a transaction that refuses to
// commit and a cascade write that fails — together with an audit capture.
type replayCascadeFixture struct {
	*fixture
	audit      *auditCapture
	failCommit *atomic.Bool
	failRevoke *atomic.Bool
}

// newReplayCascadeFixture builds the provider around now, which the caller
// advances to step past the RFC 9700 §2.2.2 grace window.
func newReplayCascadeFixture(tb testing.TB, now *time.Time) *replayCascadeFixture {
	tb.Helper()
	capture := newAuditCapture()
	clock := movableClock{cur: now}
	backing := inmem.New(inmem.WithClock(clock))
	failCommit := &atomic.Bool{}
	failRevoke := &atomic.Bool{}
	decorated := replayCascadeStore{
		Store: backing,
		refreshTokens: cascadeFaultRefreshStore{
			RefreshTokenStore: backing.RefreshTokens(),
			failRevokeChain:   failRevoke,
		},
		failCommit: failCommit,
	}
	prov := testkit.NewProvider(tb,
		testkit.WithClock(clock),
		testkit.WithOptions(
			op.WithStore(decorated),
			op.WithAuditLogger(capture.logger()),
		),
	)
	// NewProvider builds its own adapter for Provider.Store; point the seeding
	// helpers at the instance the decorated store actually wraps.
	prov.Store = backing
	return &replayCascadeFixture{
		fixture: &fixture{
			prov:     prov,
			endpoint: prov.Server.URL + "/oidc/token",
			clock:    fixedClock{now: *now},
		},
		audit:      capture,
		failCommit: failCommit,
		failRevoke: failRevoke,
	}
}

// rotateRefresh exchanges presented at the token endpoint and returns the
// successor the rotation minted.
func rotateRefresh(tb testing.TB, f *fixture, clientID, secret, presented string) string {
	tb.Helper()
	resp := f.post(tb, refreshForm(presented, ""), clientID, secret)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		tb.Fatalf("rotation status=%d want 200, body=%v", resp.StatusCode, decodeJSON(tb, resp))
	}
	rotated, _ := decodeJSON(tb, resp)["refresh_token"].(string)
	if rotated == "" {
		tb.Fatal("rotation returned no refresh_token")
	}
	return rotated
}

// assertRefreshRefused presents token and requires the RFC 6749 §5.2
// invalid_grant answer. label names the presentation so a failure says which
// of several requests in a test broke.
func assertRefreshRefused(tb testing.TB, f *fixture, clientID, secret, token, label string) {
	tb.Helper()
	resp := f.post(tb, refreshForm(token, ""), clientID, secret)
	defer func() { _ = resp.Body.Close() }()
	body := decodeJSON(tb, resp)
	if resp.StatusCode != http.StatusBadRequest {
		tb.Fatalf("%s: status=%d want 400, body=%v", label, resp.StatusCode, body)
	}
	if got := body["error"]; got != "invalid_grant" {
		tb.Errorf("%s: error=%v want invalid_grant", label, got)
	}
}

// assertChainNodeRevoked reads the persisted record straight from the store so
// the assertion covers the chain state itself rather than only what the wire
// happened to answer.
func assertChainNodeRevoked(tb testing.TB, f *fixture, token, label string) {
	tb.Helper()
	rec, err := f.prov.Store.RefreshTokens().Find(context.Background(), token)
	if err != nil {
		tb.Fatalf("%s: Find: %v", label, err)
	}
	if !rec.Revoked {
		tb.Errorf("%s: Revoked=false; the cascade left this chain node redeemable", label)
	}
}

// assertGrantTombstoned pins the JWT-access-token half of the cascade: the
// tombstone that blocks every token descended from the replayed grant at
// userinfo / introspection / mint time.
func assertGrantTombstoned(tb testing.TB, f *fixture, grantID string, issuedAt time.Time) {
	tb.Helper()
	revoked, err := f.prov.Store.GrantRevocations().IsRevoked(context.Background(), grantID, "", issuedAt)
	if err != nil {
		tb.Fatalf("IsRevoked: %v", err)
	}
	if !revoked {
		tb.Error("grant tombstone missing; the cascade retired the chain but not its access tokens")
	}
}

// seedReplayChain seeds a root refresh token, rotates it twice through the
// token endpoint, and returns the live chain tip. Three nodes are the minimum
// that distinguishes "the root and its immediate child were retired" from "the
// whole chain was retired".
func seedReplayChain(
	tb testing.TB,
	f *fixture,
	clientID, secret, seed, grantID string,
) (tip string) {
	tb.Helper()
	f.seedRefreshToken(tb, &store.RefreshToken{
		ID:       seed,
		ClientID: clientID,
		Subject:  "user-1",
		GrantID:  grantID,
		Scope:    []string{"openid"},
	})
	mid := rotateRefresh(tb, f, clientID, secret, seed)
	return rotateRefresh(tb, f, clientID, secret, mid)
}

// TestRefresh_ReplayCascadeRetiresChainAfterCommit pins the RFC 9700 §2.2.2
// cascade on the ordinary replay path, where the refresh transaction commits.
// Presenting a spent refresh token past the grace window MUST answer
// invalid_grant AND retire every node of the rotation chain — including the
// live tip, which is precisely the token a thief holding a stolen credential
// would present next — together with the grant tombstone that blocks the JWT
// access tokens descended from it.
//
// The cascade runs outside the transaction, so its size is not bounded by the
// backend's transaction-action limit and a chain longer than that limit cannot
// be retired only in part.
func TestRefresh_ReplayCascadeRetiresChainAfterCommit(t *testing.T) {
	t.Parallel()

	cur := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	issuedAt := cur
	f := newReplayCascadeFixture(t, &cur)
	client, secret := f.confidentialClientFixture(t)
	const seed = "rt-cascade-commit"
	const grantID = "grant-cascade-commit"

	tip := seedReplayChain(t, f.fixture, client.ID, secret, seed, grantID)

	// Past the grace window so the re-presentation is classified as theft
	// rather than as a retry of a lost response.
	cur = cur.Add(2 * time.Minute)

	assertRefreshRefused(t, f.fixture, client.ID, secret, seed, "replay")
	assertRefreshRefused(t, f.fixture, client.ID, secret, tip, "chain tip after replay")
	assertChainNodeRevoked(t, f.fixture, tip, "chain tip")
	assertGrantTombstoned(t, f.fixture, grantID, issuedAt)
}

// TestRefresh_ReplayCascadeRetiresChainAfterRollback pins the same cascade on
// the other settle direction. The transaction wrapping the exchange is made to
// fail its Commit, so the handler's deferred Rollback discards it — and the
// chain MUST still be retired, because the replay is the finding regardless of
// what became of the rotation.
//
// The wire answer stays invalid_grant: a replay stages no write, so a settle
// fault costs the client nothing and must not be dressed up as a server error
// that hides the finding.
func TestRefresh_ReplayCascadeRetiresChainAfterRollback(t *testing.T) {
	t.Parallel()

	cur := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	issuedAt := cur
	f := newReplayCascadeFixture(t, &cur)
	client, secret := f.confidentialClientFixture(t)
	const seed = "rt-cascade-rollback"
	const grantID = "grant-cascade-rollback"

	tip := seedReplayChain(t, f.fixture, client.ID, secret, seed, grantID)

	cur = cur.Add(2 * time.Minute)

	// Armed only for the replay request so the chain above was built against
	// the unmodified adapter and the assertions below read a healthy store.
	f.failCommit.Store(true)
	assertRefreshRefused(t, f.fixture, client.ID, secret, seed, "replay whose transaction cannot commit")
	f.failCommit.Store(false)

	assertRefreshRefused(t, f.fixture, client.ID, secret, tip, "chain tip after a rolled-back replay")
	assertChainNodeRevoked(t, f.fixture, tip, "chain tip")
	assertGrantTombstoned(t, f.fixture, grantID, issuedAt)
}

// TestRefresh_ReplayCascadeTransportFaultKeepsInvalidGrant pins the
// best-effort contract. When the cascade's own write fails, the client still
// receives the invalid_grant its replay earned rather than a 5xx, and the
// silent failure surfaces as a warn-level audit event so SOC tooling can tell
// "chain retired" from "chain revoke failed".
func TestRefresh_ReplayCascadeTransportFaultKeepsInvalidGrant(t *testing.T) {
	t.Parallel()

	cur := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	f := newReplayCascadeFixture(t, &cur)
	client, secret := f.confidentialClientFixture(t)
	const seed = "rt-cascade-fault"
	const grantID = "grant-cascade-fault"

	seedReplayChain(t, f.fixture, client.ID, secret, seed, grantID)

	cur = cur.Add(2 * time.Minute)

	f.failRevoke.Store(true)
	assertRefreshRefused(t, f.fixture, client.ID, secret, seed, "replay with a failing cascade")

	rec := f.audit.findEvent(t, "refresh.chain_revoke_failed")
	if rec == nil {
		t.Fatalf("refresh.chain_revoke_failed not emitted; capture=%s", f.audit.buf.String())
	}
	if got := rec["level"]; got != "WARN" {
		t.Errorf("level=%v want WARN", got)
	}
}
