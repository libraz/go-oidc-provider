package tokenendpoint_test

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

var errInjectedRefreshSave = errors.New("injected refresh-token save failure")

// saveFaultRefreshStore decorates the reference refresh substore so a test
// can fail the refresh persistence step of one exchange while every other
// refresh operation keeps working. The explicit forwards preserve the
// optional capabilities the token endpoint requires: an embedded interface
// alone would hide them and op.New would refuse to build the provider.
type saveFaultRefreshStore struct {
	store.RefreshTokenStore
	failSave *atomic.Bool
}

func (s saveFaultRefreshStore) Save(ctx context.Context, rt *store.RefreshToken) error {
	if s.failSave.Load() {
		return errInjectedRefreshSave
	}
	return s.RefreshTokenStore.Save(ctx, rt)
}

func (s saveFaultRefreshStore) SaveRotationWithRetry(
	ctx context.Context,
	successor *store.RefreshToken,
	sealed []byte,
) error {
	return s.RefreshTokenStore.(store.RefreshRetryResponseStore).SaveRotationWithRetry(ctx, successor, sealed)
}

func (s saveFaultRefreshStore) LoadRetryResponse(ctx context.Context, predecessorID string) ([]byte, error) {
	return s.RefreshTokenStore.(store.RefreshRetryResponseStore).LoadRetryResponse(ctx, predecessorID)
}

// saveFaultStore swaps the refresh substore of the reference Store for the
// decorated one. BeginTx is forwarded verbatim: the authorization-code
// exchange this test drives does not stage its mutations behind a
// transaction, but op.New requires the capability to be present.
type saveFaultStore struct {
	store.Store
	refreshTokens store.RefreshTokenStore
}

func (s saveFaultStore) RefreshTokens() store.RefreshTokenStore { return s.refreshTokens }

func (s saveFaultStore) BeginTx(ctx context.Context) (store.Tx, error) {
	return s.Store.(store.Transactional).BeginTx(ctx)
}

// TestAuthCode_MintFailureCleanupSparesEarlierExchangesAccessToken pins the
// blast radius of the post-mint cleanup an interrupted authorization-code
// exchange runs.
//
// A grant is reused across exchanges of the same (subject, client) pair, so
// two codes can share one GrantID: the second exchange failing after its
// access token was persisted must retire ONLY the row it just wrote. A
// grant-wide retirement here logs the user out of every resource server —
// every in-flight API call made with the access token of the earlier,
// successful exchange starts failing — over a fault the client experienced
// as one failed token request.
func TestAuthCode_MintFailureCleanupSparesEarlierExchangesAccessToken(t *testing.T) {
	t.Parallel()

	cur := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	failSave := &atomic.Bool{}
	backing := inmem.New(inmem.WithClock(movableClock{cur: &cur}))
	decorated := saveFaultStore{
		Store: backing,
		refreshTokens: saveFaultRefreshStore{
			RefreshTokenStore: backing.RefreshTokens(),
			failSave:          failSave,
		},
	}
	prov := testkit.NewProvider(t,
		testkit.WithClock(movableClock{cur: &cur}),
		testkit.WithOptions(
			op.WithStore(decorated),
			op.WithFeature(feature.Introspect),
			op.WithAccessTokenFormat(op.AccessTokenFormatOpaque),
		),
	)
	prov.Store = backing
	f := &fixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/token",
		clock:    fixedClock{now: cur},
	}
	client, secret := f.confidentialClientFixture(t)

	const grantID = "grant-shared-by-two-codes"
	const redirect = "https://rp.example/cb"
	verifier, challenge := pkcePair()
	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: "user-1", ClientID: client.ID,
		Scope: []string{"openid"},
	})
	for _, code := range []string{"code-first", "code-second"} {
		f.seedAuthCode(t, &store.AuthorizationCode{
			ID:                  code,
			ClientID:            client.ID,
			Subject:             "user-1",
			GrantID:             grantID,
			RedirectURI:         redirect,
			Scope:               []string{"openid"},
			CodeChallenge:       challenge,
			CodeChallengeMethod: "S256",
		})
	}

	first := f.post(t, authCodeForm("code-first", redirect, verifier), client.ID, secret)
	defer func() { _ = first.Body.Close() }()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first exchange status=%d want 200, body=%v", first.StatusCode, decodeJSON(t, first))
	}
	liveAT, _ := decodeJSON(t, first)["access_token"].(string)
	if liveAT == "" {
		t.Fatal("first exchange returned no access_token")
	}
	if !introspectActive(t, f, client.ID, secret, liveAT) {
		t.Fatal("the first exchange's access token is not active; the fixture is not exercising the opaque path")
	}

	// The second exchange mints (and persists) its own access token, then
	// fails while persisting the refresh token — one of the three interrupted
	// mints whose cleanup this covers.
	failSave.Store(true)
	second := f.post(t, authCodeForm("code-second", redirect, verifier), client.ID, secret)
	defer func() { _ = second.Body.Close() }()
	if second.StatusCode != http.StatusInternalServerError {
		t.Fatalf("second exchange status=%d want 500, body=%v", second.StatusCode, decodeJSON(t, second))
	}
	failSave.Store(false)

	if !introspectActive(t, f, client.ID, secret, liveAT) {
		t.Error("the earlier exchange's access token was revoked by the failed exchange's cleanup")
	}
	rec, err := f.prov.Store.OpaqueAccessTokens().Find(context.Background(), liveAT)
	if err != nil {
		t.Fatalf("OpaqueAccessTokens.Find: %v", err)
	}
	if rec.Revoked {
		t.Error("the earlier exchange's opaque access-token row is revoked")
	}
}
