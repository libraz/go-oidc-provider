package scenarios_test

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

// txcRefreshStore runs a hook immediately before a refresh token is saved,
// forwarding the capabilities the token endpoint requires.
type txcRefreshStore struct {
	store.RefreshTokenStore
	beforeSave func(*store.RefreshToken)
}

func (s txcRefreshStore) Save(ctx context.Context, rt *store.RefreshToken) error {
	s.beforeSave(rt)
	return s.RefreshTokenStore.Save(ctx, rt)
}

func (s txcRefreshStore) SaveRotationWithRetry(ctx context.Context, successor *store.RefreshToken, sealed []byte) error {
	return s.RefreshTokenStore.(store.RefreshRetryResponseStore).SaveRotationWithRetry(ctx, successor, sealed)
}

func (s txcRefreshStore) LoadRetryResponse(ctx context.Context, predecessorID string) ([]byte, error) {
	return s.RefreshTokenStore.(store.RefreshRetryResponseStore).LoadRetryResponse(ctx, predecessorID)
}

// txcStore swaps the reference store's refresh substore for the hooked one.
type txcStore struct {
	store.Store
	refreshTokens store.RefreshTokenStore
}

func (s txcStore) RefreshTokens() store.RefreshTokenStore { return s.refreshTokens }

func (s txcStore) BeginTx(ctx context.Context) (store.Tx, error) {
	return s.Store.(store.Transactional).BeginTx(ctx)
}

// TestTokenExchange_SubjectRevokedDuringIssuance_LeavesNoLiveRefreshToken
// drives a RevokeSubject that completes while a token exchange is between
// its subject_token checks and the write of the refresh token it issues
// under the inherited grant. The teardown cannot see that refresh token, so
// the exchange must refuse and retire it, under every JWT revocation strategy.
func TestTokenExchange_SubjectRevokedDuringIssuance_LeavesNoLiveRefreshToken(t *testing.T) {
	t.Parallel()

	for name, strategy := range map[string]op.AccessTokenRevocationStrategy{
		"grant_tombstone": op.RevocationStrategyGrantTombstone,
		"jti_registry":    op.RevocationStrategyJTIRegistry,
		"none":            op.RevocationStrategyNone,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var (
				tk    *testkit.Provider
				armed atomic.Bool
				saved string
			)
			backing := inmem.New()
			backing.PutUser(context.Background(), &store.User{Subject: scenariokit.DefaultSubject})
			decorated := txcStore{Store: backing, refreshTokens: txcRefreshStore{
				RefreshTokenStore: backing.RefreshTokens(),
				beforeSave: func(rt *store.RefreshToken) {
					if !armed.Swap(false) {
						return
					}
					saved = rt.ID
					if err := tk.OP.RevokeSubject(context.Background(), scenariokit.DefaultSubject); err != nil {
						t.Errorf("RevokeSubject: %v", err)
					}
				},
			}}
			tk = testkit.NewProvider(t, testkit.WithOptions(
				op.WithStore(decorated),
				op.WithAccessTokenRevocationStrategy(strategy),
				op.WithFeature(feature.Introspect),
				op.WithTokenExchangeGrant(op.TokenExchangeGrant{Policy: txDecisionPolicy{decision: &op.TokenExchangeDecision{IssueRefreshToken: op.PtrBool(true)}}}),
			))
			tk.Store = backing
			hash, err := op.HashClientSecret(glSecret)
			if err != nil {
				t.Fatalf("HashClientSecret: %v", err)
			}
			tk.RegisterClient(t, testkit.ClientFixture{
				ID:                      glCodeClient,
				SecretHash:              hash,
				RedirectURIs:            []string{glCallback},
				Scopes:                  []string{"openid", "offline_access", "read"},
				TokenEndpointAuthMethod: "client_secret_basic",
			})
			tk.RegisterClient(t, testkit.ClientFixture{
				ID:                      glCallerClient,
				SecretHash:              hash,
				GrantTypes:              []string{txGrantType, "refresh_token"},
				Scopes:                  []string{"openid", "offline_access", "read"},
				Resources:               []string{txTargetAud},
				TokenEndpointAuthMethod: "client_secret_basic",
			})
			env := &glEnv{tk: tk}
			subjectToken := env.subjectToken(t)

			armed.Store(true)
			status, body := env.exchange(t, subjectToken)
			if saved == "" {
				t.Fatalf("no refresh token was persisted; status=%d body=%v", status, body)
			}
			if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
				t.Fatalf("exchange racing RevokeSubject: status=%d body=%v, want 400 invalid_grant", status, body)
			}
			if _, ok := body["refresh_token"]; ok {
				t.Error("refused exchange carries a refresh_token")
			}
			rec, err := backing.RefreshTokens().Find(context.Background(), saved)
			if err != nil {
				t.Fatalf("Find: %v", err)
			}
			if !rec.Revoked {
				t.Error("the refresh token issued under the revoked grant is still redeemable")
			}
		})
	}
}
