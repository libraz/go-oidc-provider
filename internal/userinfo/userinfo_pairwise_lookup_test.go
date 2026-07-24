package userinfo_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/internal/userinfo"
	"github.com/libraz/go-oidc-provider/op/store"
)

// countingClientStore wraps a single client record and counts every
// GetClient call so a test can assert the /userinfo handler resolves the
// AT-bound client at most once per request.
type countingClientStore struct {
	client *store.Client
	calls  atomic.Int64
}

func (c *countingClientStore) GetClient(_ context.Context, id string) (*store.Client, error) {
	c.calls.Add(1)
	if c.client != nil && c.client.ID == id {
		return c.client, nil
	}
	return nil, store.ErrNotFound
}

// singleUserStore is a one-record [store.UserStore] for the lookup test.
type singleUserStore struct{ user *store.User }

func (s singleUserStore) FindBySubject(_ context.Context, sub string) (*store.User, error) {
	if s.user != nil && s.user.Subject == sub {
		return s.user, nil
	}
	return nil, store.ErrNotFound
}

// singleGrantStore is a one-record [store.GrantStore]. Only Find and
// FindBySubjectClient carry behaviour the pairwise userinfo path reads;
// the remaining methods are inert stubs.
type singleGrantStore struct{ grant *store.Grant }

func (s singleGrantStore) Save(context.Context, *store.Grant) error { return nil }

func (s singleGrantStore) Find(_ context.Context, id string) (*store.Grant, error) {
	if s.grant != nil && s.grant.ID == id {
		return s.grant, nil
	}
	return nil, store.ErrNotFound
}

func (s singleGrantStore) FindBySubjectClient(context.Context, string, string) (*store.Grant, error) {
	return nil, store.ErrNotFound
}

func (s singleGrantStore) ListBySubject(context.Context, string) ([]*store.Grant, error) {
	return nil, nil
}

func (s singleGrantStore) ListClientIDsBySubject(
	context.Context,
	string,
	string,
	int,
) (store.GrantClientPage, error) {
	return store.GrantClientPage{}, nil
}

func (s singleGrantStore) Delete(context.Context, string) error { return nil }

func (s singleGrantStore) HasAny(context.Context) (bool, error) { return true, nil }

// TestHandler_PairwiseResolvesClientOnce pins the #20 fix: a pairwise
// config resolves the AT-bound client through the subject projection AND
// the response-shape dispatch, but MUST hit [store.ClientStore.GetClient]
// only once per request now that the resolved client is threaded between
// the two consumers.
func TestHandler_PairwiseResolvesClientOnce(t *testing.T) {
	t.Parallel()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keySet, err := keys.NewSet([]keys.Entry{{KeyID: "k1", Signer: priv}})
	if err != nil {
		t.Fatalf("keys.NewSet: %v", err)
	}
	signer := tokens.SigningKey{KeyID: "k1", Signer: priv}

	const (
		issuer   = "https://op.example"
		clientID = "client-pairwise"
		rawSub   = "raw-subject-1"
	)
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}

	clients := &countingClientStore{client: &store.Client{ID: clientID}}
	deps := userinfo.HandlerDeps{
		Keys:      keySet,
		Issuer:    issuer,
		Clients:   clients,
		UserStore: singleUserStore{user: &store.User{Subject: rawSub, Claims: map[string]any{"email": "alice@example.com"}}},
		Grants:    singleGrantStore{grant: &store.Grant{ID: "grant-1", Subject: rawSub, ClientID: clientID}},
		Clock:     clock,
		SubjectProjector: func(_ context.Context, raw string, _ *store.Client) (string, error) {
			return "pairwise-" + raw, nil
		},
	}

	token, err := tokens.SignAccessToken(signer, tokens.AccessTokenClaims{
		Issuer:    issuer,
		Subject:   "pairwise-" + rawSub,
		Audience:  []string{issuer},
		ClientID:  clientID,
		GrantID:   "grant-1",
		IssuedAt:  clock.now.Unix(),
		ExpiresAt: clock.now.Add(time.Hour).Unix(),
		JTI:       "at-pairwise-1",
		Scope:     []string{"openid", "email"},
	})
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, issuer+"/userinfo", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	userinfo.Handler(deps).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%s", rec.Code, rec.Body.String())
	}
	if got := clients.calls.Load(); got != 1 {
		t.Errorf("GetClient called %d times, want exactly 1 per request", got)
	}
}
