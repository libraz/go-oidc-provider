package op_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func TestWithStaticClients_IsIdempotentAcrossProviderConstruction(t *testing.T) {
	t.Parallel()

	st := inmem.New()
	newProvider := func() error {
		_, err := op.New(
			op.WithIssuer(validIssuer),
			op.WithStore(st),
			op.WithUserStore(st.Users()),
			op.WithKeyset(validKeyset(t)),
			op.WithCookieKeys(newRandomCookieKey(t)),
			fixtureAuthenticator(),
			op.WithStaticClients(op.ConfidentialClient{
				ID:           "restart-client",
				Secret:       "restart-secret",
				RedirectURIs: []string{"https://app.example.com/cb"},
				Scopes:       []string{"openid"},
			}),
		)
		return err
	}
	if err := newProvider(); err != nil {
		t.Fatalf("first op.New: %v", err)
	}
	first, err := st.GetClient(context.Background(), "restart-client")
	if err != nil {
		t.Fatalf("GetClient after first New: %v", err)
	}
	if err := newProvider(); err != nil {
		t.Fatalf("second op.New with identical configuration: %v", err)
	}
	second, err := st.GetClient(context.Background(), "restart-client")
	if err != nil {
		t.Fatalf("GetClient after second New: %v", err)
	}
	if second.SecretHash != first.SecretHash {
		t.Error("idempotent reconciliation rewrote the existing secret hash")
	}
}

func TestWithStaticClients_DifferentStoredRecordConflicts(t *testing.T) {
	t.Parallel()

	st := inmem.New()
	build := func(scopes ...string) error {
		_, err := op.New(
			op.WithIssuer(validIssuer),
			op.WithStore(st),
			op.WithUserStore(st.Users()),
			op.WithKeyset(validKeyset(t)),
			op.WithCookieKeys(newRandomCookieKey(t)),
			fixtureAuthenticator(),
			op.WithStaticClients(op.PublicClient{
				ID:           "stable-client",
				RedirectURIs: []string{"https://app.example.com/cb"},
				Scopes:       scopes,
			}),
		)
		return err
	}
	if err := build("openid"); err != nil {
		t.Fatalf("initial op.New: %v", err)
	}
	err := build("openid", "profile")
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("changed static seed error=%v want ErrConflict", err)
	}
	assertErrorMentions(t, err, "differs from its static seed in Scopes;", "op.SyncStaticClients")
	got, err := st.GetClient(context.Background(), "stable-client")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if len(got.Scopes) != 1 || got.Scopes[0] != "openid" {
		t.Errorf("stored scopes=%v want unchanged [openid]", got.Scopes)
	}
}

func TestWithStaticClients_NonStaticStoredRecordConflicts(t *testing.T) {
	t.Parallel()

	st := inmem.New()
	existing := &store.Client{
		ID:                      "dynamic-client",
		RedirectURIs:            []string{"https://app.example.com/cb"},
		Scopes:                  []string{"openid"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		PublicClient:            true,
		Source:                  store.ClientSourceDynamic,
	}
	if err := st.RegisterClient(context.Background(), existing); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	_, err := op.New(
		op.WithIssuer(validIssuer),
		op.WithStore(st),
		op.WithUserStore(st.Users()),
		op.WithKeyset(validKeyset(t)),
		op.WithCookieKeys(newRandomCookieKey(t)),
		fixtureAuthenticator(),
		op.WithStaticClients(op.PublicClient{
			ID:           existing.ID,
			RedirectURIs: existing.RedirectURIs,
			Scopes:       existing.Scopes,
		}),
	)
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("static seed over dynamic record error=%v want ErrConflict", err)
	}
	assertErrorMentions(t, err, "is stored as a dynamic client")
	got, err := st.GetClient(context.Background(), existing.ID)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if got.Source != store.ClientSourceDynamic {
		t.Errorf("stored source=%q want unchanged dynamic source", got.Source)
	}
}

func TestWithStaticClients_DifferentSecretConflicts(t *testing.T) {
	t.Parallel()

	st := inmem.New()
	build := func(secret string) error {
		_, err := op.New(
			op.WithIssuer(validIssuer),
			op.WithStore(st),
			op.WithUserStore(st.Users()),
			op.WithKeyset(validKeyset(t)),
			op.WithCookieKeys(newRandomCookieKey(t)),
			fixtureAuthenticator(),
			op.WithStaticClients(op.ConfidentialClient{
				ID:           "secret-client",
				Secret:       secret,
				RedirectURIs: []string{"https://app.example.com/cb"},
				Scopes:       []string{"openid"},
			}),
		)
		return err
	}
	if err := build("original-secret"); err != nil {
		t.Fatalf("initial op.New: %v", err)
	}
	before, err := st.GetClient(context.Background(), "secret-client")
	if err != nil {
		t.Fatalf("GetClient before conflict: %v", err)
	}
	err = build("rotated-secret")
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("rotated secret error=%v want ErrConflict", err)
	}
	assertErrorMentions(t, err, "does not verify", "op.SyncStaticClients")
	after, err := st.GetClient(context.Background(), "secret-client")
	if err != nil {
		t.Fatalf("GetClient after conflict: %v", err)
	}
	if after.SecretHash != before.SecretHash {
		t.Error("conflicting secret changed the stored hash")
	}
}

func TestNew_RotatedSeedConflictsBeforeSync(t *testing.T) {
	t.Parallel()

	st := inmem.New()
	if _, err := op.New(syncProviderOpts(t, st, syncRotationSeed("secret-before", ""))...); err != nil {
		t.Fatalf("initial op.New: %v", err)
	}
	before, err := st.GetClient(context.Background(), "svc")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	_, err = op.New(syncProviderOpts(t, st, syncRotationSeed("secret-after", "secret-before"))...)
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("rotated seed error=%v want ErrConflict", err)
	}
	after, err := st.GetClient(context.Background(), "svc")
	if err != nil {
		t.Fatalf("GetClient after: %v", err)
	}
	if after.SecretHash != before.SecretHash || after.PreviousSecretHash != "" {
		t.Error("op.New rotated the stored secret; rotation belongs to SyncStaticClients")
	}
}

func TestNew_RotatedSeedAfterSync(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	st := inmem.New()
	for _, seed := range []op.ConfidentialClient{
		syncRotationSeed("secret-before", ""),
		syncRotationSeed("secret-after", "secret-before"),
	} {
		if _, err := op.SyncStaticClients(ctx, st, seed); err != nil {
			t.Fatalf("sync: %v", err)
		}
	}
	synced, err := st.GetClient(ctx, "svc")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if _, err := op.New(syncProviderOpts(t, st, syncRotationSeed("secret-after", "secret-before"))...); err != nil {
		t.Fatalf("op.New after sync: %v", err)
	}
	after, err := st.GetClient(ctx, "svc")
	if err != nil {
		t.Fatalf("GetClient after: %v", err)
	}
	if after.SecretHash != synced.SecretHash || after.PreviousSecretHash != synced.PreviousSecretHash {
		t.Error("op.New rewrote the synced hashes")
	}
}

func TestWithStaticClients_RemovedSeedIsNotDeleted(t *testing.T) {
	t.Parallel()

	st := inmem.New()
	base := []op.Option{
		op.WithIssuer(validIssuer),
		op.WithStore(st),
		op.WithUserStore(st.Users()),
		op.WithKeyset(validKeyset(t)),
		op.WithCookieKeys(newRandomCookieKey(t)),
		fixtureAuthenticator(),
	}
	if _, err := op.New(append(base, op.WithStaticClients(op.PublicClient{
		ID:           "retained-client",
		RedirectURIs: []string{"https://app.example.com/cb"},
		Scopes:       []string{"openid"},
	}))...); err != nil {
		t.Fatalf("initial op.New: %v", err)
	}
	if _, err := op.New(base...); err != nil {
		t.Fatalf("op.New after removing seed: %v", err)
	}
	if _, err := st.GetClient(context.Background(), "retained-client"); err != nil {
		t.Fatalf("removed seed was deleted: %v", err)
	}
}

func TestWithStaticClients_LaterBuildFailureLeavesStoreUntouched(t *testing.T) {
	t.Parallel()

	registry := prometheus.NewRegistry()
	if _, err := op.New(append(validBaseOptsWithInmem(t), op.WithPrometheus(registry))...); err != nil {
		t.Fatalf("register initial metrics: %v", err)
	}

	st := inmem.New()
	_, err := op.New(
		op.WithIssuer(validIssuer),
		op.WithStore(st),
		op.WithKeyset(validKeyset(t)),
		op.WithCookieKeys(newRandomCookieKey(t)),
		fixtureAuthenticator(),
		op.WithPrometheus(registry),
		op.WithStaticClients(op.PublicClient{
			ID:           "must-not-persist",
			RedirectURIs: []string{"https://app.example.com/cb"},
			Scopes:       []string{"openid"},
		}),
	)
	if err == nil {
		t.Fatal("expected duplicate metric registration to fail construction")
	}
	if _, getErr := st.GetClient(context.Background(), "must-not-persist"); !errors.Is(getErr, store.ErrNotFound) {
		t.Fatalf("client after failed build: err=%v want ErrNotFound", getErr)
	}
}

func TestWithStaticClients_NthBatchFailureLeavesStoreUntouched(t *testing.T) {
	t.Parallel()

	fault := errors.New("injected reconcile failure")
	registry := prometheus.NewRegistry()
	backend := inmem.New()
	st := &nthFailureStaticClientStore{
		Store:         backend,
		Transactional: backend,
		reconciler:    backend,
		failAt:        2,
		err:           fault,
	}
	if _, ok := any(st).(store.ClientRegistry); ok {
		t.Fatal("fault decorator must prove static seeding does not require ClientRegistry")
	}
	_, err := op.New(
		op.WithIssuer(validIssuer),
		op.WithStore(st),
		op.WithUserStore(backend.Users()),
		op.WithKeyset(validKeyset(t)),
		op.WithCookieKeys(newRandomCookieKey(t)),
		fixtureAuthenticator(),
		op.WithPrometheus(registry),
		op.WithStaticClients(
			op.PublicClient{
				ID:           "batch-a",
				RedirectURIs: []string{"https://a.example.com/cb"},
				Scopes:       []string{"openid"},
			},
			op.PublicClient{
				ID:           "batch-b",
				RedirectURIs: []string{"https://b.example.com/cb"},
				Scopes:       []string{"openid"},
			},
		),
	)
	if !errors.Is(err, fault) {
		t.Fatalf("op.New error=%v want injected failure", err)
	}
	for _, id := range []string{"batch-a", "batch-b"} {
		if _, getErr := st.GetClient(context.Background(), id); !errors.Is(getErr, store.ErrNotFound) {
			t.Errorf("GetClient(%s) err=%v want ErrNotFound", id, getErr)
		}
	}

	// Static-client reconciliation is deliberately the final fallible stage
	// after WithPrometheus registers its collector set. A failure here must
	// roll that registration back, otherwise this corrected retry on the same
	// embedder-owned registry would fail with duplicate descriptors.
	if _, retryErr := op.New(
		op.WithIssuer(validIssuer),
		op.WithStore(st),
		op.WithUserStore(backend.Users()),
		op.WithKeyset(validKeyset(t)),
		op.WithCookieKeys(newRandomCookieKey(t)),
		fixtureAuthenticator(),
		op.WithPrometheus(registry),
	); retryErr != nil {
		t.Fatalf("op.New retry after static-client failure: %v", retryErr)
	}
}

type nthFailureStaticClientStore struct {
	store.Store
	store.Transactional
	reconciler store.StaticClientReconciler
	failAt     int
	err        error
}

func (s *nthFailureStaticClientStore) GetClient(
	ctx context.Context,
	id string,
) (*store.Client, error) {
	return s.reconciler.GetClient(ctx, id)
}

func (s *nthFailureStaticClientStore) ReconcileStaticClients(
	ctx context.Context,
	clients []*store.Client,
) error {
	for i := range clients {
		if i+1 == s.failAt {
			return s.err
		}
	}
	return s.reconciler.ReconcileStaticClients(ctx, clients)
}

var _ store.StaticClientReconciler = (*nthFailureStaticClientStore)(nil)

// assertErrorMentions fails unless err's message carries every fragment.
func assertErrorMentions(t *testing.T, err error, fragments ...string) {
	t.Helper()
	for _, f := range fragments {
		if !strings.Contains(err.Error(), f) {
			t.Errorf("error %q does not mention %q", err, f)
		}
	}
}
