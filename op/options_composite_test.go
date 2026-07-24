package op_test

import (
	"context"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/composite"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestWithStaticClients_AcceptsCompositeStore confirms that
// op.WithStaticClients seeds clients through a composite.Store without
// the embedder having to register them against the routed durable
// backend first. composite.Store deliberately does NOT implement
// store.StaticClientReconciler via type assertion (its godoc explains why),
// so op.seedStaticClients must probe the optional
// StaticClientReconciler() accessor the composite exposes; this test pins
// that probe.
func TestWithStaticClients_AcceptsCompositeStore(t *testing.T) {
	t.Parallel()

	durable := inmem.New()
	volatile := inmem.New()

	storage, err := composite.New(
		composite.WithDefault(durable),
		composite.With(composite.Interactions, volatile),
		composite.With(composite.ConsumedJTIs, volatile),
	)
	if err != nil {
		t.Fatalf("composite.New: %v", err)
	}

	if _, ok := any(storage).(store.ClientRegistry); ok {
		t.Fatal("composite.Store must NOT satisfy store.ClientRegistry by direct " +
			"type assertion; the test premise relies on the optional accessor probe")
	}
	if _, ok := any(storage).(store.StaticClientReconciler); ok {
		t.Fatal("composite.Store must NOT satisfy store.StaticClientReconciler by direct " +
			"type assertion; capability depends on the routed Clients backend")
	}
	if _, ok := storage.StaticClientReconciler(); !ok {
		t.Fatal("composite.Store must expose the routed inmem atomic reconciler")
	}

	if _, err := op.New(
		op.WithIssuer(validIssuer),
		op.WithStore(storage),
		op.WithKeyset(validKeyset(t)),
		op.WithCookieKeys(newRandomCookieKey(t)),
		op.WithStaticClients(op.PublicClient{
			ID:           "demo-spa",
			RedirectURIs: []string{"https://app.example.com/cb"},
			Scopes:       []string{"openid"},
		}),
	); err != nil {
		t.Fatalf("op.New with composite store: %v", err)
	}

	got, err := durable.Clients().GetClient(context.Background(), "demo-spa")
	if err != nil {
		t.Fatalf("seed did not reach the routed Clients backend: %v", err)
	}
	if !got.PublicClient {
		t.Errorf("seed.PublicClient = false, want true")
	}
}

// TestWithStaticClients_RejectsCompositeWithReadOnlyClients confirms
// that the optional probe still rejects compositions whose routed
// Clients backend cannot atomically reconcile new entries. The composite is
// intentionally configured with a Clients backend that hides
// store.StaticClientReconciler, so
// composite.Store.StaticClientReconciler() returns (nil, false) and
// op.seedStaticClients reports the same atomic-reconciler requirement as a
// directly-supplied read-only store.
func TestWithStaticClients_RejectsCompositeWithReadOnlyClients(t *testing.T) {
	t.Parallel()

	tx := inmem.New()
	readOnly := readOnlyClientsStore{Store: inmem.New()}

	storage, err := composite.New(
		composite.WithDefault(tx),
		composite.With(composite.Clients, readOnly),
	)
	if err != nil {
		t.Fatalf("composite.New: %v", err)
	}

	_, err = op.New(
		op.WithIssuer(validIssuer),
		op.WithStore(storage),
		op.WithKeyset(validKeyset(t)),
		op.WithCookieKeys(newRandomCookieKey(t)),
		op.WithStaticClients(op.PublicClient{
			ID:           "demo-spa",
			RedirectURIs: []string{"https://app.example.com/cb"},
			Scopes:       []string{"openid"},
		}),
	)
	if err == nil {
		t.Fatal("expected StaticClientReconciler error for read-only Clients route, got nil")
	}
	if _, ok := storage.StaticClientReconciler(); ok {
		t.Fatal("read-only Clients route must not advertise StaticClientReconciler")
	}
	if !strings.Contains(err.Error(), "StaticClientReconciler") {
		t.Errorf("err = %v, want it to mention StaticClientReconciler", err)
	}
}

// readOnlyClientsStore embeds [store.Store] via the interface so neither
// [store.ClientRegistry] nor [store.StaticClientReconciler] promotes from the
// underlying in-memory store. The composite probe therefore reports that
// atomic reconciliation is unavailable, which op.New must reject.
type readOnlyClientsStore struct {
	store.Store
}

// Clients overrides the embedded accessor to return a [store.ClientStore]
// view that does not also satisfy [store.ClientRegistry]. The wrapper
// embeds via the interface so callers cannot recover the underlying
// registry through type assertion.
func (s readOnlyClientsStore) Clients() store.ClientStore {
	return readOnlyClientStore{ClientStore: s.Store.Clients()}
}

type readOnlyClientStore struct {
	store.ClientStore
}
