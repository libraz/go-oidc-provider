package composite_test

import (
	"context"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
	"github.com/libraz/go-oidc-provider/op/storeadapter/composite"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestContract_HotColdSplit drives the full contract suite against a
// composite store that mirrors a realistic hot/cold deployment: a persistent
// backend serves the transactional cluster plus Clients, while an ephemeral
// backend serves Interactions and ConsumedJTIs. The contract behaviours must
// hold identically to a single-backend store.
//
// The factory builds two fresh inmem stores per sub-test so backends remain
// isolated; both stores are pinned to the same reference clock so the
// expiry-driven sub-tests behave deterministically.
func TestContract_HotColdSplit(t *testing.T) {
	t.Parallel()

	factory := func(t *testing.T) contract.Backend {
		t.Helper()
		now := contract.Reference
		clock := fakeClock{now: now}

		persistent := inmem.New(inmem.WithClock(clock))
		ephemeral := inmem.New(inmem.WithClock(clock))

		s, err := composite.New(
			composite.WithDefault(persistent),
			composite.With(composite.Interactions, ephemeral),
			composite.With(composite.ConsumedJTIs, ephemeral),
		)
		if err != nil {
			t.Fatalf("composite.New: %v", err)
		}
		// Wrap in registryFacade so the contract harness's
		// type-assertion based ClientRegistry detection succeeds; the
		// composite intentionally hides ClientRegistry behind an
		// accessor so this thin adapter is the single bridge.
		return contract.Backend{Store: &registryFacade{Store: s}, Now: now}
	}

	contract.Run(t, factory)
}

// registryFacade exposes [store.ClientRegistry] via direct embedding so the
// contract harness's [requireRegistry] type assertion succeeds. The facade
// forwards to the composite's accessor; if the composite reports the
// capability as absent the forwarders return [store.ErrNotFound] so the
// contract failure surfaces clearly rather than as a nil-pointer panic.
type registryFacade struct {
	*composite.Store
}

// GetClient implements [store.ClientStore], which is embedded into
// [store.ClientRegistry]. The facade forwards to the composite's Clients
// substore so the read path is identical to a non-registry caller.
func (f *registryFacade) GetClient(ctx context.Context, id string) (*store.Client, error) {
	return f.Clients().GetClient(ctx, id)
}

// RegisterClient implements [store.ClientRegistry].
func (f *registryFacade) RegisterClient(ctx context.Context, c *store.Client) error {
	reg, ok := f.ClientRegistry()
	if !ok {
		return store.ErrNotFound
	}
	return reg.RegisterClient(ctx, c)
}

// UpdateClient implements [store.ClientRegistry].
func (f *registryFacade) UpdateClient(ctx context.Context, c *store.Client) error {
	reg, ok := f.ClientRegistry()
	if !ok {
		return store.ErrNotFound
	}
	return reg.UpdateClient(ctx, c)
}

// DeleteClient implements [store.ClientRegistry].
func (f *registryFacade) DeleteClient(ctx context.Context, id string) error {
	reg, ok := f.ClientRegistry()
	if !ok {
		return store.ErrNotFound
	}
	return reg.DeleteClient(ctx, id)
}
