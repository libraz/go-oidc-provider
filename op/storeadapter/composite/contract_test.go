package composite_test

import (
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store/contract"
	"github.com/libraz/go-oidc-provider/op/storeadapter/composite"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestContract_HotColdSplit drives the full contract suite against a
// composite store that mirrors a realistic hot/cold deployment: a persistent
// backend serves the atomic-routing cluster plus Clients, while an ephemeral
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
		clock := &fakeClock{now: now}

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
		// The composite goes into the harness unwrapped. It withholds
		// the plain store.ClientRegistry on purpose — the capability
		// depends on which backend is routed for Clients — and the
		// harness probes the accessor, so a facade here would only test
		// the facade.
		return contract.Backend{
			Store: s,
			Now:   clock.Now,
			Advance: func(delta time.Duration) {
				clock.now = clock.now.Add(delta)
			},
		}
	}

	contract.Run(t, factory)
}
