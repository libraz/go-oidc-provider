package oidcsql_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
)

// runFullContract drives every contract suite the adapter satisfies
// against the engine the factory builds: the aggregate store, the
// authentication factors, client updates and the Shared Signals stores.
// Every dialect and driver mode calls it, so none can omit a suite.
func runFullContract(t *testing.T, f contract.Factory) {
	t.Helper()
	contract.Run(t, f)
	runMFAContracts(t, f)
	runClientUpdateContracts(t, f)
	contract.RunSSF(t, ssfFactory(f))
}

// ssfFactory adapts a store contract factory to the SSF contract, which
// takes the two substores rather than the aggregate.
func ssfFactory(f contract.Factory) contract.SSFFactory {
	return func(t *testing.T) contract.SSFBackend {
		t.Helper()
		s, ok := f(t).Store.(store.SharedSignalsStore)
		if !ok {
			t.Fatal("sql store does not implement store.SharedSignalsStore")
		}
		return contract.SSFBackend{Streams: s.SSFStreams(), Events: s.SSFEvents()}
	}
}
