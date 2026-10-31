//go:build testcontainers

package oidcredis_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
)

// TestRedis_SSF runs the Shared Signals stream and SET-queue contract
// against a real Redis 7 instance, including the concurrent ClaimDue
// race the due-set Lua script exists to make single-winner.
func TestRedis_SSF(t *testing.T) {
	t.Parallel()
	factory := newRedisFactory(t)
	contract.RunSSF(t, func(t *testing.T) contract.SSFBackend {
		t.Helper()
		s, ok := factory(t).Store.(store.SharedSignalsStore)
		if !ok {
			t.Fatal("redis store does not implement store.SharedSignalsStore")
		}
		return contract.SSFBackend{Streams: s.SSFStreams(), Events: s.SSFEvents()}
	})
}
