//go:build testcontainers

package oidcredis_test

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	redismod "github.com/testcontainers/testcontainers-go/modules/redis"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/libraz/go-oidc-provider/op/store/contract"
	oidcredis "github.com/libraz/go-oidc-provider/op/storeadapter/redis"
)

// redisImage pins the engine version the contract harness validates
// against. Bumping it must coincide with re-running the full contract
// suite.
const redisImage = "redis:7-alpine"

// fixedClock wires [contract.Reference] through every backend the
// harness builds.
type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

// newRedisFactory boots a single Redis container with AUTH enabled and
// returns a [contract.Factory] that creates an isolated keyspace per
// sub-test by mapping each request to a distinct prefix. The container
// terminates via [testing.T.Cleanup] after the parent test (and all
// parallel sub-tests) finish. If Docker is not reachable the parent
// test is skipped rather than failed.
//
// The harness deliberately uses the plaintext-with-AUTH variant inside
// the container (the testcontainers redis module does not expose a
// turnkey TLS-enabled image) and opts into the adapter's
// WithDevModeAllowPlaintext escape hatch. The TLS enforcement path is
// covered by the in-process unit tests in store_test.go; this harness
// validates the on-the-wire SETNX / SET / GET / EXISTS semantics
// against the real engine.
func newRedisFactory(t *testing.T) contract.Factory {
	t.Helper()
	ctx := context.Background()

	const authPassword = "ofcs-test-pw" //nolint:gosec // ephemeral test container.

	ctr, err := redismod.Run(ctx, redisImage,
		testcontainers.WithCmdArgs("--requirepass", authPassword),
		testcontainers.WithWaitStrategy(
			wait.ForLog("Ready to accept connections").
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		t.Skipf("redis container unavailable (Docker not running?): %v", err)
	}
	t.Cleanup(func() {
		_ = ctr.Terminate(context.Background())
	})

	endpoint, err := ctr.Endpoint(ctx, "")
	if err != nil {
		t.Fatalf("Endpoint: %v", err)
	}

	dsn := fmt.Sprintf("redis://:%s@%s/0", authPassword, endpoint)
	clock := fixedClock{now: contract.Reference}

	var seq atomic.Uint64
	silence := func(string) {} // suppress dev-mode warning during tests

	return func(t *testing.T) contract.Backend {
		t.Helper()
		// Per-sub-test prefix isolates keyspaces so parallel sub-tests
		// see independent worlds without needing a fresh container.
		prefix := fmt.Sprintf("oidc-t-%d:", seq.Add(1))
		store, err := oidcredis.New(t.Context(),
			oidcredis.WithDSN(dsn),
			oidcredis.WithRedisAuth("", authPassword),
			oidcredis.WithDevModeAllowPlaintext(silence),
			oidcredis.WithKeyPrefix(prefix),
			oidcredis.WithClock(clock),
		)
		if err != nil {
			t.Fatalf("oidcredis.New: %v", err)
		}
		t.Cleanup(func() { _ = store.Close() })
		return contract.Backend{Store: store, Now: clock.Now}
	}
}

// TestRedis_Interactions runs the InteractionStore contract subgroup
// against a real Redis 7 instance booted via testcontainers-go. The
// test is gated by the `testcontainers` build tag so a default
// `go test` invocation stays driver- and Docker-free.
func TestRedis_Interactions(t *testing.T) {
	t.Parallel()
	contract.RunInteractions(t, newRedisFactory(t))
}

// TestRedis_ConsumedJTIs runs the ConsumedJTIStore contract subgroup
// against a real Redis 7 instance booted via testcontainers-go.
func TestRedis_ConsumedJTIs(t *testing.T) {
	t.Parallel()
	contract.RunConsumedJTIs(t, newRedisFactory(t))
}

// TestRedis_Sessions runs the SessionStore contract subgroup against a
// real Redis 7 instance. The harness validates the chooser-group
// secondary index, lazy cleanup of stale entries after parent TTL
// eviction, and the JSON round-trip shape against the live engine.
func TestRedis_Sessions(t *testing.T) {
	t.Parallel()
	contract.RunSessions(t, newRedisFactory(t))
}
