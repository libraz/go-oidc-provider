//go:build testcontainers

package oidcredis_test

import (
	"context"
	"fmt"
	"os"
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
// against. Bumping this must coincide with re-running the full contract
// suite, and must stay aligned with the example compose files
// (examples/09-redis-volatile).
const redisImage = "redis:7.4-alpine"

// fixedClock wires [contract.Reference] through every backend the
// harness builds.
type fixedClock struct{ now time.Time }

// Now reads through the pointer so a Now method value bound once —
// as the contract harness does — still observes later mutations. A
// value receiver would copy the struct at bind time and freeze the
// harness clock while the store's own clock kept moving.
func (c *fixedClock) Now() time.Time { return c.now }

// newRedisFactory boots a single Redis container with AUTH enabled and
// returns a [contract.Factory] that creates an isolated keyspace per
// sub-test by mapping each request to a distinct prefix. The container
// terminates via [testing.T.Cleanup] after the parent test (and all
// parallel sub-tests) finish. If Docker is not reachable the parent
// test is skipped rather than failed. RELEASE_CONTRACT_REQUIRED=1 upgrades
// that absence to a failure for release gates.
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
		if os.Getenv("RELEASE_CONTRACT_REQUIRED") == "1" {
			t.Fatalf("redis container required for release contract: %v", err)
		}
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
	var seq atomic.Uint64
	silence := func(string) {} // suppress dev-mode warning during tests

	return func(t *testing.T) contract.Backend {
		t.Helper()
		clock := &fixedClock{now: contract.Reference}
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
		return contract.Backend{
			Store: store,
			Now:   clock.Now,
			Advance: func(delta time.Duration) {
				clock.now = clock.now.Add(delta)
			},
		}
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

// TestRedis_SubstoreNamespace runs the substore-namespace contract
// subgroup against a real Redis 7 instance. Redis is the backend where
// a shared keyspace is easiest to introduce by accident — every substore
// writes into one flat key namespace under a common prefix — so the
// disjointness of the interaction, session and consumed-JTI key shapes
// is asserted against the live engine rather than inferred from the key
// builders.
func TestRedis_SubstoreNamespace(t *testing.T) {
	t.Parallel()
	contract.RunSubstoreNamespace(t, newRedisFactory(t))
}

// TestRedis_SessionStore_ConcurrentRotate pins the rotation
// post-condition declared on [store.SessionStore] directly against the
// Redis adapter. The helper is also exercised via [contract.RunSessions]
// -> sessionCases; the explicit call documents the contract a
// volatile-tier sessions-only embedder is expected to honour.
func TestRedis_SessionStore_ConcurrentRotate(t *testing.T) {
	t.Parallel()
	b := newRedisFactory(t)(t)
	contract.AssertConcurrentRotate(t, b.Store.Sessions(), b.Now())
}

// TestRedis_SessionStore_ExpiredReturnsNotFound pins the expired-
// session contract against the Redis adapter via the shared
// [contract.AssertExpiredSessionReturnsNotFound] helper. Redis evicts
// the parent key via TTL when ExpiresAt is past-dated; the helper
// tolerates Save dropping the write because the post-condition
// observers (Find / Touch / ListByChooserGroup) all report ErrNotFound
// either way.
func TestRedis_SessionStore_ExpiredReturnsNotFound(t *testing.T) {
	t.Parallel()
	b := newRedisFactory(t)(t)
	contract.AssertExpiredSessionReturnsNotFound(t, b.Store.Sessions(), b.Now())
}

// TestRedis_SessionStore_NotFoundOnMissing pins the absent-ID
// contract against the Redis adapter via the shared
// [contract.AssertSessionNotFoundOnMissing] helper.
func TestRedis_SessionStore_NotFoundOnMissing(t *testing.T) {
	t.Parallel()
	b := newRedisFactory(t)(t)
	contract.AssertSessionNotFoundOnMissing(t, b.Store.Sessions(), b.Now())
}

// TestRedis_SessionStore_BatchListMatches pins the chooser-group
// batch lookup contract against the Redis adapter via the shared
// [contract.AssertSessionBatchListMatches] helper. The Redis
// implementation backs the lookup with a SET secondary index plus an
// MGET parent fetch; the helper exercises that path against 16
// records to surface dedup / aliasing bugs the single-record cases
// in [contract.RunSessions] would miss.
func TestRedis_SessionStore_BatchListMatches(t *testing.T) {
	t.Parallel()
	b := newRedisFactory(t)(t)
	contract.AssertSessionBatchListMatches(t, b.Store.Sessions(), 16, b.Now())
}
