//go:build testcontainers

//nolint:testpackage // exercises the unexported sessionStore.chooserGroupKey helper.
package oidcredis

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	redismod "github.com/testcontainers/testcontainers-go/modules/redis"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/libraz/go-oidc-provider/op/store"
)

// chooserGroupTTLRedisImage pins the engine version this white-box TTL
// test validates against. Kept in sync with contract_redis_test.go's
// redisImage constant (both target the ExpireNX / ExpireGT flags
// introduced in Redis 7.0).
const chooserGroupTTLRedisImage = "redis:7.4-alpine"

// TestSessionStore_Save_ChooserGroupKeyGetsTTL proves the chooser-group
// secondary index key Save creates carries a positive TTL rather than
// living forever. A TTL-less index key is exempt from volatile-*
// maxmemory eviction, so under memory pressure Redis would evict the
// live, TTL-bearing session keys the index points at before touching
// the index itself — the opposite of the intended eviction priority.
func TestSessionStore_Save_ChooserGroupKeyGetsTTL(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	const authPassword = "ofcs-test-pw" //nolint:gosec // ephemeral test container.
	ctr, err := redismod.Run(ctx, chooserGroupTTLRedisImage,
		testcontainers.WithCmdArgs("--requirepass", authPassword),
		testcontainers.WithWaitStrategy(
			wait.ForLog("Ready to accept connections").WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		t.Skipf("redis container unavailable (Docker not running?): %v", err)
	}
	t.Cleanup(func() { _ = ctr.Terminate(context.Background()) })

	endpoint, err := ctr.Endpoint(ctx, "")
	if err != nil {
		t.Fatalf("Endpoint: %v", err)
	}
	dsn := fmt.Sprintf("redis://:%s@%s/0", authPassword, endpoint)

	s, err := New(ctx,
		WithDSN(dsn),
		WithRedisAuth("", authPassword),
		WithDevModeAllowPlaintext(func(string) {}),
		WithKeyPrefix("cg-ttl-test:"),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	now := s.clock.Now()
	sess := &store.Session{
		ID:             "sess-ttl-1",
		Subject:        "sub",
		AuthTime:       now,
		ChooserGroupID: "cg-ttl-1",
		ExpiresAt:      now.Add(time.Hour),
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := s.Sessions().Save(ctx, sess); err != nil {
		t.Fatalf("Save: %v", err)
	}

	groupKey := s.sessionsImpl.chooserGroupKey(sess.ChooserGroupID)
	ttl, err := s.client.TTL(ctx, groupKey).Result()
	if err != nil {
		t.Fatalf("TTL: %v", err)
	}
	if ttl <= 0 {
		t.Fatalf("chooser-group key TTL = %v, want a positive TTL", ttl)
	}
}

// TestSessionStore_Save_ChooserGroupTTLNeverShrinks proves that adding
// a shorter-lived sibling session to an existing chooser group does
// not truncate the group index's TTL below a longer-lived member's
// expiry. If the group's TTL tracked only the most-recent Save's
// session lifetime, a short-lived cohort member would prematurely
// evict the secondary index entry a still-live sibling relies on for
// ListByChooserGroup visibility.
func TestSessionStore_Save_ChooserGroupTTLNeverShrinks(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	const authPassword = "ofcs-test-pw" //nolint:gosec // ephemeral test container.
	ctr, err := redismod.Run(ctx, chooserGroupTTLRedisImage,
		testcontainers.WithCmdArgs("--requirepass", authPassword),
		testcontainers.WithWaitStrategy(
			wait.ForLog("Ready to accept connections").WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		t.Skipf("redis container unavailable (Docker not running?): %v", err)
	}
	t.Cleanup(func() { _ = ctr.Terminate(context.Background()) })

	endpoint, err := ctr.Endpoint(ctx, "")
	if err != nil {
		t.Fatalf("Endpoint: %v", err)
	}
	dsn := fmt.Sprintf("redis://:%s@%s/0", authPassword, endpoint)

	s, err := New(ctx,
		WithDSN(dsn),
		WithRedisAuth("", authPassword),
		WithDevModeAllowPlaintext(func(string) {}),
		WithKeyPrefix("cg-ttl-shrink-test:"),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	now := s.clock.Now()
	groupKey := s.sessionsImpl.chooserGroupKey("cg-shrink-1")

	longLived := &store.Session{
		ID:             "sess-long",
		Subject:        "sub",
		AuthTime:       now,
		ChooserGroupID: "cg-shrink-1",
		ExpiresAt:      now.Add(2 * time.Hour),
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := s.Sessions().Save(ctx, longLived); err != nil {
		t.Fatalf("Save longLived: %v", err)
	}
	ttlAfterLong, err := s.client.TTL(ctx, groupKey).Result()
	if err != nil {
		t.Fatalf("TTL after longLived: %v", err)
	}

	shortLived := &store.Session{
		ID:             "sess-short",
		Subject:        "sub",
		AuthTime:       now,
		ChooserGroupID: "cg-shrink-1",
		ExpiresAt:      now.Add(time.Minute),
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := s.Sessions().Save(ctx, shortLived); err != nil {
		t.Fatalf("Save shortLived: %v", err)
	}
	ttlAfterShort, err := s.client.TTL(ctx, groupKey).Result()
	if err != nil {
		t.Fatalf("TTL after shortLived: %v", err)
	}

	// The short-lived sibling's Save MUST NOT shrink the group's TTL
	// below what the long-lived member already established (allow a
	// small margin for the container's own coarse-second rounding).
	if ttlAfterShort < ttlAfterLong-2*time.Second {
		t.Fatalf("chooser-group TTL shrank after a shorter-lived sibling Save: before=%v after=%v",
			ttlAfterLong, ttlAfterShort)
	}
}
