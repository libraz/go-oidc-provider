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

// chooserGroupMembershipRedisImage pins the engine version this
// white-box membership test validates against. Kept in sync with the
// image constants in the other test files in this package.
const chooserGroupMembershipRedisImage = "redis:7.4-alpine"

// TestSessionStore_ListByChooserGroup_IgnoresResidualIndexMembership
// proves the chooser-group listing answers from the session record, not
// from the SET that indexes it. The test reinstates the index entry a
// group change removes, which is the state Redis is left in whenever the
// removal does not reach the server — a connection lost mid-transaction,
// or an index written by an adapter that issued the removal as a bare
// best-effort command. The listing feeds the account chooser and the
// sign-out-everywhere sweep, so an entry the reader trusts on its own
// puts one browser's account in front of another user, and lets that
// user's sign-out revoke it and fire back-channel logout for it.
func TestSessionStore_ListByChooserGroup_IgnoresResidualIndexMembership(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	const authPassword = "ofcs-test-pw" //nolint:gosec // ephemeral test container.
	ctr, err := redismod.Run(ctx, chooserGroupMembershipRedisImage,
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
		WithKeyPrefix("cg-membership-test:"),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	now := s.clock.Now()
	const (
		sessionID   = "sess-moved"
		leftGroup   = "cg-left"
		joinedGroup = "cg-joined"
	)
	sess := &store.Session{
		ID:             sessionID,
		Subject:        "other-users-subject",
		AuthTime:       now,
		ChooserGroupID: leftGroup,
		ExpiresAt:      now.Add(time.Hour),
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := s.Sessions().Save(ctx, sess); err != nil {
		t.Fatalf("Save into the original group: %v", err)
	}
	moved := *sess
	moved.ChooserGroupID = joinedGroup
	moved.UpdatedAt = now.Add(time.Minute)
	if err := s.Sessions().Save(ctx, &moved); err != nil {
		t.Fatalf("Save into the new group: %v", err)
	}

	leftKey := s.sessionsImpl.chooserGroupKey(leftGroup)
	if err := s.client.SAdd(ctx, leftKey, sessionID).Err(); err != nil {
		t.Fatalf("reinstate the index entry the group change removes: %v", err)
	}

	left, err := s.Sessions().ListByChooserGroup(ctx, leftGroup)
	if err != nil {
		t.Fatalf("ListByChooserGroup(left group): %v", err)
	}
	for _, got := range left {
		if got.ID == sessionID {
			t.Errorf("session %q (subject %q, ChooserGroupID %q) listed under group %q "+
				"on the strength of a residual index entry",
				got.ID, got.Subject, got.ChooserGroupID, leftGroup)
		}
	}

	joined, err := s.Sessions().ListByChooserGroup(ctx, joinedGroup)
	if err != nil {
		t.Fatalf("ListByChooserGroup(new group): %v", err)
	}
	if len(joined) != 1 || joined[0].ID != sessionID {
		t.Fatalf("ListByChooserGroup(new group) = %+v, want exactly %q", joined, sessionID)
	}

	// The rejected entry is also retired from the index, so a group the
	// sessions have all left does not keep its SET alive indefinitely.
	members, err := s.client.SMembers(ctx, leftKey).Result()
	if err != nil {
		t.Fatalf("SMEMBERS left group: %v", err)
	}
	if len(members) != 0 {
		t.Errorf("left group index still holds %v after the listing rejected it", members)
	}
}
