package inmem

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

type refreshIndexClock struct{ now time.Time }

func (c refreshIndexClock) Now() time.Time { return c.now }

func TestRefreshIndexSavePathsAndCloneIsolation(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	s := New(WithClock(refreshIndexClock{now: now}))
	ctx := context.Background()
	root := newRefreshIndexToken(now, "root-secret", "client-a", "grant-a", nil)
	if err := s.refreshes.Save(ctx, root); err != nil {
		t.Fatalf("Save root: %v", err)
	}
	root.ClientID = "mutated-client"
	root.GrantID = "mutated-grant"

	parent := "root-secret"
	successor := newRefreshIndexToken(now, "rotated-secret", "client-a", "grant-a", &parent)
	if err := s.refreshes.SaveRotationWithRetry(ctx, successor, []byte("sealed")); err != nil {
		t.Fatalf("SaveRotationWithRetry: %v", err)
	}
	if err := s.refreshes.Save(
		ctx,
		newRefreshIndexToken(now, "other-secret", "client-b", "grant-b", nil),
	); err != nil {
		t.Fatalf("Save other: %v", err)
	}
	duplicate := newRefreshIndexToken(now, "root-secret", "client-duplicate", "grant-duplicate", nil)
	if err := s.refreshes.Save(ctx, duplicate); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("duplicate Save: want ErrAlreadyExists, got %v", err)
	}

	assertRefreshIndexIDs(t, s.refreshes.byClient["client-a"], "root-secret", "rotated-secret")
	assertRefreshIndexIDs(t, s.refreshes.byGrant["grant-a"], "root-secret", "rotated-secret")
	if len(s.refreshes.byClient["mutated-client"]) != 0 || len(s.refreshes.byGrant["mutated-grant"]) != 0 {
		t.Fatal("secondary indexes retained caller mutations instead of the stored clone")
	}
	if len(s.refreshes.byClient["client-duplicate"]) != 0 ||
		len(s.refreshes.byGrant["grant-duplicate"]) != 0 {
		t.Fatal("failed duplicate Save mutated secondary indexes")
	}
	if _, rawKeyPresent := s.refreshes.byClient["client-a"]["root-secret"]; rawKeyPresent {
		t.Fatal("secondary index contains the raw bearer credential")
	}

	if err := s.refreshes.RevokeByGrant(ctx, "grant-a"); err != nil {
		t.Fatalf("RevokeByGrant: %v", err)
	}
	assertRefreshRevoked(t, s.refreshes, "root-secret", true)
	assertRefreshRevoked(t, s.refreshes, "rotated-secret", true)
	assertRefreshRevoked(t, s.refreshes, "other-secret", false)
}

func TestRefreshIndexTransactionCommitRollbackAndRevoke(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	s := New(WithClock(refreshIndexClock{now: now}))
	ctx := context.Background()

	rolledBack, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx rollback: %v", err)
	}
	if err := rolledBack.RefreshTokens().Save(
		ctx,
		newRefreshIndexToken(now, "rolled-back", "client-r", "grant-r", nil),
	); err != nil {
		t.Fatalf("Save rollback token: %v", err)
	}
	if err := rolledBack.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if len(s.refreshes.byClient["client-r"]) != 0 || len(s.refreshes.byGrant["grant-r"]) != 0 {
		t.Fatal("rolled-back refresh token leaked into secondary indexes")
	}
	if _, err := s.refreshes.Find(ctx, "rolled-back"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find rolled-back token: want ErrNotFound, got %v", err)
	}

	if err := s.refreshes.Save(
		ctx,
		newRefreshIndexToken(now, "parent-token", "client-c", "grant-c", nil),
	); err != nil {
		t.Fatalf("Save parent token: %v", err)
	}
	committed, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx commit: %v", err)
	}
	if err := committed.RefreshTokens().Save(
		ctx,
		newRefreshIndexToken(now, "staged-token", "client-c", "grant-c", nil),
	); err != nil {
		t.Fatalf("Save staged token: %v", err)
	}
	if err := committed.RefreshTokens().RevokeByGrant(ctx, "grant-c"); err != nil {
		t.Fatalf("transaction RevokeByGrant: %v", err)
	}
	if err := committed.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	assertRefreshIndexIDs(t, s.refreshes.byClient["client-c"], "parent-token", "staged-token")
	assertRefreshIndexIDs(t, s.refreshes.byGrant["grant-c"], "parent-token", "staged-token")
	assertRefreshRevoked(t, s.refreshes, "parent-token", true)
	assertRefreshRevoked(t, s.refreshes, "staged-token", true)
}

func TestRefreshIndexRevokeOperationCount(t *testing.T) {
	t.Parallel()

	const targetCount = 7
	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()
	for _, total := range []int{1_000, 10_000, 100_000} {
		s := New(WithClock(refreshIndexClock{now: now}))
		for i := range total {
			grantID := "unrelated"
			clientID := "unrelated-client"
			if i < targetCount {
				grantID = "target"
				clientID = "target-client"
			}
			id := "token-" + strconv.Itoa(total) + "-" + strconv.Itoa(i)
			if err := s.refreshes.Save(
				ctx,
				newRefreshIndexToken(now, id, clientID, grantID, nil),
			); err != nil {
				t.Fatalf("total=%d Save %d: %v", total, i, err)
			}
		}

		s.refreshes.mu.Lock()
		grantVisited := s.refreshes.revokeByGrantLocked("target", now)
		clientVisited := s.refreshes.revokeByClientLocked("target-client", now)
		s.refreshes.mu.Unlock()
		if grantVisited != targetCount || clientVisited != targetCount {
			t.Fatalf(
				"total=%d grant visited=%d client visited=%d, want exactly %d matching rows each",
				total,
				grantVisited,
				clientVisited,
				targetCount,
			)
		}
	}
}

func TestRefreshIndexConcurrentSaveAndRevoke(t *testing.T) {
	t.Parallel()

	const tokenCount = 128
	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	s := New(WithClock(refreshIndexClock{now: now}))
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := range tokenCount {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := "concurrent-" + strconv.Itoa(i)
			if err := s.refreshes.Save(
				ctx,
				newRefreshIndexToken(now, id, "client-concurrent", "grant-concurrent", nil),
			); err != nil {
				t.Errorf("Save %s: %v", id, err)
			}
		}()
	}
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.refreshes.RevokeByGrant(ctx, "grant-concurrent"); err != nil {
				t.Errorf("RevokeByGrant: %v", err)
			}
		}()
	}
	wg.Wait()

	if err := s.refreshes.RevokeByGrant(ctx, "grant-concurrent"); err != nil {
		t.Fatalf("final RevokeByGrant: %v", err)
	}
	if got := len(s.refreshes.byGrant["grant-concurrent"]); got != tokenCount {
		t.Fatalf("grant index contains %d tokens, want %d", got, tokenCount)
	}
	for i := range tokenCount {
		assertRefreshRevoked(t, s.refreshes, "concurrent-"+strconv.Itoa(i), true)
	}
}

func BenchmarkRefreshIndexRevokeByGrant(b *testing.B) {
	const targetCount = 8
	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()
	for _, total := range []int{1_000, 10_000, 100_000} {
		b.Run(strconv.Itoa(total), func(b *testing.B) {
			s := New(WithClock(refreshIndexClock{now: now}))
			for i := range total {
				grantID := "unrelated"
				if i < targetCount {
					grantID = "target"
				}
				id := "benchmark-" + strconv.Itoa(total) + "-" + strconv.Itoa(i)
				err := s.refreshes.Save(
					ctx,
					newRefreshIndexToken(now, id, "client-"+strconv.Itoa(i%11), grantID, nil),
				)
				if err != nil {
					b.Fatalf("Save %d: %v", i, err)
				}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if err := s.refreshes.RevokeByGrant(ctx, "target"); err != nil {
					b.Fatalf("RevokeByGrant: %v", err)
				}
			}
			b.ReportMetric(targetCount, "matched/op")
		})
	}
}

func newRefreshIndexToken(
	now time.Time,
	id, clientID, grantID string,
	parentID *string,
) *store.RefreshToken {
	return &store.RefreshToken{
		ID:        id,
		ClientID:  clientID,
		Subject:   "subject",
		GrantID:   grantID,
		Scope:     []string{"openid"},
		ParentID:  parentID,
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}
}

func assertRefreshIndexIDs(t *testing.T, ids map[string]struct{}, rawIDs ...string) {
	t.Helper()
	if len(ids) != len(rawIDs) {
		t.Fatalf("index size=%d, want %d", len(ids), len(rawIDs))
	}
	for _, rawID := range rawIDs {
		if _, ok := ids[hashKey(rawID)]; !ok {
			t.Errorf("index missing hash of %q", rawID)
		}
	}
}

func assertRefreshRevoked(t *testing.T, s *refreshStore, id string, want bool) {
	t.Helper()
	got, err := s.Find(context.Background(), id)
	if err != nil {
		t.Fatalf("Find %s: %v", id, err)
	}
	if got.Revoked != want || (got.ConsumedAt != nil) != want {
		t.Errorf(
			"%s revoked state=(Revoked=%v ConsumedAt=%v), want revoked=%v",
			id,
			got.Revoked,
			got.ConsumedAt,
			want,
		)
	}
}
