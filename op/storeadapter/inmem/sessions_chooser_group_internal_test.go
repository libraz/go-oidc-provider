package inmem

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

func listGroupIDs(t *testing.T, s *Store, group string) []string {
	t.Helper()
	got, err := s.sessions.ListByChooserGroup(context.Background(), group)
	if err != nil {
		t.Fatalf("ListByChooserGroup(%q): %v", group, err)
	}
	ids := make([]string, 0, len(got))
	for _, sess := range got {
		ids = append(ids, sess.ID)
	}
	slices.Sort(ids)
	return ids
}

func TestSessionChooserGroupIndex_FollowsSaveDeleteAndExpiry(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	s := New(WithClock(refreshIndexClock{now: now}))
	ctx := context.Background()
	save := func(id, group string, ttl time.Duration) {
		t.Helper()
		if err := s.sessions.Save(ctx, &store.Session{
			ID: id, Subject: "sub", ChooserGroupID: group, ExpiresAt: now.Add(ttl),
		}); err != nil {
			t.Fatalf("Save %s: %v", id, err)
		}
	}

	save("a", "g1", time.Hour)
	save("b", "g1", time.Hour)
	save("c", "g2", time.Hour)
	save("dead", "g1", -time.Minute)
	if got := listGroupIDs(t, s, "g1"); !slices.Equal(got, []string{"a", "b"}) {
		t.Fatalf("g1 = %v, want [a b] (expired excluded)", got)
	}

	// Re-saving under another group moves the session.
	save("a", "g2", time.Hour)
	if got := listGroupIDs(t, s, "g1"); !slices.Equal(got, []string{"b"}) {
		t.Fatalf("g1 after move = %v, want [b]", got)
	}
	if got := listGroupIDs(t, s, "g2"); !slices.Equal(got, []string{"a", "c"}) {
		t.Fatalf("g2 after move = %v, want [a c]", got)
	}

	if err := s.sessions.Delete(ctx, "b"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if got := listGroupIDs(t, s, "g1"); len(got) != 0 {
		t.Fatalf("g1 after delete = %v, want empty", got)
	}
	if _, leaked := s.sessions.byGroup["g1"]["b"]; leaked {
		t.Fatal("chooser-group index retained a deleted session")
	}
	if _, leaked := s.sessions.byGroup["g1"]["a"]; leaked {
		t.Fatal("chooser-group index retained a session moved to another group")
	}
}

func TestSessionChooserGroupIndex_SweepDropsExpiredEntries(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	s := New(WithClock(refreshIndexClock{now: now}))
	ctx := context.Background()
	if err := s.sessions.Save(ctx, &store.Session{
		ID: "old", Subject: "sub", ChooserGroupID: "g", ExpiresAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	s.sessions.mu.Lock()
	s.sessions.gcLocked(now)
	s.sessions.mu.Unlock()
	if len(s.sessions.m) != 0 || len(s.sessions.byGroup) != 0 {
		t.Fatalf("sweep left m=%d byGroup=%d entries", len(s.sessions.m), len(s.sessions.byGroup))
	}
}
