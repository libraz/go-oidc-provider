package inmem_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestRevokeByClient_RefreshTokens pins the cascade: every refresh token
// belonging to the deleted client_id is stamped consumed + revoked.
func TestRevokeByClient_RefreshTokens(t *testing.T) {
	t.Parallel()

	s := inmem.New()
	ctx := context.Background()
	now := time.Now()
	for i, cid := range []string{"client-a", "client-a", "client-b"} {
		err := s.RefreshTokens().Save(ctx, &store.RefreshToken{
			ID:        []string{"r0", "r1", "r2"}[i],
			ClientID:  cid,
			Subject:   "user-1",
			GrantID:   "g1",
			ExpiresAt: now.Add(time.Hour),
			CreatedAt: now,
		})
		if err != nil {
			t.Fatalf("Save %d: %v", i, err)
		}
	}
	rb, ok := s.RefreshTokens().(store.RevokeByClient)
	if !ok {
		t.Fatal("inmem RefreshTokenStore does not implement store.RevokeByClient")
	}
	if err := rb.RevokeByClient(ctx, "client-a"); err != nil {
		t.Fatalf("RevokeByClient: %v", err)
	}
	for _, id := range []string{"r0", "r1"} {
		rec, err := s.RefreshTokens().Find(ctx, id)
		if err != nil {
			t.Fatalf("Find %s: %v", id, err)
		}
		if rec.ConsumedAt == nil || !rec.Revoked {
			t.Errorf("%s: ConsumedAt=%v Revoked=%v want both set", id, rec.ConsumedAt, rec.Revoked)
		}
	}
	rec, err := s.RefreshTokens().Find(ctx, "r2")
	if err != nil {
		t.Fatalf("Find r2: %v", err)
	}
	if rec.ConsumedAt != nil || rec.Revoked {
		t.Errorf("r2 (other client) was revoked")
	}
}

// TestRevokeByClient_Grants pins the cascade for the grant substore.
func TestRevokeByClient_Grants(t *testing.T) {
	t.Parallel()

	s := inmem.New()
	ctx := context.Background()
	now := time.Now()
	for i, cid := range []string{"client-a", "client-a", "client-b"} {
		err := s.Grants().Save(ctx, &store.Grant{
			ID:        []string{"g0", "g1", "g2"}[i],
			Subject:   "user-1",
			ClientID:  cid,
			Scope:     []string{"openid"},
			CreatedAt: now,
			UpdatedAt: now,
		})
		if err != nil {
			t.Fatalf("Save %d: %v", i, err)
		}
	}
	rb, ok := s.Grants().(store.RevokeByClient)
	if !ok {
		t.Fatal("inmem GrantStore does not implement store.RevokeByClient")
	}
	if err := rb.RevokeByClient(ctx, "client-a"); err != nil {
		t.Fatalf("RevokeByClient: %v", err)
	}
	for _, id := range []string{"g0", "g1"} {
		_, err := s.Grants().Find(ctx, id)
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s err=%v want ErrNotFound (grant must be deleted)", id, err)
		}
	}
	if _, err := s.Grants().Find(ctx, "g2"); err != nil {
		t.Errorf("g2 (other client) was deleted: %v", err)
	}
}

// TestRevokeByClient_EmptyClientID is a no-op.
func TestRevokeByClient_EmptyClientID(t *testing.T) {
	t.Parallel()

	s := inmem.New()
	ctx := context.Background()
	rb := s.RefreshTokens().(store.RevokeByClient)
	if err := rb.RevokeByClient(ctx, ""); err != nil {
		t.Errorf("RevokeByClient(empty) err=%v want nil", err)
	}
}
