package oidcsql_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

func TestSQLite_RefreshRetryResponse_AtomicRotationAndLoad(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b := newSQLiteFactory(t)(t)
	retries, ok := b.Store.RefreshTokens().(store.RefreshRetryResponseStore)
	if !ok {
		t.Fatal("SQL RefreshTokenStore does not implement RefreshRetryResponseStore")
	}
	now := b.Now()
	if err := b.Store.RefreshTokens().Save(ctx, &store.RefreshToken{
		ID: "retry-parent", ClientID: "client", Subject: "subject", GrantID: "grant", Scope: []string{"openid"}, ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}); err != nil {
		t.Fatalf("Save parent: %v", err)
	}
	if _, err := b.Store.RefreshTokens().Consume(ctx, "retry-parent"); err != nil {
		t.Fatalf("Consume parent: %v", err)
	}
	parent := "retry-parent"
	sealed := []byte("already-encrypted-retry-response")
	if err := retries.SaveRotationWithRetry(ctx, &store.RefreshToken{
		ID: "retry-successor", ClientID: "client", Subject: "subject", GrantID: "grant", Scope: []string{"openid"}, ParentID: &parent, ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}, sealed); err != nil {
		t.Fatalf("SaveRotationWithRetry: %v", err)
	}
	got, err := retries.LoadRetryResponse(ctx, parent)
	if err != nil {
		t.Fatalf("LoadRetryResponse: %v", err)
	}
	if !bytes.Equal(got, sealed) {
		t.Fatalf("sealed response=%q want %q", got, sealed)
	}
	if successor, err := b.Store.RefreshTokens().Find(ctx, "retry-successor"); err != nil || successor == nil {
		t.Fatalf("successor missing after atomic save: rec=%+v err=%v", successor, err)
	}
}

func TestSQLite_RefreshRetryResponse_RollbackDropsWholeRotation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b := newSQLiteFactory(t)(t)
	now := b.Now()
	if err := b.Store.RefreshTokens().Save(ctx, &store.RefreshToken{
		ID: "rollback-parent", ClientID: "client", Subject: "subject", GrantID: "grant", Scope: []string{"openid"}, ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}); err != nil {
		t.Fatalf("Save parent: %v", err)
	}
	transactional, ok := b.Store.(store.Transactional)
	if !ok {
		t.Fatal("SQL store does not implement Transactional")
	}
	tx, err := transactional.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if _, err := tx.RefreshTokens().Consume(ctx, "rollback-parent"); err != nil {
		t.Fatalf("Consume in tx: %v", err)
	}
	retries, ok := tx.RefreshTokens().(store.RefreshRetryResponseStore)
	if !ok {
		t.Fatal("transactional SQL refresh store does not implement RefreshRetryResponseStore")
	}
	parent := "rollback-parent"
	if err := retries.SaveRotationWithRetry(ctx, &store.RefreshToken{
		ID: "rollback-successor", ClientID: "client", Subject: "subject", GrantID: "grant", Scope: []string{"openid"}, ParentID: &parent, ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}, []byte("sealed-rollback")); err != nil {
		t.Fatalf("SaveRotationWithRetry in tx: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	gotParent, err := b.Store.RefreshTokens().Find(ctx, parent)
	if err != nil || gotParent.ConsumedAt != nil {
		t.Fatalf("parent changed after rollback: rec=%+v err=%v", gotParent, err)
	}
	if _, err := b.Store.RefreshTokens().Find(ctx, "rollback-successor"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("successor survived rollback: want ErrNotFound, got %v", err)
	}
	directRetries := b.Store.RefreshTokens().(store.RefreshRetryResponseStore)
	if _, err := directRetries.LoadRetryResponse(ctx, parent); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("retry response survived rollback: want ErrNotFound, got %v", err)
	}
}
