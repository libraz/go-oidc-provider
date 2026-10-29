package oidcsql_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

// TestUserPasswords_RoundTrip exercises the SQL adapter's
// [store.UserPasswordStore] implementation end-to-end against SQLite
// (no testcontainers, runs in the default `go test` run). The harness
// mirrors what the inmem adapter ships out of the box: seed a user via
// PutUserWithPassword, look it up by username, read the hash back,
// then verify lookups for unknown usernames / passkey-only users
// surface [store.ErrNotFound].
func TestUserPasswords_RoundTrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := openSQLite(t)
	s, err := oidcsql.New(db, oidcsql.SQLite())
	if err != nil {
		t.Fatalf("oidcsql.New: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	hash := []byte("$argon2id$v=19$m=65536,t=3,p=4$AAAA$BBBB")
	user := &store.User{
		Subject: "demo-user",
		Claims:  map[string]any{"name": "Demo User"},
	}
	if err := s.PutUserWithPassword(ctx, user, "demo", hash); err != nil {
		t.Fatalf("PutUserWithPassword: %v", err)
	}

	pwStore := s.UserPasswords()

	gotByName, err := pwStore.FindByUsername(ctx, "demo")
	if err != nil {
		t.Fatalf("FindByUsername(demo): %v", err)
	}
	if gotByName.Subject != "demo-user" {
		t.Fatalf("FindByUsername subject: got %q want %q", gotByName.Subject, "demo-user")
	}
	if got, ok := gotByName.Claims["name"].(string); !ok || got != "Demo User" {
		t.Fatalf("FindByUsername claims: got %v", gotByName.Claims)
	}

	gotHash, err := pwStore.ReadPasswordHash(ctx, "demo-user")
	if err != nil {
		t.Fatalf("ReadPasswordHash: %v", err)
	}
	if !bytes.Equal(gotHash, hash) {
		t.Fatalf("ReadPasswordHash: got %q want %q", gotHash, hash)
	}

	if _, err := pwStore.FindByUsername(ctx, "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("FindByUsername(missing): want ErrNotFound, got %v", err)
	}
	if _, err := pwStore.ReadPasswordHash(ctx, "missing-subject"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ReadPasswordHash(missing-subject): want ErrNotFound, got %v", err)
	}

	// Passkey-only re-seed: clear the password by passing zero values.
	if err := s.PutUserWithPassword(ctx, user, "", nil); err != nil {
		t.Fatalf("PutUserWithPassword(clear): %v", err)
	}
	if _, err := pwStore.FindByUsername(ctx, "demo"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("FindByUsername(demo) after clear: want ErrNotFound, got %v", err)
	}
	if _, err := pwStore.ReadPasswordHash(ctx, "demo-user"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ReadPasswordHash after clear: want ErrNotFound, got %v", err)
	}

	// FindBySubject still works after the password is cleared.
	gotBySub, err := s.Users().FindBySubject(ctx, "demo-user")
	if err != nil {
		t.Fatalf("FindBySubject after clear: %v", err)
	}
	if gotBySub.Subject != "demo-user" {
		t.Fatalf("FindBySubject after clear subject: got %q", gotBySub.Subject)
	}
}

func newPasswordUpdaterStore(t *testing.T) (*oidcsql.Store, store.UserPasswordHashUpdater) {
	t.Helper()
	s, err := oidcsql.New(openSQLite(t), oidcsql.SQLite())
	if err != nil {
		t.Fatalf("oidcsql.New: %v", err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	up, ok := s.UserPasswords().(store.UserPasswordHashUpdater)
	if !ok {
		t.Fatal("sql user store does not implement UserPasswordHashUpdater")
	}
	return s, up
}

func TestUpdatePasswordHash_ReplacesHash(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, up := newPasswordUpdaterStore(t)

	user := &store.User{Subject: "demo-user", Claims: map[string]any{"name": "Demo User"}}
	if err := s.PutUserWithPassword(ctx, user, "demo", []byte("old-hash")); err != nil {
		t.Fatalf("PutUserWithPassword: %v", err)
	}
	if err := up.UpdatePasswordHash(ctx, "demo-user", []byte("new-hash")); err != nil {
		t.Fatalf("UpdatePasswordHash: %v", err)
	}
	got, err := s.UserPasswords().ReadPasswordHash(ctx, "demo-user")
	if err != nil {
		t.Fatalf("ReadPasswordHash: %v", err)
	}
	if !bytes.Equal(got, []byte("new-hash")) {
		t.Fatalf("ReadPasswordHash: got %q want %q", got, "new-hash")
	}
}

func TestUpdatePasswordHash_UnknownSubject(t *testing.T) {
	t.Parallel()
	_, up := newPasswordUpdaterStore(t)
	err := up.UpdatePasswordHash(context.Background(), "nobody", []byte("h"))
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}
