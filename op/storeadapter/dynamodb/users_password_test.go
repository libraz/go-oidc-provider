//go:build testcontainers

package oidcdynamo_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
	oidcdynamo "github.com/libraz/go-oidc-provider/op/storeadapter/dynamodb"
)

func newPasswordUpdaterStore(t *testing.T, prefix string) *oidcdynamo.Store {
	t.Helper()
	client := newEmulatorClient(t)
	s, err := oidcdynamo.New(client, oidcdynamo.WithTablePrefix(prefix))
	if err != nil {
		t.Fatalf("oidcdynamo.New: %v", err)
	}
	if err := s.CreateTables(t.Context()); err != nil {
		t.Fatalf("CreateTables: %v", err)
	}
	disableEmulatorTTL(t, client, s)
	return s
}

func TestUpdatePasswordHash_ReplacesHash(t *testing.T) {
	t.Parallel()
	s := newPasswordUpdaterStore(t, "pwupd_")
	ctx := t.Context()

	user := &store.User{Subject: "demo-user", Claims: map[string]any{"name": "Demo User"}}
	if err := s.PutUserWithPassword(ctx, user, "demo", []byte("old-hash")); err != nil {
		t.Fatalf("PutUserWithPassword: %v", err)
	}
	up, ok := s.UserPasswords().(store.UserPasswordHashUpdater)
	if !ok {
		t.Fatal("dynamodb user store does not implement UserPasswordHashUpdater")
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
	// The claims document is untouched by the hash write.
	if _, err := s.Users().FindBySubject(ctx, "demo-user"); err != nil {
		t.Fatalf("FindBySubject: %v", err)
	}
}

func TestUpdatePasswordHash_UnknownSubject(t *testing.T) {
	t.Parallel()
	s := newPasswordUpdaterStore(t, "pwupdmiss_")
	up := s.UserPasswords().(store.UserPasswordHashUpdater)
	err := up.UpdatePasswordHash(t.Context(), "nobody", []byte("h"))
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	// A failed update must not create the item.
	if _, err := s.Users().FindBySubject(t.Context(), "nobody"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("FindBySubject after failed update: want ErrNotFound, got %v", err)
	}
}
