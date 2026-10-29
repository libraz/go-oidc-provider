package inmem_test

import (
	"context"
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func TestUpdatePasswordHash_ReplacesHash(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st := inmem.New()
	st.PutUserWithPassword(ctx, &store.User{Subject: "sub-1"}, "alice", []byte("old"))

	up, ok := st.UserPasswords().(store.UserPasswordHashUpdater)
	if !ok {
		t.Fatal("inmem user store does not implement UserPasswordHashUpdater")
	}
	enc := []byte("$argon2id$new")
	if err := up.UpdatePasswordHash(ctx, "sub-1", enc); err != nil {
		t.Fatalf("UpdatePasswordHash: %v", err)
	}
	enc[0] = 'X' // the store must have copied the input
	got, err := st.UserPasswords().ReadPasswordHash(ctx, "sub-1")
	if err != nil {
		t.Fatalf("ReadPasswordHash: %v", err)
	}
	if string(got) != "$argon2id$new" {
		t.Fatalf("hash = %q, want $argon2id$new", got)
	}
}

func TestUpdatePasswordHash_SetsHashForPasswordlessUser(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st := inmem.New()
	st.PutUser(ctx, &store.User{Subject: "sub-1"})

	up := st.UserPasswords().(store.UserPasswordHashUpdater)
	if err := up.UpdatePasswordHash(ctx, "sub-1", []byte("h")); err != nil {
		t.Fatalf("UpdatePasswordHash: %v", err)
	}
	if _, err := st.UserPasswords().ReadPasswordHash(ctx, "sub-1"); err != nil {
		t.Fatalf("ReadPasswordHash: %v", err)
	}
}

func TestUpdatePasswordHash_UnknownSubject(t *testing.T) {
	t.Parallel()
	up := inmem.New().UserPasswords().(store.UserPasswordHashUpdater)
	err := up.UpdatePasswordHash(context.Background(), "nobody", []byte("h"))
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("err = %v, want store.ErrNotFound", err)
	}
}
