//go:build example

// users.go — store.UserPasswordStore against vault_principals.
//
// The library only reads end-user records (registration / password
// resets live in the embedder's own management plane), so this store
// implements FindBySubject, FindByUsername, and ReadPasswordHash. The
// PrimaryPassword login Step consumes all three.

package main

import (
	"context"
	databasesql "database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

type userStore struct{ q querier }

const (
	userSelectBySubject = `SELECT principal, login_handle, display_name, contact_email, last_touched FROM vault_principals WHERE principal = ?`
	userSelectByHandle  = `SELECT principal, login_handle, display_name, contact_email, last_touched FROM vault_principals WHERE login_handle = ?`
	userSelectSecretPHC = `SELECT secret_phc FROM vault_principals WHERE principal = ?`
)

// FindBySubject implements store.UserStore.
func (s *userStore) FindBySubject(ctx context.Context, sub string) (*store.User, error) {
	return s.scan(ctx, userSelectBySubject, sub)
}

// FindByUsername implements store.UserPasswordStore. The embedder
// treats the submitted username as the login_handle column.
func (s *userStore) FindByUsername(ctx context.Context, username string) (*store.User, error) {
	return s.scan(ctx, userSelectByHandle, username)
}

// ReadPasswordHash implements store.UserPasswordStore. It returns
// store.ErrNotFound both when the principal is unknown and when the row
// carries no secret, so the orchestrator surfaces an enumeration-safe
// invalid-credentials response either way.
func (s *userStore) ReadPasswordHash(ctx context.Context, subject string) ([]byte, error) {
	var hash []byte
	err := s.q.QueryRowContext(ctx, userSelectSecretPHC, subject).Scan(&hash)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("users.ReadPasswordHash: %w", err)
	}
	if len(hash) == 0 {
		return nil, store.ErrNotFound
	}
	out := make([]byte, len(hash))
	copy(out, hash)
	return out, nil
}

func (s *userStore) scan(ctx context.Context, query, arg string) (*store.User, error) {
	var (
		subject string
		handle  databasesql.NullString
		name    databasesql.NullString
		email   databasesql.NullString
		touched int64
	)
	err := s.q.QueryRowContext(ctx, query, arg).Scan(&subject, &handle, &name, &email, &touched)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("users.scan: %w", err)
	}
	claims := map[string]any{}
	if name.Valid {
		claims["name"] = name.String
	}
	if email.Valid {
		claims["email"] = email.String
	}
	return &store.User{
		Subject:   subject,
		Claims:    claims,
		UpdatedAt: time.Unix(touched, 0),
	}, nil
}
