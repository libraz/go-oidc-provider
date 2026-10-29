//go:build example

package main

import (
	"context"
	databasesql "database/sql"
	"errors"
	"log"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/libraz/go-oidc-provider/op/store"
)

// userTable adapts the application's own users table to the login flow.
// The OP never sees the column names: it asks for a user by subject or
// by username, reads the stored hash, and writes a new hash back once a
// bcrypt hash has verified. The subject is the row id as a string.
type userTable struct{ db *databasesql.DB }

var (
	_ store.UserPasswordStore       = (*userTable)(nil)
	_ store.UserPasswordHashUpdater = (*userTable)(nil)
)

// FindBySubject resolves the "sub" claim back to a row.
func (u *userTable) FindBySubject(ctx context.Context, sub string) (*store.User, error) {
	id, err := rowID(sub)
	if err != nil {
		return nil, err
	}
	return u.find(ctx, "id = ?", id)
}

// rowID maps a subject to its row id. A subject that is not a row id is
// an unknown user, not a backend fault.
func rowID(subject string) (int64, error) {
	id, err := strconv.ParseInt(subject, 10, 64)
	if err != nil {
		return 0, store.ErrNotFound
	}
	return id, nil
}

// FindByUsername looks the login name up by email, case-folded the same
// way the rows were written.
func (u *userTable) FindByUsername(ctx context.Context, username string) (*store.User, error) {
	return u.find(ctx, "email = ?", strings.ToLower(strings.TrimSpace(username)))
}

func (u *userTable) find(ctx context.Context, where string, arg any) (*store.User, error) {
	var (
		id          int64
		email, name string
	)
	err := u.db.QueryRowContext(ctx, "SELECT id, email, display_name FROM app_users WHERE "+where, arg).
		Scan(&id, &email, &name)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &store.User{
		Subject: strconv.FormatInt(id, 10),
		Claims:  map[string]any{"name": name, "email": email},
	}, nil
}

// ReadPasswordHash returns the stored hash as is: a bcrypt "$2a$" hash
// is verified by the scheme listed in LegacySchemes, an "$argon2id$" one
// by the OP itself.
func (u *userTable) ReadPasswordHash(ctx context.Context, subject string) ([]byte, error) {
	id, err := rowID(subject)
	if err != nil {
		return nil, err
	}
	var hash databasesql.NullString
	err = u.db.QueryRowContext(ctx, "SELECT password_hash FROM app_users WHERE id = ?", id).Scan(&hash)
	if errors.Is(err, databasesql.ErrNoRows) || (err == nil && hash.String == "") {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return []byte(hash.String), nil
}

// UpdatePasswordHash stores the argon2id hash the OP derived from a
// password that matched a bcrypt hash. A failure here never fails the
// login; the OP retries on the next one.
func (u *userTable) UpdatePasswordHash(ctx context.Context, subject string, encoded []byte) error {
	id, err := rowID(subject)
	if err != nil {
		return err
	}
	res, err := u.db.ExecContext(ctx, "UPDATE app_users SET password_hash = ? WHERE id = ?", string(encoded), id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return store.ErrNotFound
	}
	log.Printf("user %s: bcrypt password hash rewritten as argon2id", subject)
	return nil
}

// demoUsers stands in for the rows an existing application already has.
var demoUsers = []struct{ email, name, password string }{
	{"alice@example.com", "Alice Example", "alice-password"},
	{"bob@example.com", "Bob Example", "bob-password"},
}

// createDemoUsers creates the application's users table with bcrypt
// hashes, as a system migrating to this OP would already have it. It
// runs with EXAMPLE53_MIGRATE=1 only; a real deployment owns this table
// and its rows. INSERT OR IGNORE is SQLite (MySQL spells it INSERT
// IGNORE), and it keeps a hash a previous login already rewrote.
func createDemoUsers(ctx context.Context, db *databasesql.DB) error {
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS app_users (
		id INTEGER PRIMARY KEY,
		email TEXT UNIQUE NOT NULL,
		display_name TEXT NOT NULL,
		password_hash TEXT
	)`); err != nil {
		return err
	}
	for _, d := range demoUsers {
		hash, err := bcrypt.GenerateFromPassword([]byte(d.password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		if _, err := db.ExecContext(ctx,
			"INSERT OR IGNORE INTO app_users (email, display_name, password_hash) VALUES (?, ?, ?)",
			d.email, d.name, string(hash)); err != nil {
			return err
		}
	}
	return nil
}
