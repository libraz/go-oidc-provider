//go:build example

package main

import (
	"context"
	databasesql "database/sql"
	"errors"
	"log"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/libraz/go-oidc-provider/op/store"
)

// userTable adapts the application's own users table to the login flow.
// The OP never sees the column names: it asks for a user by subject or
// by username, reads the stored hash, and writes a new hash back once a
// bcrypt hash has verified. The subject is the subject column, an opaque
// value assigned once per row and never reused; the row id would leak
// the user count to every RP and can be reissued after a delete.
type userTable struct{ db *databasesql.DB }

var (
	_ store.UserPasswordStore       = (*userTable)(nil)
	_ store.UserPasswordHashUpdater = (*userTable)(nil)
)

// FindBySubject resolves the "sub" claim back to a row.
func (u *userTable) FindBySubject(ctx context.Context, sub string) (*store.User, error) {
	return u.find(ctx, "subject = ?", sub)
}

// FindByUsername looks the login name up by email, case-folded the same
// way the rows were written.
func (u *userTable) FindByUsername(ctx context.Context, username string) (*store.User, error) {
	return u.find(ctx, "email = ?", strings.ToLower(strings.TrimSpace(username)))
}

func (u *userTable) find(ctx context.Context, where string, arg any) (*store.User, error) {
	var subject, email, name string
	err := u.db.QueryRowContext(ctx, "SELECT subject, email, display_name FROM app_users WHERE "+where, arg).
		Scan(&subject, &email, &name)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &store.User{
		Subject: subject,
		// The table records no email verification, so email_verified
		// is released as false.
		Claims: store.StandardClaims{Name: name, Email: email}.Map(),
	}, nil
}

// ReadPasswordHash returns the stored hash as is: a bcrypt "$2a$" hash
// is verified by the scheme listed in LegacySchemes, an "$argon2id$" one
// by the OP itself.
func (u *userTable) ReadPasswordHash(ctx context.Context, subject string) ([]byte, error) {
	var hash databasesql.NullString
	err := u.db.QueryRowContext(ctx, "SELECT password_hash FROM app_users WHERE subject = ?", subject).Scan(&hash)
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
	res, err := u.db.ExecContext(ctx, "UPDATE app_users SET password_hash = ? WHERE subject = ?", string(encoded), subject)
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
// A table without an opaque immutable identifier adds the subject column
// and backfills it once; the random default here is SQLite's spelling
// (MySQL 8.0.13+ writes DEFAULT (UUID())).
func createDemoUsers(ctx context.Context, db *databasesql.DB) error {
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS app_users (
		id INTEGER PRIMARY KEY,
		subject TEXT UNIQUE NOT NULL DEFAULT (lower(hex(randomblob(16)))),
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
