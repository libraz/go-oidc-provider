//go:build example

package main

import (
	"context"
	databasesql "database/sql"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
)

// userTable adapts the application's own users table to the login flow.
// The OP never sees the column names: it asks for a user by subject or
// by username, reads the stored hash, and writes a new hash back once a
// bcrypt hash has verified. A row with disabled_at set is treated as
// absent (store.ErrNotFound), so a disabled user cannot sign in or
// resolve at /userinfo; disableUser sets it. The subject is the subject column, an opaque
// value assigned once per row and never reused; the row id would leak
// the user count to every RP and can be reissued after a delete.
type userTable struct{ db *databasesql.DB }

var (
	_ store.UserPasswordStore       = (*userTable)(nil)
	_ store.UserPasswordHashUpdater = (*userTable)(nil)
	_ store.SchemaValidator         = (*userTable)(nil)
)

// ValidateSchema is called by op.New, so a missing app_users table or
// column fails at startup instead of on the first login. It reads
// nothing: WHERE 1 = 0 makes the database resolve every column and
// return no rows.
func (u *userTable) ValidateSchema(ctx context.Context) error {
	rows, err := u.db.QueryContext(ctx,
		"SELECT subject, email, display_name, password_hash, disabled_at FROM app_users WHERE 1 = 0")
	if err != nil {
		return fmt.Errorf("app_users table does not match what the user store reads: %w", err)
	}
	return rows.Close()
}

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
	err := u.db.QueryRowContext(ctx, "SELECT subject, email, display_name FROM app_users WHERE disabled_at IS NULL AND "+where, arg).
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
	err := u.db.QueryRowContext(ctx, "SELECT password_hash FROM app_users WHERE subject = ? AND disabled_at IS NULL", subject).Scan(&hash)
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
	res, err := u.db.ExecContext(ctx, "UPDATE app_users SET password_hash = ? WHERE subject = ? AND disabled_at IS NULL", string(encoded), subject)
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

// disableUser disables the user in the application's table first, then
// revokes every grant the subject holds so refresh tokens and the access
// tokens behind them stop working. The order matters: with the row
// disabled, the user cannot sign in again between the two steps. Browser
// sessions are not revoked, but a session cannot mint tokens once its
// grants are gone, and the next /authorize fails to resolve the subject.
// Run it again after a failed revocation; both steps are idempotent.
func disableUser(ctx context.Context, db *databasesql.DB, provider *op.Provider, subject string) error {
	if _, err := db.ExecContext(ctx,
		"UPDATE app_users SET disabled_at = ? WHERE subject = ? AND disabled_at IS NULL",
		time.Now().UTC().Format(time.RFC3339), subject); err != nil { //nolint:forbidigo // example admin command; embedders pass their own clock.
		return fmt.Errorf("disable user: %w", err)
	}
	if err := provider.RevokeSubject(ctx, subject); err != nil {
		return fmt.Errorf("revoke subject: %w", err)
	}
	return nil
}

// disableUserByEmail resolves the subject of the (possibly already
// disabled) account with the given email and disables it.
func disableUserByEmail(ctx context.Context, db *databasesql.DB, provider *op.Provider, email string) error {
	var subject string
	err := db.QueryRowContext(ctx, "SELECT subject FROM app_users WHERE email = ?",
		strings.ToLower(strings.TrimSpace(email))).Scan(&subject)
	if errors.Is(err, databasesql.ErrNoRows) {
		return fmt.Errorf("no user with email %q", email)
	}
	if err != nil {
		return err
	}
	return disableUser(ctx, db, provider, subject)
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
// and backfills it once; the bring-your-own user store page gives the
// ALTER for each engine. The random default here is SQLite's spelling.
func createDemoUsers(ctx context.Context, db *databasesql.DB) error {
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS app_users (
		id INTEGER PRIMARY KEY,
		subject TEXT UNIQUE NOT NULL DEFAULT (lower(hex(randomblob(16)))),
		email TEXT UNIQUE NOT NULL,
		display_name TEXT NOT NULL,
		password_hash TEXT,
		disabled_at TEXT
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
