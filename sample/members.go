//go:build example

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	opstore "github.com/libraz/go-oidc-provider/op/store"
)

// The application owns its account table outright. None of these column
// names match the OP's bundled oidc_users schema, and several columns —
// display_name, signed_up_at, totp_enabled — exist for the application's
// own screens and are never observed by the library. That is the point: the
// OP reaches accounts only through the store interfaces below.
const membersDDL = `
CREATE TABLE IF NOT EXISTS members (
  member_id     VARCHAR(64)  NOT NULL PRIMARY KEY,
  email         VARCHAR(320) NOT NULL,
  password_phc  VARBINARY(255) NOT NULL,
  display_name  VARCHAR(120) NOT NULL,
  totp_enabled  TINYINT(1)   NOT NULL DEFAULT 0,
  signed_up_at  DATETIME(6)  NOT NULL,
  updated_at    DATETIME(6)  NOT NULL,
  UNIQUE KEY members_email_unique (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`

// errEmailTaken is returned by signUp when the address is already
// registered. Signup surfaces it as a form error rather than a 500.
var errEmailTaken = errors.New("that email address is already registered")

// member is the application's own account record.
type member struct {
	ID          string
	Email       string
	DisplayName string
	TOTPEnabled bool
	UpdatedAt   time.Time
}

// memberStore is the application's account table projected onto the two
// store interfaces the OP needs. It implements
// [opstore.UserPasswordStore]: FindBySubject and FindByUsername project
// rows onto opstore.User, and ReadPasswordHash returns the PHC string the
// built-in password step verifies. Everything else on this type serves the
// application's own screens and is invisible to the library.
type memberStore struct {
	db *sql.DB
}

func newMemberStore(ctx context.Context, db *sql.DB) (*memberStore, error) {
	if _, err := db.ExecContext(ctx, membersDDL); err != nil {
		return nil, fmt.Errorf("create members table: %w", err)
	}
	return &memberStore{db: db}, nil
}

// normaliseEmail decides the application's identity rule. The library
// passes whatever the login form submitted verbatim, so case-folding is
// the application's responsibility — and it has to be the same rule at
// signup and at login or the two disagree.
func normaliseEmail(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

// FindBySubject implements [opstore.UserStore].
func (s *memberStore) FindBySubject(ctx context.Context, sub string) (*opstore.User, error) {
	const q = `SELECT member_id, email, display_name, updated_at FROM members WHERE member_id = ?`
	return s.projectOne(ctx, q, sub)
}

// FindByUsername implements [opstore.UserPasswordStore]. The application's
// username is the email address, normalised the same way signup does.
func (s *memberStore) FindByUsername(ctx context.Context, username string) (*opstore.User, error) {
	const q = `SELECT member_id, email, display_name, updated_at FROM members WHERE email = ?`
	return s.projectOne(ctx, q, normaliseEmail(username))
}

// ReadPasswordHash implements [opstore.UserPasswordStore].
func (s *memberStore) ReadPasswordHash(ctx context.Context, sub string) ([]byte, error) {
	const q = `SELECT password_phc FROM members WHERE member_id = ?`
	var phc []byte
	switch err := s.db.QueryRowContext(ctx, q, sub).Scan(&phc); {
	case errors.Is(err, sql.ErrNoRows):
		return nil, opstore.ErrNotFound
	case err != nil:
		return nil, err
	}
	return phc, nil
}

// projectOne maps one row onto the library's view of a user. Only the
// claims the OP may release are included; the application's other columns
// stay behind.
func (s *memberStore) projectOne(ctx context.Context, query, arg string) (*opstore.User, error) {
	var (
		id, email, name string
		updated         time.Time
	)
	switch err := s.db.QueryRowContext(ctx, query, arg).Scan(&id, &email, &name, &updated); {
	case errors.Is(err, sql.ErrNoRows):
		return nil, opstore.ErrNotFound
	case err != nil:
		return nil, err
	}
	return &opstore.User{
		Subject: id,
		Claims: map[string]any{
			"email":          email,
			"email_verified": false,
			"name":           name,
		},
		UpdatedAt: updated,
	}, nil
}

// signUp creates an account and returns its subject. The subject is
// generated rather than derived from the email so a member can change
// their address without breaking the "sub" claim already issued to
// relying parties, which OIDC Core requires to be stable.
func (s *memberStore) signUp(ctx context.Context, email, displayName, password string, now time.Time) (string, error) {
	normalised := normaliseEmail(email)
	hash, err := op.HashPassword(password)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	subject, err := newOpaqueID()
	if err != nil {
		return "", err
	}
	const q = `INSERT INTO members
	  (member_id, email, password_phc, display_name, totp_enabled, signed_up_at, updated_at)
	  VALUES (?, ?, ?, ?, 0, ?, ?)`
	if _, err := s.db.ExecContext(ctx, q, subject, normalised, hash, displayName, now, now); err != nil {
		if isDuplicateKey(err) {
			return "", errEmailTaken
		}
		return "", err
	}
	return subject, nil
}

// find returns the application's own view of an account.
func (s *memberStore) find(ctx context.Context, subject string) (*member, error) {
	const q = `SELECT member_id, email, display_name, totp_enabled, updated_at
	           FROM members WHERE member_id = ?`
	var (
		m       member
		enabled int
	)
	switch err := s.db.QueryRowContext(ctx, q, subject).
		Scan(&m.ID, &m.Email, &m.DisplayName, &enabled, &m.UpdatedAt); {
	case errors.Is(err, sql.ErrNoRows):
		return nil, opstore.ErrNotFound
	case err != nil:
		return nil, err
	}
	m.TOTPEnabled = enabled == 1
	return &m, nil
}

// changePassword replaces the stored hash. Existing sessions and refresh
// tokens are deliberately left alone: whether a password change revokes
// them is a policy decision, and this application shows the seam rather
// than making the choice for an embedder.
func (s *memberStore) changePassword(ctx context.Context, subject, password string, now time.Time) error {
	hash, err := op.HashPassword(password)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	const q = `UPDATE members SET password_phc = ?, updated_at = ? WHERE member_id = ?`
	res, err := s.db.ExecContext(ctx, q, hash, now, subject)
	if err != nil {
		return err
	}
	return expectOneRow(res)
}

// setTOTPEnabled records that the member finished enrolment. The secret
// itself lives in the OP's TOTP substore; this column exists only so the
// application's own screens can tell the member what is switched on.
func (s *memberStore) setTOTPEnabled(ctx context.Context, subject string, enabled bool, now time.Time) error {
	flag := 0
	if enabled {
		flag = 1
	}
	const q = `UPDATE members SET totp_enabled = ?, updated_at = ? WHERE member_id = ?`
	res, err := s.db.ExecContext(ctx, q, flag, now, subject)
	if err != nil {
		return err
	}
	return expectOneRow(res)
}

func expectOneRow(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return opstore.ErrNotFound
	}
	return nil
}

// isDuplicateKey recognises MySQL error 1062 without importing the driver
// package here; the string form is stable across driver versions and keeps
// this file free of a driver dependency.
func isDuplicateKey(err error) bool {
	return err != nil && strings.Contains(err.Error(), "Error 1062")
}
