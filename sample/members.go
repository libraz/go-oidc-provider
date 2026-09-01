//go:build example

package main

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/libraz/go-oidc-provider/op"
	opstore "github.com/libraz/go-oidc-provider/op/store"
)

// The application owns its account table outright. None of these column
// names match the OP's bundled oidc_users schema, and several columns —
// display_name, signed_up_at, totp_enabled — exist for the application's
// own screens and are never observed by the library. That is the point: the
// OP reaches accounts only through the store interfaces below.
//
// The email column pins its own collation. MySQL 8.4's default for
// utf8mb4 is utf8mb4_0900_ai_ci, which is accent-insensitive as well as
// case-insensitive: under it "cafe@example.com" and "café@example.com"
// are the same row, so a lookup by one address can resolve the other
// member's account. utf8mb4_bin makes the unique key and every WHERE
// clause compare bytes, which leaves normaliseEmail as the only place
// that decides which addresses are the same person.
const membersDDL = `
CREATE TABLE IF NOT EXISTS members (
  member_id     VARCHAR(64)  NOT NULL PRIMARY KEY,
  email         VARCHAR(320) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
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

// errPasswordMismatch is returned when a re-authentication does not
// present the member's current password.
var errPasswordMismatch = errors.New("that password is not correct")

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
//
// It is the only place that rule lives, which is why the email column's
// collation is pinned to utf8mb4_bin: a case- or accent-insensitive
// collation would fold addresses this function considers distinct, and
// the identity rule would then be split between here and the schema.
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

// verifyPassword reports whether password is the member's current one.
// Changing a credential has to present the credential it replaces, so
// the password change and the second-factor enrolment both come through
// here before they alter anything.
func (s *memberStore) verifyPassword(ctx context.Context, subject, password string) error {
	stored, err := s.ReadPasswordHash(ctx, subject)
	if err != nil {
		return err
	}
	return matchPasswordHash(password, string(stored))
}

// maxPasswordHashBytes bounds the derived-key length read out of a stored
// record, so a record claiming an absurd length cannot turn one
// verification into an allocation the process cannot serve.
const maxPasswordHashBytes = 1024

// matchPasswordHash checks a plaintext against the PHC argon2id encoding
// op.HashPassword produced. The library hashes but does not export a
// verifier: it verifies passwords itself inside the login flow, and an
// application that adds a re-authentication step of its own does the
// comparison on its own side.
//
// Every failure returns the same error. A malformed stored record and a
// wrong password are both "not authenticated" here, and telling them
// apart would only describe the stored value to whoever is guessing.
func matchPasswordHash(password, encoded string) error {
	// "$argon2id$v=19$m=65536,t=3,p=1$<salt>$<hash>" splits into six
	// fields, the first of which is empty.
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return errPasswordMismatch
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return errPasswordMismatch
	}
	var (
		memory      uint32
		iterations  uint32
		parallelism uint8
	)
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return errPasswordMismatch
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return errPasswordMismatch
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) == 0 || len(want) > maxPasswordHashBytes {
		return errPasswordMismatch
	}
	//nolint:gosec // G115: len(want) is bounded by maxPasswordHashBytes on the line above.
	keyLength := uint32(len(want))
	got := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, keyLength)
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return errPasswordMismatch
	}
	return nil
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
