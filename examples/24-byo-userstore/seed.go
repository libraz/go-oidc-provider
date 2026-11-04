//go:build example

// seed.go — demo-row seeder for example 24-byo-userstore.
//
// seedMember upserts a single members row so an operator can drive
// the manual login walkthrough (steps 1–5 in the package godoc) on a
// fresh SQLite database. The PHC-encoded password hash comes from
// op.HashPassword; production embedders enrol members through their
// own management plane and never call this helper.
//
// The subject is random and generated once: a re-run against an
// existing row keeps the stored value, because a subject must never
// change after RPs have keyed an account on it.

package main

import (
	"context"
	"crypto/rand"
	databasesql "database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/libraz/go-oidc-provider/op"
)

// newSubject returns a 128-bit random identifier, hex-encoded.
func newSubject() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("random subject: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// seedMember upserts the demo row and returns its subject.
func seedMember(ctx context.Context, db *databasesql.DB) (string, error) {
	hash, err := op.HashPassword(demoPassword)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	subject, err := newSubject()
	if err != nil {
		return "", err
	}
	const upsert = `
INSERT INTO members (member_id, subject, email_address, password_phc, full_name, locale_pref, tenant_id, last_modified)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(member_id) DO UPDATE SET
    email_address = excluded.email_address,
    password_phc  = excluded.password_phc,
    full_name     = excluded.full_name,
    locale_pref   = excluded.locale_pref,
    tenant_id     = excluded.tenant_id,
    last_modified = excluded.last_modified;
`
	now := time.Now().Unix() //nolint:forbidigo // example seed script — not OP business logic; examples use only the public op API.
	if _, err = db.ExecContext(ctx, upsert,
		demoMemberID, subject, demoUsername, hash,
		"Demo Member", "en-US", "tenant-acme", now,
	); err != nil {
		return "", fmt.Errorf("seed member: %w", err)
	}
	// subject is deliberately absent from the DO UPDATE list, so read back
	// the stored value rather than the one just generated.
	var stored string
	if err := db.QueryRowContext(ctx, `SELECT subject FROM members WHERE member_id = ?`, demoMemberID).Scan(&stored); err != nil {
		return "", fmt.Errorf("read seeded subject: %w", err)
	}
	return stored, nil
}
