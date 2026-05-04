//go:build example

// seed.go — demo-row seeder for example 18-byo-userstore.
//
// seedMember upserts a single members row so an operator can drive
// the manual login walkthrough (steps 1–5 in the package godoc) on a
// fresh SQLite database. The PHC-encoded password hash comes from
// op.HashPassword; production embedders enrol members through their
// own management plane and never call this helper.

package main

import (
	"context"
	databasesql "database/sql"
	"fmt"
	"time"

	"github.com/libraz/go-oidc-provider/op"
)

func seedMember(ctx context.Context, db *databasesql.DB) error {
	hash, err := op.HashPassword(demoPassword)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	const upsert = `
INSERT INTO members (member_id, email_address, password_phc, full_name, locale_pref, tenant_id, last_modified)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(member_id) DO UPDATE SET
    email_address = excluded.email_address,
    password_phc  = excluded.password_phc,
    full_name     = excluded.full_name,
    locale_pref   = excluded.locale_pref,
    tenant_id     = excluded.tenant_id,
    last_modified = excluded.last_modified;
`
	now := time.Now().Unix() //nolint:forbidigo // example seed script — not OP business logic; internal/timex is unreachable from examples/.
	_, err = db.ExecContext(ctx, upsert,
		demoSubject, demoUsername, hash,
		"Demo Member", "en-US", "tenant-acme", now,
	)
	if err != nil {
		return fmt.Errorf("seed member: %w", err)
	}
	return nil
}
