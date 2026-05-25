//go:build example

// seed.go — demo-row seeders.
//
// seedUser upserts a single vault_principals row and seedClient upserts
// the demo client into vault_relying_parties so an operator can drive
// the manual login walkthrough on a fresh database. The PHC-encoded
// password hash comes from op.HashPassword; production embedders enrol
// users and clients through their own management plane and never call
// these helpers.

package main

import (
	"context"
	databasesql "database/sql"
	"fmt"
	"time"

	"github.com/libraz/go-oidc-provider/op"
)

func seedUser(ctx context.Context, db *databasesql.DB) error {
	hash, err := op.HashPassword(demoPassword)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	const upsert = `
INSERT INTO vault_principals (principal, login_handle, secret_phc, display_name, contact_email, last_touched)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(principal) DO UPDATE SET
    login_handle  = excluded.login_handle,
    secret_phc    = excluded.secret_phc,
    display_name  = excluded.display_name,
    contact_email = excluded.contact_email,
    last_touched  = excluded.last_touched;`
	now := time.Now().Unix() //nolint:forbidigo // example seed script — not OP business logic; internal/timex is unreachable from examples/.
	if _, err := db.ExecContext(ctx, upsert,
		demoSubject, demoUsername, hash, "Demo User", demoUsername, now,
	); err != nil {
		return fmt.Errorf("seed principal: %w", err)
	}
	return nil
}

func seedClient(ctx context.Context, db *databasesql.DB) error {
	const upsert = `
INSERT INTO vault_relying_parties (relying_party, redirect_targets, permitted_scope, is_public)
VALUES (?, ?, ?, 1)
ON CONFLICT(relying_party) DO UPDATE SET
    redirect_targets = excluded.redirect_targets,
    permitted_scope  = excluded.permitted_scope,
    is_public        = excluded.is_public;`
	redirects := encodeStrings([]string{redirectURI})
	scopes := encodeStrings([]string{"openid", "profile", "email"})
	if _, err := db.ExecContext(ctx, upsert, clientID, redirects, scopes); err != nil {
		return fmt.Errorf("seed relying party: %w", err)
	}
	return nil
}
