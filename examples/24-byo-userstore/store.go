//go:build example

// store.go — embedder-owned Storage projection for example
// 24-byo-userstore.
//
// This file holds the type that makes BYO-userstore concrete:
// MemberUserStore, the projection from the embedder's members table
// onto store.UserStore + store.UserPasswordStore. The members DDL
// lives here too so the schema and the projection that depends on it
// stay co-located — run() in main.go applies the DDL before
// buildProvider() in op.go passes MemberUserStore to
// op.WithUserStore.
//
// There is no wrapper type around the bundled store. Replacing one
// substore is what op.WithUserStore is for; replacing several is what
// op/storeadapter/composite is for. Hand-writing a wrapper that embeds
// the store.Store interface is the shape to avoid — it compiles, and
// it silently drops every optional capability the backend implements.

package main

import (
	"context"
	databasesql "database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// membersDDL is the embedder-owned schema. Column names deliberately
// avoid the OP's bundled oidc_users layout (subject / claims /
// updated_at / username / password_hash) to make it concrete that
// MemberUserStore is doing the projection: nothing in the OP cares
// about these column names.
const membersDDL = `
CREATE TABLE IF NOT EXISTS members (
    member_id      TEXT PRIMARY KEY,
    email_address  TEXT NOT NULL,
    password_phc   BLOB NOT NULL,
    full_name      TEXT,
    locale_pref    TEXT,
    tenant_id      TEXT,
    last_modified  INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS members_email ON members (email_address);
`

// MemberUserStore projects the members table onto store.User and
// satisfies store.UserPasswordStore. The struct holds only the
// *sql.DB; SQL templates live as string constants below so the
// example is single-file readable. Production embedders would lift
// them into a query builder of their choice.
type MemberUserStore struct {
	db *databasesql.DB
}

const (
	memberSelectBySubject   = `SELECT member_id, email_address, full_name, locale_pref, tenant_id, last_modified FROM members WHERE member_id = ?`
	memberSelectByEmail     = `SELECT member_id, email_address, full_name, locale_pref, tenant_id, last_modified FROM members WHERE email_address = ?`
	memberSelectPasswordPHC = `SELECT password_phc FROM members WHERE member_id = ?`
)

// FindBySubject implements store.UserStore.FindBySubject.
func (m *MemberUserStore) FindBySubject(ctx context.Context, sub string) (*store.User, error) {
	return m.scanMember(ctx, memberSelectBySubject, sub)
}

// FindByUsername implements store.UserPasswordStore.FindByUsername.
// The embedder treats "username" as "email_address" — the column the
// PrimaryPassword Step's input string is matched against. Production
// embedders MAY case-fold the value here as long as FindBySubject is
// consistent so the resolved subject is stable across login paths.
func (m *MemberUserStore) FindByUsername(ctx context.Context, username string) (*store.User, error) {
	return m.scanMember(ctx, memberSelectByEmail, username)
}

// ReadPasswordHash implements store.UserPasswordStore.ReadPasswordHash.
// It returns store.ErrNotFound both when the subject is unknown and
// when the row exists but carries no password (e.g. an
// invitation-only member that has not yet enrolled), so the
// orchestrator surfaces an enumeration-safe response.
func (m *MemberUserStore) ReadPasswordHash(ctx context.Context, subject string) ([]byte, error) {
	var hash []byte
	err := m.db.QueryRowContext(ctx, memberSelectPasswordPHC, subject).Scan(&hash)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("members.ReadPasswordHash: %w", err)
	}
	if len(hash) == 0 {
		return nil, store.ErrNotFound
	}
	out := make([]byte, len(hash))
	copy(out, hash)
	return out, nil
}

// scanMember projects a SELECT row onto store.User. Columns the OP
// does not consume (tenant_id is the example) are still loaded and
// placed on Claims so embedders can demonstrate scope-based
// filtering: the OP releases only the claim names authorised by the
// granted scopes, so tenant remains invisible to the RP unless the
// embedder adds a scope that releases it.
func (m *MemberUserStore) scanMember(ctx context.Context, query, arg string) (*store.User, error) {
	var (
		subject    string
		email      databasesql.NullString
		fullName   databasesql.NullString
		localePref databasesql.NullString
		tenantID   databasesql.NullString
		updatedAt  int64
	)
	err := m.db.QueryRowContext(ctx, query, arg).
		Scan(&subject, &email, &fullName, &localePref, &tenantID, &updatedAt)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("members.scan: %w", err)
	}

	claims := map[string]any{}
	if email.Valid {
		claims["email"] = email.String
	}
	if fullName.Valid {
		claims["name"] = fullName.String
	}
	if localePref.Valid {
		claims["locale"] = localePref.String
	}
	if tenantID.Valid {
		// Custom embedder claim. Not authorised by any standard
		// scope, so the OP filters it out of /userinfo and ID Token
		// responses. Embedders that want to release it MUST register
		// a custom scope or use the OIDC Core §5.5 claims parameter.
		claims["tenant"] = tenantID.String
	}

	return &store.User{
		Subject:   subject,
		Claims:    claims,
		UpdatedAt: time.Unix(updatedAt, 0),
	}, nil
}
