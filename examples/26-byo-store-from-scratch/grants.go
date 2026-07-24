//go:build example

// grants.go — store.GrantStore against vault_consent_ledger. Part of
// the atomic-routing cluster. Save upserts so the contract's "backends
// that perform upsert MAY treat Save as idempotent" path is taken.

package main

import (
	"context"
	databasesql "database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

type grantStore struct {
	q   querier
	now func() time.Time
}

const (
	grantUpsert = `
INSERT INTO vault_consent_ledger
  (ledger_id, principal, relying_party, requested_scope, claim_consent,
   auth_epoch, acr_class, amr_methods, rich_details, issued_epoch,
   touched_epoch, is_revoked)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
ON CONFLICT(ledger_id) DO UPDATE SET
  principal       = excluded.principal,
  relying_party   = excluded.relying_party,
  requested_scope = excluded.requested_scope,
  claim_consent   = excluded.claim_consent,
  auth_epoch      = excluded.auth_epoch,
  acr_class       = excluded.acr_class,
  amr_methods     = excluded.amr_methods,
  rich_details    = excluded.rich_details,
  touched_epoch   = excluded.touched_epoch,
  is_revoked      = 0`

	grantSelectBase = `
SELECT ledger_id, principal, relying_party, requested_scope, claim_consent,
       auth_epoch, acr_class, amr_methods, rich_details, issued_epoch, touched_epoch
FROM vault_consent_ledger`

	grantByID            = grantSelectBase + ` WHERE ledger_id = ? AND is_revoked = 0`
	grantBySubjectClient = grantSelectBase + ` WHERE principal = ? AND relying_party = ? AND is_revoked = 0 ORDER BY touched_epoch DESC LIMIT 1`
	grantBySubject       = grantSelectBase + ` WHERE principal = ? AND is_revoked = 0`
	grantClientIDs       = `SELECT DISTINCT relying_party FROM vault_consent_ledger WHERE principal = ? AND relying_party > ? AND is_revoked = 0 ORDER BY relying_party LIMIT ?`
	grantRevoke          = `UPDATE vault_consent_ledger SET is_revoked = 1 WHERE ledger_id = ? AND is_revoked = 0`
	grantHasAny          = `SELECT 1 FROM vault_consent_ledger LIMIT 1`
)

func (s *grantStore) Save(ctx context.Context, g *store.Grant) error {
	_, err := s.q.ExecContext(ctx, grantUpsert,
		g.ID, g.Subject, g.ClientID, encodeStrings(g.Scope), encodeMap(g.Claims),
		epochOf(g.AuthTime), g.ACR, encodeStrings(g.AMR), encodeObjectArray(g.AuthorizationDetails),
		epochOf(g.CreatedAt), epochOf(g.UpdatedAt))
	if err != nil {
		return fmt.Errorf("grants.Save: %w", err)
	}
	return nil
}

func (s *grantStore) Find(ctx context.Context, id string) (*store.Grant, error) {
	g, err := s.scan(s.q.QueryRowContext(ctx, grantByID, id))
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("grants.Find: %w", err)
	}
	return g, nil
}

func (s *grantStore) FindBySubjectClient(ctx context.Context, subject, clientID string) (*store.Grant, error) {
	g, err := s.scan(s.q.QueryRowContext(ctx, grantBySubjectClient, subject, clientID))
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("grants.FindBySubjectClient: %w", err)
	}
	return g, nil
}

func (s *grantStore) ListBySubject(ctx context.Context, subject string) ([]*store.Grant, error) {
	rows, err := s.q.QueryContext(ctx, grantBySubject, subject)
	if err != nil {
		return nil, fmt.Errorf("grants.ListBySubject: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*store.Grant
	for rows.Next() {
		g, err := s.scan(rows)
		if err != nil {
			return nil, fmt.Errorf("grants.ListBySubject.scan: %w", err)
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("grants.ListBySubject.iter: %w", err)
	}
	return out, nil
}

func (s *grantStore) ListClientIDsBySubject(
	ctx context.Context,
	subject, cursor string,
	limit int,
) (store.GrantClientPage, error) {
	if limit <= 0 {
		return store.GrantClientPage{}, errors.New("grants.ListClientIDsBySubject: limit must be positive")
	}
	rows, err := s.q.QueryContext(ctx, grantClientIDs, subject, cursor, limit+1)
	if err != nil {
		return store.GrantClientPage{}, fmt.Errorf("grants.ListClientIDsBySubject: %w", err)
	}
	defer func() { _ = rows.Close() }()
	clientIDs := make([]string, 0, limit+1)
	for rows.Next() {
		var clientID string
		if err := rows.Scan(&clientID); err != nil {
			return store.GrantClientPage{}, fmt.Errorf("grants.ListClientIDsBySubject.scan: %w", err)
		}
		clientIDs = append(clientIDs, clientID)
	}
	if err := rows.Err(); err != nil {
		return store.GrantClientPage{}, fmt.Errorf("grants.ListClientIDsBySubject.iter: %w", err)
	}
	page := store.GrantClientPage{ClientIDs: clientIDs}
	if len(page.ClientIDs) > limit {
		page.ClientIDs = page.ClientIDs[:limit]
		page.NextCursor = page.ClientIDs[len(page.ClientIDs)-1]
	}
	return page, nil
}

func (s *grantStore) Delete(ctx context.Context, id string) error {
	res, err := s.q.ExecContext(ctx, grantRevoke, id)
	if err != nil {
		return fmt.Errorf("grants.Delete: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("grants.Delete.RowsAffected: %w", err)
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *grantStore) HasAny(ctx context.Context) (bool, error) {
	var probe int
	err := s.q.QueryRowContext(ctx, grantHasAny).Scan(&probe)
	if errors.Is(err, databasesql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("grants.HasAny: %w", err)
	}
	return true, nil
}

// scanner abstracts *sql.Row and *sql.Rows so scan drives both the
// single-row and multi-row paths through one helper.
type scanner interface {
	Scan(dest ...any) error
}

func (s *grantStore) scan(sc scanner) (*store.Grant, error) {
	var (
		g         store.Grant
		scope     string
		claims    string
		amr       string
		details   string
		authEpoch int64
		created   int64
		touched   int64
	)
	if err := sc.Scan(
		&g.ID, &g.Subject, &g.ClientID, &scope, &claims,
		&authEpoch, &g.ACR, &amr, &details, &created, &touched,
	); err != nil {
		return nil, err
	}
	g.Scope = decodeStrings(scope)
	g.Claims = decodeMap(claims)
	g.AMR = decodeStrings(amr)
	g.AuthorizationDetails = decodeObjectArray(details)
	g.AuthTime = timeOf(authEpoch)
	g.CreatedAt = timeOf(created)
	g.UpdatedAt = timeOf(touched)
	return &g, nil
}
