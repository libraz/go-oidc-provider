package oidcsql

import (
	"context"
	databasesql "database/sql"
	"errors"

	"github.com/libraz/go-oidc-provider/op/store"
)

type grantStore struct {
	parent *Store
	tx     *databasesql.Tx
}

func newGrantStore(s *Store, tx *databasesql.Tx) *grantStore {
	return &grantStore{parent: s, tx: tx}
}

func (s *grantStore) runner() runner { return pickRunner(s.parent, s.tx) }

func (s *grantStore) Save(ctx context.Context, g *store.Grant) error {
	_, err := s.runner().ExecContext(ctx, s.parent.queries.grantSave,
		g.ID, g.Subject, g.ClientID,
		encodeStrings(g.Scope), encodeMap(g.Claims),
		timeToInt64(g.AuthTime), g.ACR, encodeStrings(g.AMR),
		timeToInt64(g.CreatedAt), timeToInt64(g.UpdatedAt))
	if err != nil {
		return wrapErr("grants.Save", err)
	}
	return nil
}

func (s *grantStore) Find(ctx context.Context, id string) (*store.Grant, error) {
	rec, err := s.scan(s.runner().QueryRowContext(ctx, s.parent.queries.grantFind, id))
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, wrapErr("grants.Find", err)
	}
	return rec, nil
}

func (s *grantStore) FindBySubjectClient(ctx context.Context, subject, clientID string) (*store.Grant, error) {
	rec, err := s.scan(s.runner().QueryRowContext(ctx,
		s.parent.queries.grantFindBySubjectClient, subject, clientID))
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, wrapErr("grants.FindBySubjectClient", err)
	}
	return rec, nil
}

func (s *grantStore) ListBySubject(ctx context.Context, subject string) ([]*store.Grant, error) {
	rows, err := s.runner().QueryContext(ctx, s.parent.queries.grantListBySubject, subject)
	if err != nil {
		return nil, wrapErr("grants.ListBySubject", err)
	}
	defer rows.Close() //nolint:errcheck // best-effort close; the explicit error path inside the loop already handles failure.
	var out []*store.Grant
	for rows.Next() {
		rec, err := s.scan(rowProxy{rows})
		if err != nil {
			return nil, wrapErr("grants.ListBySubject.scan", err)
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapErr("grants.ListBySubject.iter", err)
	}
	return out, nil
}

func (s *grantStore) Delete(ctx context.Context, id string) error {
	res, err := s.runner().ExecContext(ctx, s.parent.queries.grantDelete, id)
	if err != nil {
		return wrapErr("grants.Delete", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return wrapErr("grants.Delete.RowsAffected", err)
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// scanner abstracts *sql.Row and *sql.Rows so [grantStore.scan] can
// drive both single-row Find and multi-row List paths through one
// helper.
type scanner interface {
	Scan(dest ...any) error
}

// rowProxy adapts *sql.Rows to the scanner interface (Rows.Scan
// already matches the signature, but the named type makes the
// adaptation explicit).
type rowProxy struct {
	rows *databasesql.Rows
}

func (r rowProxy) Scan(dest ...any) error { return r.rows.Scan(dest...) }

func (s *grantStore) scan(sc scanner) (*store.Grant, error) {
	var (
		g         store.Grant
		scopeRaw  []byte
		claimsRaw []byte
		amrRaw    []byte
		authTime  int64
		created   int64
		updated   int64
	)
	if err := sc.Scan(
		&g.ID, &g.Subject, &g.ClientID,
		&scopeRaw, &claimsRaw, &authTime,
		&g.ACR, &amrRaw,
		&created, &updated,
	); err != nil {
		return nil, err
	}
	scope, err := decodeStrings(scopeRaw)
	if err != nil {
		return nil, err
	}
	claims, err := decodeMap(claimsRaw)
	if err != nil {
		return nil, err
	}
	amr, err := decodeStrings(amrRaw)
	if err != nil {
		return nil, err
	}
	g.Scope = scope
	g.Claims = claims
	g.AMR = amr
	g.AuthTime = int64ToTime(authTime)
	g.CreatedAt = int64ToTime(created)
	g.UpdatedAt = int64ToTime(updated)
	return &g, nil
}
