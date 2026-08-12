package oidcsql

import (
	"context"
	databasesql "database/sql"
	"errors"
	"fmt"

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
	claims, err := encodeMap(g.Claims)
	if err != nil {
		return fmt.Errorf("oidcsql: grants.Save claims: %w", err)
	}
	details, err := encodeObjectArray(g.AuthorizationDetails)
	if err != nil {
		return fmt.Errorf("oidcsql: grants.Save authorization details: %w", err)
	}
	_, err = s.runner().ExecContext(ctx, s.parent.queries.grantSave,
		g.ID, g.Subject, g.ClientID,
		encodeStrings(g.Scope), claims,
		timeToInt64(g.AuthTime), g.ACR, encodeStrings(g.AMR),
		details,
		timeToInt64(g.CreatedAt), timeToInt64(g.UpdatedAt))
	if err != nil {
		return wrapErr("grants.Save", err)
	}
	return nil
}

func (s *grantStore) Find(ctx context.Context, id string) (*store.Grant, error) {
	query := s.parent.queries.grantFind
	if s.tx != nil {
		query = s.parent.queries.grantFindForUpdate
	}
	rec, err := s.scan(s.runner().QueryRowContext(ctx, query, id))
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, wrapErr("grants.Find", err)
	}
	return rec, nil
}

func (s *grantStore) FindBySubjectClient(ctx context.Context, subject, clientID string) (*store.Grant, error) {
	query := s.parent.queries.grantFindBySubjectClient
	if s.tx != nil {
		query = s.parent.queries.grantFindBySubjectClientForUpdate
	}
	rec, err := s.scan(s.runner().QueryRowContext(ctx, query, subject, clientID))
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

func (s *grantStore) ListClientIDsBySubject(
	ctx context.Context,
	subject, cursor string,
	limit int,
) (store.GrantClientPage, error) {
	if limit <= 0 {
		return store.GrantClientPage{}, errors.New("oidcsql: grant client page limit must be positive")
	}
	rows, err := s.runner().QueryContext(
		ctx,
		s.parent.queries.grantListClientIDs,
		subject,
		cursor,
		limit+1,
	)
	if err != nil {
		return store.GrantClientPage{}, wrapErr("grants.ListClientIDsBySubject", err)
	}
	defer rows.Close() //nolint:errcheck // rows.Err below reports iteration failures.
	clientIDs := make([]string, 0, limit+1)
	for rows.Next() {
		var clientID string
		if err := rows.Scan(&clientID); err != nil {
			return store.GrantClientPage{}, wrapErr("grants.ListClientIDsBySubject.scan", err)
		}
		clientIDs = append(clientIDs, clientID)
	}
	if err := rows.Err(); err != nil {
		return store.GrantClientPage{}, wrapErr("grants.ListClientIDsBySubject.iter", err)
	}
	page := store.GrantClientPage{ClientIDs: clientIDs}
	if len(page.ClientIDs) > limit {
		page.ClientIDs = page.ClientIDs[:limit]
		page.NextCursor = page.ClientIDs[len(page.ClientIDs)-1]
	}
	return page, nil
}

// ListSubjectsByClient returns a bounded, distinct keyset page for the
// client-scoped grant view used by registration deletion fan-out. The
// limit+1 fetch lets callers detect another page without materialising every
// grant row or subject in the database.
func (s *grantStore) ListSubjectsByClient(
	ctx context.Context,
	clientID, cursor string,
	limit int,
) (store.GrantSubjectPage, error) {
	if limit <= 0 {
		return store.GrantSubjectPage{}, errors.New("oidcsql: grant subject page limit must be positive")
	}
	rows, err := s.runner().QueryContext(
		ctx,
		s.parent.queries.grantListSubjects,
		clientID,
		cursor,
		limit+1,
	)
	if err != nil {
		return store.GrantSubjectPage{}, wrapErr("grants.ListSubjectsByClient", err)
	}
	defer rows.Close() //nolint:errcheck // rows.Err below reports iteration failures.
	subjects := make([]string, 0, limit+1)
	for rows.Next() {
		var subject string
		if err := rows.Scan(&subject); err != nil {
			return store.GrantSubjectPage{}, wrapErr("grants.ListSubjectsByClient.scan", err)
		}
		subjects = append(subjects, subject)
	}
	if err := rows.Err(); err != nil {
		return store.GrantSubjectPage{}, wrapErr("grants.ListSubjectsByClient.iter", err)
	}
	page := store.GrantSubjectPage{Subjects: subjects}
	if len(page.Subjects) > limit {
		page.Subjects = page.Subjects[:limit]
		page.NextCursor = page.Subjects[len(page.Subjects)-1]
	}
	return page, nil
}

func (s *grantStore) HasAny(ctx context.Context) (bool, error) {
	var probe int
	err := s.runner().QueryRowContext(ctx, s.parent.queries.grantHasAny).Scan(&probe)
	if errors.Is(err, databasesql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, wrapErr("grants.HasAny", err)
	}
	return true, nil
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

// RevokeByClient implements [store.RevokeByClient]. The dynamic
// registration cascade invokes it after a successful
// DELETE /register/{client_id} so the deleted client's grants are
// removed in one shot. A missing client is not an error.
func (s *grantStore) RevokeByClient(ctx context.Context, clientID string) error {
	if clientID == "" {
		return nil
	}
	if _, err := s.runner().ExecContext(ctx, s.parent.queries.grantDeleteByClient, clientID); err != nil {
		return wrapErr("grants.RevokeByClient", err)
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
		g          store.Grant
		scopeRaw   []byte
		claimsRaw  []byte
		amrRaw     []byte
		detailsRaw []byte
		authTime   int64
		created    int64
		updated    int64
	)
	if err := sc.Scan(
		&g.ID, &g.Subject, &g.ClientID,
		&scopeRaw, &claimsRaw, &authTime,
		&g.ACR, &amrRaw, &detailsRaw,
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
	details, err := decodeObjectArray(detailsRaw)
	if err != nil {
		return nil, err
	}
	g.Scope = scope
	g.Claims = claims
	g.AMR = amr
	g.AuthorizationDetails = details
	g.AuthTime = int64ToTime(authTime)
	g.CreatedAt = int64ToTime(created)
	g.UpdatedAt = int64ToTime(updated)
	return &g, nil
}
