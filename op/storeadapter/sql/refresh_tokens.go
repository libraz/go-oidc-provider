package oidcsql

import (
	"context"
	databasesql "database/sql"
	"errors"

	"github.com/libraz/go-oidc-provider/op/store"
)

type refreshStore struct {
	parent *Store
	tx     *databasesql.Tx
}

func newRefreshStore(s *Store, tx *databasesql.Tx) *refreshStore {
	return &refreshStore{parent: s, tx: tx}
}

func (s *refreshStore) runner() runner { return pickRunner(s.parent, s.tx) }

func (s *refreshStore) Save(ctx context.Context, t *store.RefreshToken) error {
	_, err := s.runner().ExecContext(ctx, s.parent.queries.refreshSave,
		t.ID, t.ClientID, t.GrantID, nullableString(t.ParentID), t.Subject,
		encodeStrings(t.Scope), t.Resource,
		t.DPoPJKT, t.MTLSCertThumbprint, t.Nonce, boolToInt64(t.Revoked),
		timeToInt64(t.ExpiresAt), timePtrToInt64Ptr(t.ConsumedAt), timeToInt64(t.CreatedAt))
	if err != nil {
		if isDuplicate(err) {
			return store.ErrAlreadyExists
		}
		return wrapErr("refreshes.Save", err)
	}
	return nil
}

// nullableString folds *string into the database/sql nullable shape
// the drivers expect. Pgx and the mysql driver both accept (*string)(nil)
// as NULL; the modernc.org sqlite driver also accepts it. The helper
// is purely cosmetic: callers do not need to remember the convention.
func nullableString(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

func (s *refreshStore) find(ctx context.Context, id string) (*store.RefreshToken, error) {
	var (
		t        store.RefreshToken
		scope    []byte
		parent   *string
		consumed *int64
		expires  int64
		created  int64
		revoked  int64
	)
	err := s.runner().QueryRowContext(ctx, s.parent.queries.refreshFind, id).Scan(
		&t.ID, &t.ClientID, &t.Subject, &t.GrantID,
		&scope, &t.Resource, &parent, &consumed, &expires, &created,
		&t.DPoPJKT, &t.MTLSCertThumbprint, &t.Nonce, &revoked)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, wrapErr("refreshes.Find", err)
	}
	dec, err := decodeStrings(scope)
	if err != nil {
		return nil, err
	}
	t.Scope = dec
	t.ParentID = parent
	t.ConsumedAt = int64PtrToTimePtr(consumed)
	t.ExpiresAt = int64ToTime(expires)
	t.CreatedAt = int64ToTime(created)
	t.Revoked = int64ToBool(revoked)
	return &t, nil
}

func (s *refreshStore) Find(ctx context.Context, id string) (*store.RefreshToken, error) {
	t, err := s.find(ctx, id)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (s *refreshStore) Consume(ctx context.Context, id string) (*store.RefreshToken, error) {
	t, err := s.find(ctx, id)
	if err != nil {
		return nil, err
	}
	if t.ConsumedAt != nil {
		return nil, store.ErrAlreadyConsumed
	}
	now := s.parent.clock.Now()
	res, err := s.runner().ExecContext(ctx, s.parent.queries.refreshConsume, timeToInt64(now), id)
	if err != nil {
		return nil, wrapErr("refreshes.Consume", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, wrapErr("refreshes.Consume.RowsAffected", err)
	}
	if n == 0 {
		return nil, store.ErrAlreadyConsumed
	}
	t.ConsumedAt = &now
	return t, nil
}

// RevokeChain marks every refresh token in the rotation chain rooted
// at rootID as consumed. Backends that delete or mark equivalently
// satisfy the contract; the SQL adapter marks (preserving the audit
// trail). The walk is bounded by the chain depth, which the library
// caps at the refresh-token TTL by construction.
//
//nolint:gocognit // BFS over a parent_id graph; the row.Close error handling adds branching but the structure is straight.
func (s *refreshStore) RevokeChain(ctx context.Context, rootID string) error {
	if _, err := s.find(ctx, rootID); err != nil {
		return err
	}
	now := s.parent.clock.Now()
	visited := map[string]struct{}{rootID: {}}
	queue := []string{rootID}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		// Mark current consumed + revoked.
		if _, err := s.runner().ExecContext(ctx,
			s.parent.queries.refreshRevokeChainUpdate, timeToInt64(now), current); err != nil {
			return wrapErr("refreshes.RevokeChain.update", err)
		}
		// Enqueue every direct descendant.
		rows, err := s.runner().QueryContext(ctx,
			s.parent.queries.refreshRevokeChainChildren, current)
		if err != nil {
			return wrapErr("refreshes.RevokeChain.children", err)
		}
		var children []string
		for rows.Next() {
			var id string
			if scanErr := rows.Scan(&id); scanErr != nil {
				_ = rows.Close()
				return wrapErr("refreshes.RevokeChain.scan", scanErr)
			}
			children = append(children, id)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return wrapErr("refreshes.RevokeChain.iter", err)
		}
		if err := rows.Close(); err != nil {
			return wrapErr("refreshes.RevokeChain.close", err)
		}
		for _, child := range children {
			if _, ok := visited[child]; ok {
				continue
			}
			visited[child] = struct{}{}
			queue = append(queue, child)
		}
	}
	return nil
}

// RevokeByGrant marks every refresh token whose grant_id equals
// grantID as consumed + revoked. The library calls it from the
// code-replay cascade. A missing grant is not an error.
func (s *refreshStore) RevokeByGrant(ctx context.Context, grantID string) error {
	now := s.parent.clock.Now()
	if _, err := s.runner().ExecContext(ctx,
		s.parent.queries.refreshRevokeByGrant, timeToInt64(now), grantID); err != nil {
		return wrapErr("refreshes.RevokeByGrant", err)
	}
	return nil
}
