package oidcsql

import (
	"context"
	databasesql "database/sql"
	"errors"

	"github.com/libraz/go-oidc-provider/op/store"
)

type iatStore struct {
	parent *Store
	tx     *databasesql.Tx
}

func newIATStore(s *Store, tx *databasesql.Tx) *iatStore {
	return &iatStore{parent: s, tx: tx}
}

func (s *iatStore) runner() runner { return pickRunner(s.parent, s.tx) }

func (s *iatStore) Put(ctx context.Context, t *store.InitialAccessToken) error {
	_, err := s.runner().ExecContext(ctx, s.parent.queries.iatPut,
		t.ID, t.HashedValue, t.MaxUses, t.Uses,
		encodeStrings(t.AllowedScopes), t.Tag,
		timeToInt64(t.ExpiresAt), timeToInt64(t.CreatedAt))
	if err != nil {
		if isDuplicate(err) {
			return store.ErrAlreadyExists
		}
		return wrapErr("iats.Put", err)
	}
	return nil
}

func (s *iatStore) GetByHash(ctx context.Context, hash string) (*store.InitialAccessToken, error) {
	var (
		t       store.InitialAccessToken
		scopes  []byte
		expires int64
		created int64
	)
	err := s.runner().QueryRowContext(ctx, s.parent.queries.iatGetByHash, hash).Scan(
		&t.ID, &t.HashedValue, &t.MaxUses, &t.Uses,
		&scopes, &t.Tag, &expires, &created)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, wrapErr("iats.GetByHash", err)
	}
	dec, err := decodeStrings(scopes)
	if err != nil {
		return nil, err
	}
	t.AllowedScopes = dec
	t.ExpiresAt = int64ToTime(expires)
	t.CreatedAt = int64ToTime(created)
	return &t, nil
}

func (s *iatStore) IncrementUses(ctx context.Context, id string) (int, error) {
	// Atomic compare-and-swap loop: read current uses + max_uses,
	// compute the new value, conditional update on (id, uses=current).
	// On failure ([RowsAffected] == 0) re-read and retry; in the
	// hot path the loop terminates after one iteration. The loop
	// caps at a small number of attempts to surface starvation rather
	// than busy-looping forever.
	const maxAttempts = 8
	for range maxAttempts {
		var maxUses, uses int
		err := s.runner().QueryRowContext(ctx, s.parent.queries.iatIncrementUsesRead, id).Scan(&maxUses, &uses)
		if errors.Is(err, databasesql.ErrNoRows) {
			return 0, store.ErrNotFound
		}
		if err != nil {
			return 0, wrapErr("iats.IncrementUses.read", err)
		}
		ceiling := maxUses
		if ceiling == 0 {
			ceiling = 1
		}
		if uses >= ceiling {
			return uses, store.ErrConflict
		}
		nextUses := uses + 1
		res, err := s.runner().ExecContext(ctx, s.parent.queries.iatIncrementUsesUpdate, nextUses, id, uses)
		if err != nil {
			return 0, wrapErr("iats.IncrementUses.update", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return 0, wrapErr("iats.IncrementUses.RowsAffected", err)
		}
		if n == 1 {
			return nextUses, nil
		}
	}
	return 0, store.ErrConflict
}

func (s *iatStore) Delete(ctx context.Context, id string) error {
	res, err := s.runner().ExecContext(ctx, s.parent.queries.iatDelete, id)
	if err != nil {
		return wrapErr("iats.Delete", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return wrapErr("iats.Delete.RowsAffected", err)
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}
