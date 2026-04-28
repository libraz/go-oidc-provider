package oidcsql

import (
	"context"
	databasesql "database/sql"
	"errors"

	"github.com/libraz/go-oidc-provider/op/store"
)

type ratStore struct {
	parent *Store
	tx     *databasesql.Tx
}

func newRATStore(s *Store, tx *databasesql.Tx) *ratStore {
	return &ratStore{parent: s, tx: tx}
}

func (s *ratStore) runner() runner { return pickRunner(s.parent, s.tx) }

func (s *ratStore) Put(ctx context.Context, t *store.RegistrationAccessToken) error {
	_, err := s.runner().ExecContext(ctx, s.parent.queries.ratPut,
		t.ClientID, t.HashedValue, timeToInt64(t.CreatedAt))
	if err != nil {
		return wrapErr("rats.Put", err)
	}
	return nil
}

func (s *ratStore) GetByClientID(ctx context.Context, clientID string) (*store.RegistrationAccessToken, error) {
	var (
		t       store.RegistrationAccessToken
		created int64
	)
	err := s.runner().QueryRowContext(ctx, s.parent.queries.ratGetByClientID, clientID).Scan(
		&t.ClientID, &t.HashedValue, &created)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, wrapErr("rats.GetByClientID", err)
	}
	t.CreatedAt = int64ToTime(created)
	return &t, nil
}

func (s *ratStore) Delete(ctx context.Context, clientID string) error {
	res, err := s.runner().ExecContext(ctx, s.parent.queries.ratDelete, clientID)
	if err != nil {
		return wrapErr("rats.Delete", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return wrapErr("rats.Delete.RowsAffected", err)
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}
