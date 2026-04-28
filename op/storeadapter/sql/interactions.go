package oidcsql

import (
	"context"
	databasesql "database/sql"
	"errors"

	"github.com/libraz/go-oidc-provider/op/store"
)

type interactionStore struct {
	parent *Store
	tx     *databasesql.Tx
}

func newInteractionStore(s *Store, tx *databasesql.Tx) *interactionStore {
	return &interactionStore{parent: s, tx: tx}
}

func (s *interactionStore) runner() runner { return pickRunner(s.parent, s.tx) }

func (s *interactionStore) Save(ctx context.Context, i *store.Interaction) error {
	_, err := s.runner().ExecContext(ctx, s.parent.queries.interactionSave,
		i.ID, i.ClientID, i.Step, i.RawState,
		timeToInt64(i.ExpiresAt), timeToInt64(i.CreatedAt), timeToInt64(i.UpdatedAt))
	if err != nil {
		return wrapErr("interactions.Save", err)
	}
	return nil
}

func (s *interactionStore) Find(ctx context.Context, id string) (*store.Interaction, error) {
	var (
		i        store.Interaction
		expiry   int64
		created  int64
		updated  int64
		rawState []byte
	)
	err := s.runner().QueryRowContext(ctx, s.parent.queries.interactionFind, id).Scan(
		&i.ID, &i.ClientID, &i.Step, &rawState, &expiry, &created, &updated)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, wrapErr("interactions.Find", err)
	}
	i.RawState = append([]byte(nil), rawState...)
	i.ExpiresAt = int64ToTime(expiry)
	i.CreatedAt = int64ToTime(created)
	i.UpdatedAt = int64ToTime(updated)
	if isExpired(i.ExpiresAt, s.parent.clock) {
		return nil, store.ErrNotFound
	}
	return &i, nil
}

func (s *interactionStore) Delete(ctx context.Context, id string) error {
	res, err := s.runner().ExecContext(ctx, s.parent.queries.interactionDelete, id)
	if err != nil {
		return wrapErr("interactions.Delete", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return wrapErr("interactions.Delete.RowsAffected", err)
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}
