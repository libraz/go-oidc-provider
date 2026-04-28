package oidcsql

import (
	"context"
	databasesql "database/sql"
	"errors"

	"github.com/libraz/go-oidc-provider/op/store"
)

type parStore struct {
	parent *Store
	tx     *databasesql.Tx
}

func newParStore(s *Store, tx *databasesql.Tx) *parStore {
	return &parStore{parent: s, tx: tx}
}

func (s *parStore) runner() runner { return pickRunner(s.parent, s.tx) }

func (s *parStore) Save(ctx context.Context, par *store.PushedAuthRequest) error {
	_, err := s.runner().ExecContext(ctx, s.parent.queries.parSave,
		par.URI, par.ClientID, par.RawParams,
		timeToInt64(par.ExpiresAt), timePtrToInt64Ptr(par.ConsumedAt), timeToInt64(par.CreatedAt))
	if err != nil {
		if isDuplicate(err) {
			return store.ErrAlreadyExists
		}
		return wrapErr("par.Save", err)
	}
	return nil
}

func (s *parStore) Find(ctx context.Context, uri string) (*store.PushedAuthRequest, error) {
	rec, err := s.find(ctx, uri)
	if err != nil {
		return nil, err
	}
	if isExpired(rec.ExpiresAt, s.parent.clock) {
		return nil, store.ErrNotFound
	}
	return rec, nil
}

func (s *parStore) find(ctx context.Context, uri string) (*store.PushedAuthRequest, error) {
	var (
		rec      store.PushedAuthRequest
		raw      []byte
		expires  int64
		consumed *int64
		created  int64
	)
	err := s.runner().QueryRowContext(ctx, s.parent.queries.parFind, uri).Scan(
		&rec.URI, &rec.ClientID, &raw, &expires, &consumed, &created)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	rec.RawParams = append([]byte(nil), raw...)
	rec.ExpiresAt = int64ToTime(expires)
	rec.ConsumedAt = int64PtrToTimePtr(consumed)
	rec.CreatedAt = int64ToTime(created)
	return &rec, nil
}

func (s *parStore) Consume(ctx context.Context, uri string) (*store.PushedAuthRequest, error) {
	rec, err := s.find(ctx, uri)
	if err != nil {
		return nil, err
	}
	if isExpired(rec.ExpiresAt, s.parent.clock) {
		return nil, store.ErrNotFound
	}
	if rec.ConsumedAt != nil {
		return nil, store.ErrAlreadyConsumed
	}
	now := s.parent.clock.Now()
	res, err := s.runner().ExecContext(ctx, s.parent.queries.parConsume, timeToInt64(now), uri)
	if err != nil {
		return nil, wrapErr("par.Consume", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, wrapErr("par.Consume.RowsAffected", err)
	}
	if n == 0 {
		return nil, store.ErrAlreadyConsumed
	}
	rec.ConsumedAt = &now
	return rec, nil
}
