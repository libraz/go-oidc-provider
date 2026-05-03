package oidcsql

import (
	"context"
	databasesql "database/sql"
	"errors"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/patterns"
)

type parStore struct {
	parent *Store
	tx     *databasesql.Tx
}

func newParStore(s *Store, tx *databasesql.Tx) *parStore {
	return &parStore{parent: s, tx: tx}
}

func (s *parStore) runner() runner { return pickRunner(s.parent, s.tx) }

// Save honours the hash-on-store contract documented on
// [store.PushedAuthRequestStore.Save]: the raw [store.PushedAuthRequest.URI]
// is the bearer secret the client presents at the authorization
// endpoint, so the row is keyed on its SHA-256 digest (via
// [patterns.Digest]) and the raw value never reaches the database.
func (s *parStore) Save(ctx context.Context, par *store.PushedAuthRequest) error {
	uriDigest := patterns.Digest(par.URI)
	_, err := s.runner().ExecContext(ctx, s.parent.queries.parSave,
		uriDigest, par.ClientID, par.RawParams,
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

// find resolves a row by hashing the presented uri and comparing in
// constant time against the stored digest. The returned record's URI
// is restored to the caller's raw value so call sites observe the
// same opaque bearer URI they passed in; nothing outside this file
// ever needs the raw value back, but the round-trip mirrors the
// inmem reference and keeps the contract tests symmetrical.
func (s *parStore) find(ctx context.Context, uri string) (*store.PushedAuthRequest, error) {
	uriDigest := patterns.Digest(uri)
	var (
		rec      store.PushedAuthRequest
		stored   string
		raw      []byte
		expires  int64
		consumed *int64
		created  int64
	)
	err := s.runner().QueryRowContext(ctx, s.parent.queries.parFind, uriDigest).Scan(
		&stored, &rec.ClientID, &raw, &expires, &consumed, &created)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if !patterns.ConstantTimeKeyMatch(stored, uriDigest) {
		return nil, store.ErrNotFound
	}
	rec.URI = uri
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
	uriDigest := patterns.Digest(uri)
	res, err := s.runner().ExecContext(ctx, s.parent.queries.parConsume, timeToInt64(now), uriDigest)
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
