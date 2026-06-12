//go:build example

// par.go — store.PushedAuthRequestStore against vault_pushed_handles.
// Part of the atomic-routing cluster. The request_uri is a bearer
// secret, so it is hashed before storage and looked up by digest.

package main

import (
	"context"
	databasesql "database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

type parStore struct {
	q   querier
	now func() time.Time
}

const (
	parInsert = `
INSERT INTO vault_pushed_handles
  (handle_digest, relying_party, raw_blob, expires_epoch, consumed_epoch, issued_epoch)
VALUES (?, ?, ?, ?, ?, ?)`

	parSelect = `
SELECT handle_digest, relying_party, raw_blob, expires_epoch, consumed_epoch, issued_epoch
FROM vault_pushed_handles WHERE handle_digest = ?`

	parConsume = `
UPDATE vault_pushed_handles SET consumed_epoch = ?
WHERE handle_digest = ? AND consumed_epoch IS NULL`
)

func (s *parStore) Save(ctx context.Context, par *store.PushedAuthRequest) error {
	_, err := s.q.ExecContext(ctx, parInsert,
		digest(par.URI), par.ClientID, par.RawParams,
		epochOf(par.ExpiresAt), epochPtr(par.ConsumedAt), epochOf(par.CreatedAt))
	if err != nil {
		if isDuplicate(err) {
			return store.ErrAlreadyExists
		}
		return fmt.Errorf("par.Save: %w", err)
	}
	return nil
}

func (s *parStore) Find(ctx context.Context, uri string) (*store.PushedAuthRequest, error) {
	rec, err := s.find(ctx, uri)
	if err != nil {
		return nil, err
	}
	if expiredStrict(rec.ExpiresAt, s.now()) {
		return nil, store.ErrNotFound
	}
	return rec, nil
}

func (s *parStore) find(ctx context.Context, uri string) (*store.PushedAuthRequest, error) {
	d := digest(uri)
	var (
		rec      store.PushedAuthRequest
		stored   string
		raw      []byte
		expires  int64
		consumed *int64
		created  int64
	)
	err := s.q.QueryRowContext(ctx, parSelect, d).Scan(
		&stored, &rec.ClientID, &raw, &expires, &consumed, &created)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("par.find: %w", err)
	}
	if !constantTimeMatch(stored, d) {
		return nil, store.ErrNotFound
	}
	rec.URI = uri
	rec.RawParams = append([]byte(nil), raw...)
	rec.ExpiresAt = timeOf(expires)
	rec.ConsumedAt = timePtr(consumed)
	rec.CreatedAt = timeOf(created)
	return &rec, nil
}

func (s *parStore) Consume(ctx context.Context, uri string) (*store.PushedAuthRequest, error) {
	rec, err := s.find(ctx, uri)
	if err != nil {
		return nil, err
	}
	if expiredStrict(rec.ExpiresAt, s.now()) {
		return nil, store.ErrNotFound
	}
	if rec.ConsumedAt != nil {
		return nil, store.ErrAlreadyConsumed
	}
	now := s.now()
	res, err := s.q.ExecContext(ctx, parConsume, now.Unix(), digest(uri))
	if err != nil {
		return nil, fmt.Errorf("par.Consume: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("par.Consume.RowsAffected: %w", err)
	}
	if n == 0 {
		return nil, store.ErrAlreadyConsumed
	}
	rec.ConsumedAt = &now
	return rec, nil
}
