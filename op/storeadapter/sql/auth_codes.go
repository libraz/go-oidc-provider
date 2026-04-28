package oidcsql

import (
	"context"
	databasesql "database/sql"
	"errors"

	"github.com/libraz/go-oidc-provider/op/store"
)

type authCodeStore struct {
	parent *Store
	tx     *databasesql.Tx
}

func newAuthCodeStore(s *Store, tx *databasesql.Tx) *authCodeStore {
	return &authCodeStore{parent: s, tx: tx}
}

func (s *authCodeStore) runner() runner { return pickRunner(s.parent, s.tx) }

func (s *authCodeStore) Save(ctx context.Context, code *store.AuthorizationCode) error {
	_, err := s.runner().ExecContext(ctx, s.parent.queries.authCodeSave,
		code.ID, code.ClientID, code.GrantID, code.Subject, code.RedirectURI,
		encodeStrings(code.Scope), code.CodeChallenge, code.CodeChallengeMethod,
		code.Nonce, code.State, code.DPoPJKT,
		timeToInt64(code.ExpiresAt), timePtrToInt64Ptr(code.ConsumedAt), timeToInt64(code.CreatedAt))
	if err != nil {
		if isDuplicate(err) {
			return store.ErrAlreadyExists
		}
		return wrapErr("authCodes.Save", err)
	}
	return nil
}

func (s *authCodeStore) Find(ctx context.Context, id string) (*store.AuthorizationCode, error) {
	rec, err := s.find(ctx, id)
	if err != nil {
		return nil, err
	}
	if isExpired(rec.ExpiresAt, s.parent.clock) {
		return nil, store.ErrNotFound
	}
	return rec, nil
}

// find is the no-expiry-filter variant used by Consume so the
// post-mortem record (with ConsumedAt populated) can still be
// returned when the caller's transaction has already advanced past
// expiry.
func (s *authCodeStore) find(ctx context.Context, id string) (*store.AuthorizationCode, error) {
	var (
		c        store.AuthorizationCode
		scope    []byte
		expires  int64
		consumed *int64
		created  int64
	)
	err := s.runner().QueryRowContext(ctx, s.parent.queries.authCodeFind, id).Scan(
		&c.ID, &c.ClientID, &c.GrantID, &c.Subject, &c.RedirectURI,
		&scope, &c.CodeChallenge, &c.CodeChallengeMethod,
		&c.Nonce, &c.State, &c.DPoPJKT,
		&expires, &consumed, &created)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, wrapErr("authCodes.Find", err)
	}
	dec, err := decodeStrings(scope)
	if err != nil {
		return nil, err
	}
	c.Scope = dec
	c.ExpiresAt = int64ToTime(expires)
	c.ConsumedAt = int64PtrToTimePtr(consumed)
	c.CreatedAt = int64ToTime(created)
	return &c, nil
}

func (s *authCodeStore) Consume(ctx context.Context, id string) (*store.AuthorizationCode, error) {
	rec, err := s.find(ctx, id)
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
	res, err := s.runner().ExecContext(ctx, s.parent.queries.authCodeConsume, timeToInt64(now), id)
	if err != nil {
		return nil, wrapErr("authCodes.Consume", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, wrapErr("authCodes.Consume.RowsAffected", err)
	}
	if n == 0 {
		// Lost the compare-and-swap to a concurrent Consume.
		return nil, store.ErrAlreadyConsumed
	}
	rec.ConsumedAt = &now
	return rec, nil
}
