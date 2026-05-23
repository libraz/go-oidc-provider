package oidcsql

import (
	"context"
	databasesql "database/sql"
	"errors"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/patterns"
)

type authCodeStore struct {
	parent *Store
	tx     *databasesql.Tx
}

func newAuthCodeStore(s *Store, tx *databasesql.Tx) *authCodeStore {
	return &authCodeStore{parent: s, tx: tx}
}

func (s *authCodeStore) runner() runner { return pickRunner(s.parent, s.tx) }

// Save honours the hash-on-store contract documented on
// [store.AuthorizationCodeStore.Save]: the raw [store.AuthorizationCode.ID]
// is the bearer secret the client redeems at the token endpoint, so
// the row is keyed on its SHA-256 digest (via [patterns.Digest]) and
// the raw value never reaches the database. A snapshot, replica, or
// backup leak yields one-way digests that cannot be redeemed.
func (s *authCodeStore) Save(ctx context.Context, code *store.AuthorizationCode) error {
	idDigest := patterns.Digest(code.ID)
	_, err := s.runner().ExecContext(ctx, s.parent.queries.authCodeSave,
		idDigest, code.ClientID, code.GrantID, code.Subject, code.RedirectURI,
		encodeStrings(code.Scope), code.Resource, code.CodeChallenge, code.CodeChallengeMethod,
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
//
// The presented id is hashed before the WHERE lookup so the bearer
// secret never appears in the query string or in driver logs; the
// stored id_digest column round-trips back into the returned record's
// ID field swapped with the caller's raw value so call sites observe
// the same opaque token they passed in.
func (s *authCodeStore) find(ctx context.Context, id string) (*store.AuthorizationCode, error) {
	idDigest := patterns.Digest(id)
	var (
		c        store.AuthorizationCode
		stored   string
		scope    []byte
		expires  int64
		consumed *int64
		created  int64
	)
	err := s.runner().QueryRowContext(ctx, s.parent.queries.authCodeFind, idDigest).Scan(
		&stored, &c.ClientID, &c.GrantID, &c.Subject, &c.RedirectURI,
		&scope, &c.Resource, &c.CodeChallenge, &c.CodeChallengeMethod,
		&c.Nonce, &c.State, &c.DPoPJKT,
		&expires, &consumed, &created)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, wrapErr("authCodes.Find", err)
	}
	// Constant-time compare against the stored digest so a future
	// refactor that swaps the equality predicate for a slice scan
	// still fails closed in the presence of a timing oracle.
	if !patterns.ConstantTimeKeyMatch(stored, idDigest) {
		return nil, store.ErrNotFound
	}
	dec, err := decodeStrings(scope)
	if err != nil {
		return nil, err
	}
	c.ID = id
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
		return rec, store.ErrAlreadyConsumed
	}
	now := s.parent.clock.Now()
	idDigest := patterns.Digest(id)
	res, err := s.runner().ExecContext(ctx, s.parent.queries.authCodeConsume, timeToInt64(now), idDigest)
	if err != nil {
		return nil, wrapErr("authCodes.Consume", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, wrapErr("authCodes.Consume.RowsAffected", err)
	}
	if n == 0 {
		// Lost the compare-and-swap to a concurrent Consume.
		if replay, findErr := s.find(ctx, id); findErr == nil && replay.ConsumedAt != nil {
			return replay, store.ErrAlreadyConsumed
		}
		return nil, store.ErrAlreadyConsumed
	}
	rec.ConsumedAt = &now
	return rec, nil
}
