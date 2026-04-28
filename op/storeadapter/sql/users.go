package oidcsql

import (
	"context"
	databasesql "database/sql"
	"errors"

	"github.com/libraz/go-oidc-provider/op/store"
)

type userStore struct {
	parent *Store
	tx     *databasesql.Tx
}

func newUserStore(s *Store, tx *databasesql.Tx) *userStore {
	return &userStore{parent: s, tx: tx}
}

func (s *userStore) runner() runner { return pickRunner(s.parent, s.tx) }

// FindBySubject implements [store.UserStore.FindBySubject].
func (s *userStore) FindBySubject(ctx context.Context, sub string) (*store.User, error) {
	var (
		u         store.User
		claimsRaw []byte
		updated   int64
	)
	err := s.runner().QueryRowContext(ctx, s.parent.queries.userFindBySubject, sub).Scan(
		&u.Subject, &claimsRaw, &updated)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, wrapErr("users.FindBySubject", err)
	}
	claims, err := decodeMap(claimsRaw)
	if err != nil {
		return nil, err
	}
	u.Claims = claims
	u.UpdatedAt = int64ToTime(updated)
	return &u, nil
}

// PutUser inserts or replaces a user record. The library never calls
// this on the [store.UserStore] interface; it is exported on the
// concrete *Store path so embedders that use the SQL adapter for
// their entire users table can seed records without writing to it
// directly. Backends that perform upsert treat PutUser as idempotent.
func (s *Store) PutUser(ctx context.Context, u *store.User) error {
	_, err := s.db.ExecContext(ctx, s.queries.userPut,
		u.Subject, encodeMap(u.Claims), timeToInt64(u.UpdatedAt))
	if err != nil {
		return wrapErr("users.Put", err)
	}
	return nil
}
