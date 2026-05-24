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
	return s.scanUser(ctx, s.parent.queries.userFindBySubject, sub)
}

// FindByUsername implements [store.UserPasswordStore.FindByUsername].
// The username is matched verbatim against the indexed column; embedders
// are responsible for any case-folding or trimming before seeding and
// before submitting credentials at login.
func (s *userStore) FindByUsername(ctx context.Context, username string) (*store.User, error) {
	return s.scanUser(ctx, s.parent.queries.userFindByUsername, username)
}

// ReadPasswordHash implements [store.UserPasswordStore.ReadPasswordHash].
// It returns [store.ErrNotFound] both when the subject is unknown and
// when the row exists but carries no password (passkey-only account),
// so the orchestrator surfaces an enumeration-safe response.
func (s *userStore) ReadPasswordHash(ctx context.Context, subject string) ([]byte, error) {
	var hash []byte
	err := s.runner().QueryRowContext(ctx, s.parent.queries.userReadPasswordHash, subject).Scan(&hash)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, wrapErr("users.ReadPasswordHash", err)
	}
	if len(hash) == 0 {
		return nil, store.ErrNotFound
	}
	out := make([]byte, len(hash))
	copy(out, hash)
	return out, nil
}

func (s *userStore) scanUser(ctx context.Context, query, arg string) (*store.User, error) {
	var (
		u         store.User
		claimsRaw []byte
		updated   int64
	)
	err := s.runner().QueryRowContext(ctx, query, arg).Scan(&u.Subject, &claimsRaw, &updated)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, wrapErr("users.scan", err)
	}
	claims, err := decodeMap(claimsRaw)
	if err != nil {
		return nil, err
	}
	u.Claims = claims
	u.UpdatedAt = int64ToTime(updated)
	return &u, nil
}

// PutUser inserts or replaces a user record without touching the
// password columns. The library never calls this on the
// [store.UserStore] interface; it is exported on the concrete *Store
// path so embedders that use the SQL adapter for their entire users
// table can seed records without writing to it directly. Backends
// that perform upsert treat PutUser as idempotent.
func (s *Store) PutUser(ctx context.Context, u *store.User) error {
	_, err := s.db.ExecContext(ctx, s.queries.userPut,
		u.Subject, encodeMap(u.Claims), timeToInt64(u.UpdatedAt))
	if err != nil {
		return wrapErr("users.Put", err)
	}
	return nil
}

// PutUserWithPassword inserts or replaces a user record together with a
// username→subject mapping and a PHC-encoded password hash. Pass an
// empty username and nil hash to clear the password credential
// (e.g. when a user migrates to passkey-only). Callers are responsible
// for hash encoding (typically [op.HashPassword]). The helper is the
// SQL counterpart of [inmem.Store.PutUserWithPassword] and is exposed
// on the concrete *Store path so embedders seed accounts without
// touching the schema directly.
func (s *Store) PutUserWithPassword(ctx context.Context, u *store.User, username string, passwordHash []byte) error {
	if u == nil {
		return errors.New("oidcsql: PutUserWithPassword: user is nil")
	}
	var (
		usernameArg any = username
		hashArg     any = passwordHash
	)
	if username == "" {
		usernameArg = nil
	}
	if len(passwordHash) == 0 {
		hashArg = nil
	}
	_, err := s.db.ExecContext(ctx, s.queries.userPutWithPassword,
		u.Subject, encodeMap(u.Claims), timeToInt64(u.UpdatedAt), usernameArg, hashArg)
	if err != nil {
		return wrapErr("users.PutWithPassword", err)
	}
	return nil
}

// UserPasswords returns the SQL implementation of
// [store.UserPasswordStore]. The returned value is the same underlying
// handle as [Store.Users] (a *userStore satisfies both interfaces); the
// split mirrors the inmem reference adapter so the LoginFlow compiler
// accepts it directly.
func (s *Store) UserPasswords() store.UserPasswordStore {
	return s.usersImpl
}
