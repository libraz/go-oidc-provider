package oidcdynamo

import (
	"context"
	"errors"

	"github.com/libraz/go-oidc-provider/op/store"
)

// userStore is the read side of the embedder's user directory. The
// library never writes through [store.UserStore]; the write helpers on
// [Store] exist so examples and tests can seed a directory without
// standing up a second one.
type userStore struct {
	parent *Store
}

func (s *userStore) FindBySubject(ctx context.Context, sub string) (*store.User, error) {
	found, err := s.parent.get(ctx, s.parent.names.users, sub)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, wrapErr("users.FindBySubject", err)
	}
	return decodeUser(found)
}

// FindByUsername implements [store.UserPasswordStore]. The username
// index is eventually consistent, so the item it surfaces is re-read by
// primary key before it is returned: a password ceremony must not run
// against a stale directory entry.
func (s *userStore) FindByUsername(ctx context.Context, username string) (*store.User, error) {
	matches, err := s.parent.queryIndex(
		ctx, s.parent.names.users, indexByUsername, attrUsername, username)
	if err != nil {
		return nil, wrapErr("users.FindByUsername", err)
	}
	for _, match := range matches {
		subject := readS(match, attrPK)
		if subject == "" {
			continue
		}
		fresh, err := s.parent.get(ctx, s.parent.names.users, subject)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, wrapErr("users.FindByUsername.reread", err)
		}
		if readS(fresh, attrUsername) != username {
			continue
		}
		return decodeUser(fresh)
	}
	return nil, store.ErrNotFound
}

// ReadPasswordHash implements [store.UserPasswordStore]. The hash is
// kept out of the JSON document and in its own attribute so a code path
// that reads a user for its claims never pulls the credential into
// memory alongside them.
func (s *userStore) ReadPasswordHash(ctx context.Context, subject string) ([]byte, error) {
	found, err := s.parent.get(ctx, s.parent.names.users, subject)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, wrapErr("users.ReadPasswordHash", err)
	}
	hash := readBytes(found, attrCodeHash)
	if len(hash) == 0 {
		return nil, store.ErrNotFound
	}
	return hash, nil
}

func decodeUser(found item) (*store.User, error) {
	var u store.User
	if err := unmarshalDoc(found, &u); err != nil {
		return nil, err
	}
	return &u, nil
}

// PutUser upserts a directory entry without touching any password
// material already stored for the subject.
func (s *Store) PutUser(ctx context.Context, u *store.User) error {
	if u == nil {
		return errors.New("oidcdynamo: nil user")
	}
	existing, err := s.get(ctx, s.names.users, u.Subject)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return wrapErr("users.PutUser.read", err)
	}
	i, err := newItem(u.Subject).doc(u)
	if err != nil {
		return err
	}
	if existing != nil {
		i.set(attrUsername, readS(existing, attrUsername))
		if hash := readBytes(existing, attrCodeHash); len(hash) > 0 {
			i[attrCodeHash] = avB(hash)
		}
	}
	if err := s.put(ctx, s.names.users, i); err != nil {
		return wrapErr("users.PutUser", err)
	}
	return nil
}

// PutUserWithPassword upserts a directory entry together with the
// username it authenticates under and its encoded password hash. The
// library never calls it; examples and tests use it to seed.
func (s *Store) PutUserWithPassword(
	ctx context.Context,
	u *store.User,
	username string,
	passwordHash []byte,
) error {
	if u == nil {
		return errors.New("oidcdynamo: nil user")
	}
	i, err := newItem(u.Subject).doc(u)
	if err != nil {
		return err
	}
	i.set(attrUsername, username)
	i[attrCodeHash] = avB(passwordHash)
	if err := s.put(ctx, s.names.users, i); err != nil {
		return wrapErr("users.PutUserWithPassword", err)
	}
	return nil
}

// UserPasswords returns the password-capable view of the user
// directory, for wiring into op.PrimaryPassword.
func (s *Store) UserPasswords() store.UserPasswordStore { return s.usersImpl }

var (
	_ store.UserStore         = (*userStore)(nil)
	_ store.UserPasswordStore = (*userStore)(nil)
)
