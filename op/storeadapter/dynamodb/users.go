package oidcdynamo

import (
	"context"
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/libraz/go-oidc-provider/op/store"
)

// userStore is the read side of the embedder's user directory. The
// library never writes through [store.UserStore]; the write helpers on
// [Store] exist so examples and tests can seed a directory without
// standing up a second one.
type userStore struct {
	parent *Store
}

// usernamePrefix namespaces the username reservations inside the user
// table. A reservation points at the subject that holds the username and
// is what makes the username unique: DynamoDB has no unique index, so
// without it two directory entries could log in under one identifier and
// the password ceremony would resolve to whichever the index surfaced.
//
// Subjects the OP issues are random Base64URL and never carry the
// prefix; the seed helpers reject one that does rather than let an entry
// overwrite a reservation.
const usernamePrefix = "username#"

func usernameKey(username string) string { return usernamePrefix + username }

// errReservedSubject reports a subject that would land on the username
// keyspace.
var errReservedSubject = errors.New("oidcdynamo: subject must not start with " + usernamePrefix)

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

// FindByUsername implements [store.UserPasswordStore].
//
// The reservation is consulted first: it is strongly consistent and
// single-valued, so a directory seeded through [Store.PutUserWithPassword]
// resolves to exactly one subject. A directory the embedder populated
// with its own tooling has no reservations, and for those the username
// index is walked instead — its answer is only as unique as the writer
// made it, which is why the index result is re-read by primary key and
// checked against the username before a password ceremony runs on it.
func (s *userStore) FindByUsername(ctx context.Context, username string) (*store.User, error) {
	if username == "" {
		return nil, store.ErrNotFound
	}
	u, err := s.findReservedUsername(ctx, username)
	if err == nil {
		return u, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	return s.findIndexedUsername(ctx, username)
}

func (s *userStore) findReservedUsername(ctx context.Context, username string) (*store.User, error) {
	reserved, err := s.parent.get(ctx, s.parent.names.users, usernameKey(username))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, wrapErr("users.FindByUsername", err)
	}
	subject := readS(reserved, attrSubject)
	if subject == "" {
		return nil, store.ErrNotFound
	}
	return s.findVerifiedUsername(ctx, subject, username)
}

func (s *userStore) findIndexedUsername(ctx context.Context, username string) (*store.User, error) {
	matches, err := s.parent.queryIndex(
		ctx, s.parent.names.users, indexByUsername, attrUsername, username,
	)
	if err != nil {
		return nil, wrapErr("users.FindByUsername", err)
	}
	for _, match := range matches {
		subject := readS(match, attrPK)
		if subject == "" {
			continue
		}
		u, err := s.findVerifiedUsername(ctx, subject, username)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return u, nil
	}
	return nil, store.ErrNotFound
}

// findVerifiedUsername reads the directory entry and returns it only
// while it still carries the username the lookup started from, so a
// pointer left behind by a renamed entry cannot resolve to it.
func (s *userStore) findVerifiedUsername(ctx context.Context, subject, username string) (*store.User, error) {
	found, err := s.parent.get(ctx, s.parent.names.users, subject)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, wrapErr("users.FindByUsername.reread", err)
	}
	if readS(found, attrUsername) != username {
		return nil, store.ErrNotFound
	}
	return decodeUser(found)
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
	if strings.HasPrefix(u.Subject, usernamePrefix) {
		return errReservedSubject
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
	if err := s.overwrite(ctx, s.names.users, i); err != nil {
		return wrapErr("users.PutUser", err)
	}
	return nil
}

// PutUserWithPassword upserts a directory entry together with the
// username it authenticates under and its encoded password hash, and
// claims the username for the subject. It reports [store.ErrAlreadyExists]
// when another subject already holds the username. The library never
// calls it; examples and tests use it to seed.
func (s *Store) PutUserWithPassword(
	ctx context.Context,
	u *store.User,
	username string,
	passwordHash []byte,
) error {
	if u == nil {
		return errors.New("oidcdynamo: nil user")
	}
	if strings.HasPrefix(u.Subject, usernamePrefix) {
		return errReservedSubject
	}
	i, err := newItem(u.Subject).doc(u)
	if err != nil {
		return err
	}
	i.set(attrUsername, username)
	i[attrCodeHash] = avB(passwordHash)
	if username == "" {
		if err := s.overwrite(ctx, s.names.users, i); err != nil {
			return wrapErr("users.PutUserWithPassword", err)
		}
		return nil
	}
	return s.putUserClaimingUsername(ctx, i, u.Subject, username)
}

// putUserClaimingUsername writes the entry and its username reservation
// together, releasing the reservation the subject held under a previous
// username in the same transaction.
//
// The claim is what enforces uniqueness, so it is a guarded write rather
// than a lookup followed by an insert: two enrolments of one username
// would otherwise both find it free, and the login that followed would
// resolve to whichever entry the index happened to return.
func (s *Store) putUserClaimingUsername(ctx context.Context, entry item, subject, username string) error {
	existing, err := s.get(ctx, s.names.users, subject)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return wrapErr("users.PutUserWithPassword.read", err)
	}

	owner := map[string]string{"#pk": attrPK, "#subject": attrSubject}
	ownerValue := map[string]types.AttributeValue{":subject": avS(subject)}
	// "Unclaimed, or already mine" — a re-seed of the same subject is
	// idempotent while another subject's claim aborts the write.
	const ownedByMe = "attribute_not_exists(#pk) OR #subject = :subject"

	actions := []types.TransactWriteItem{
		{Put: &types.Put{TableName: aws.String(s.names.users), Item: entry}},
		{Put: &types.Put{
			TableName:                 aws.String(s.names.users),
			Item:                      newItem(usernameKey(username)).set(attrSubject, subject),
			ConditionExpression:       aws.String(ownedByMe),
			ExpressionAttributeNames:  owner,
			ExpressionAttributeValues: ownerValue,
		}},
	}
	if prior := readS(existing, attrUsername); prior != "" && prior != username {
		actions = append(actions, types.TransactWriteItem{Delete: &types.Delete{
			TableName:                 aws.String(s.names.users),
			Key:                       key(usernameKey(prior)),
			ConditionExpression:       aws.String(ownedByMe),
			ExpressionAttributeNames:  owner,
			ExpressionAttributeValues: ownerValue,
		}})
	}

	if _, err := s.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: actions,
	}); err != nil {
		if isTransactionCanceledByCondition(err) {
			return store.ErrAlreadyExists
		}
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
