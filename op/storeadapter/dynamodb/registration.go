package oidcdynamo

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/libraz/go-oidc-provider/op/store"
)

// iatStore holds RFC 7591 initial access tokens. The token's hashed
// value is the lookup key registration presents; the record id is the
// partition key because the use counter and the delete address it
// directly.
type iatStore struct {
	parent *Store
}

func (s *iatStore) Put(ctx context.Context, t *store.InitialAccessToken) error {
	if t == nil {
		return errors.New("oidcdynamo: nil initial access token")
	}
	entry, err := newItem(t.ID).doc(t)
	if err != nil {
		return err
	}
	entry.expires(t.ExpiresAt)
	entry.set(attrTokenHash, t.HashedValue)
	entry.setN(attrUses, int64(t.Uses))
	entry.setN(attrMaxUses, int64(t.MaxUses))
	placed, err := s.parent.putIfAbsent(ctx, s.parent.names.iats, entry)
	if err != nil {
		return wrapErr("iats.Put", err)
	}
	if !placed {
		return store.ErrAlreadyExists
	}
	return nil
}

// GetByHash resolves a presented token. The index is eventually
// consistent, so the hit is re-read by primary key before it is
// returned: registration must not run against a stale use counter.
//
// The re-read deliberately uses the plain get rather than the
// expiry-filtering getLive the rest of this adapter reaches for. Per
// [store.InitialAccessTokenStore.GetByHash] an expired token is still
// returned and the caller applies the expiry gate, because the
// registration endpoint distinguishes "this token expired" from "no
// such token" in what it tells the client and in the audit event it
// emits. Filtering here collapses the two, and an operator reading the
// trail would see the same signal for a lapsed token as for a forged
// one.
func (s *iatStore) GetByHash(ctx context.Context, hash string) (*store.InitialAccessToken, error) {
	matches, err := s.parent.queryIndex(ctx, s.parent.names.iats, indexByHash, attrTokenHash, hash)
	if err != nil {
		return nil, wrapErr("iats.GetByHash", err)
	}
	for _, match := range matches {
		id := readS(match, attrPK)
		if id == "" {
			continue
		}
		found, err := s.parent.get(ctx, s.parent.names.iats, id)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, wrapErr("iats.GetByHash.reread", err)
		}
		if readS(found, attrTokenHash) != hash {
			continue
		}
		var rec store.InitialAccessToken
		if err := unmarshalDoc(found, &rec); err != nil {
			return nil, err
		}
		rec.Uses = int(readN(found, attrUses))
		return &rec, nil
	}
	return nil, store.ErrNotFound
}

// IncrementUses bumps the counter atomically and returns the new value.
// The increment and the cap check are one conditional update: two
// concurrent registrations against a single-use token must not both
// observe the same pre-increment count, which a read-then-write would
// allow. A cap already reached reports [store.ErrConflict], and a
// MaxUses of zero means single-use.
func (s *iatStore) IncrementUses(ctx context.Context, id string) (int, error) {
	out, err := s.parent.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:        aws.String(s.parent.names.iats),
		Key:              key(id),
		UpdateExpression: aws.String("ADD #uses :one"),
		ConditionExpression: aws.String(
			"attribute_exists(#pk) AND (#uses < #max OR (#max = :zero AND #uses = :zero))",
		),
		ExpressionAttributeNames: map[string]string{
			"#pk":   attrPK,
			"#uses": attrUses,
			"#max":  attrMaxUses,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":one":  avN(1),
			":zero": avN(0),
		},
		ReturnValues: types.ReturnValueUpdatedNew,
	})
	if err != nil {
		if isConditionalCheckFailed(err) {
			if _, getErr := s.parent.get(ctx, s.parent.names.iats, id); errors.Is(getErr, store.ErrNotFound) {
				return 0, store.ErrNotFound
			}
			return 0, store.ErrConflict
		}
		return 0, wrapErr("iats.IncrementUses", err)
	}
	return int(readN(out.Attributes, attrUses)), nil
}

func (s *iatStore) Delete(ctx context.Context, id string) error {
	existed, err := s.parent.deleteKey(ctx, s.parent.names.iats, id)
	if err != nil {
		return wrapErr("iats.Delete", err)
	}
	if !existed {
		return store.ErrNotFound
	}
	return nil
}

// ratStore holds RFC 7592 registration access tokens, one per client.
// The client id is the partition key: every method addresses the record
// by it.
type ratStore struct {
	parent *Store
}

func (s *ratStore) Put(ctx context.Context, t *store.RegistrationAccessToken) error {
	if t == nil {
		return errors.New("oidcdynamo: nil registration access token")
	}
	entry, err := newItem(t.ClientID).doc(t)
	if err != nil {
		return err
	}
	entry.set(attrTokenHash, t.HashedValue)
	if err := s.parent.overwrite(ctx, s.parent.names.rats, entry); err != nil {
		return wrapErr("rats.Put", err)
	}
	return nil
}

func (s *ratStore) GetByClientID(ctx context.Context, clientID string) (*store.RegistrationAccessToken, error) {
	found, err := s.parent.get(ctx, s.parent.names.rats, clientID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, wrapErr("rats.GetByClientID", err)
	}
	var rec store.RegistrationAccessToken
	if err := unmarshalDoc(found, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

func (s *ratStore) Delete(ctx context.Context, clientID string) error {
	existed, err := s.parent.deleteKey(ctx, s.parent.names.rats, clientID)
	if err != nil {
		return wrapErr("rats.Delete", err)
	}
	if !existed {
		return store.ErrNotFound
	}
	return nil
}

var (
	_ store.InitialAccessTokenStore      = (*iatStore)(nil)
	_ store.RegistrationAccessTokenStore = (*ratStore)(nil)
)
