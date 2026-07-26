package oidcdynamo

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/libraz/go-oidc-provider/op/store"
)

// authCodeStore holds authorization codes.
//
// The code is a bearer secret the client redeems at the token
// endpoint, so the item is keyed on its digest and the raw value never
// reaches the table: a leaked export yields one-way digests that cannot
// be redeemed. Redemption is a conditional update on consumed_at, which
// is what gives the RFC 6749 §4.1.2 single-use guarantee — and the
// replay detection built on it — a real backing rather than a
// read-then-write race.
type authCodeStore struct {
	parent *Store
	tx     *txBuffer
}

func (s *authCodeStore) Save(ctx context.Context, code *store.AuthorizationCode) error {
	if code == nil {
		return errors.New("oidcdynamo: nil authorization code")
	}
	entry, err := authCodeItem(code)
	if err != nil {
		return err
	}
	if s.tx != nil {
		return s.tx.putIfAbsent(s.parent.names.authCodes, entry)
	}
	placed, err := s.parent.putIfAbsent(ctx, s.parent.names.authCodes, entry)
	if err != nil {
		return wrapErr("authCodes.Save", err)
	}
	if !placed {
		return store.ErrAlreadyExists
	}
	return nil
}

func (s *authCodeStore) Find(ctx context.Context, id string) (*store.AuthorizationCode, error) {
	rec, err := s.find(ctx, id)
	if err != nil {
		return nil, err
	}
	if s.parent.isExpired(rec.ExpiresAt) {
		return nil, store.ErrNotFound
	}
	return rec, nil
}

// find is the no-expiry-filter read Consume needs so it can still
// return the post-mortem record once a code has been redeemed.
func (s *authCodeStore) find(ctx context.Context, id string) (*store.AuthorizationCode, error) {
	digest := digestKey(id)
	found, err := s.read(ctx, s.parent.names.authCodes, digest)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, wrapErr("authCodes.Find", err)
	}
	var rec store.AuthorizationCode
	if err := unmarshalDoc(found, &rec); err != nil {
		return nil, err
	}
	// The document stores the digest; the caller gets back the opaque
	// value it presented.
	rec.ID = id
	rec.ConsumedAt = optionalTime(found, attrConsumedAt)
	return &rec, nil
}

func (s *authCodeStore) read(ctx context.Context, table, pk string) (item, error) {
	if s.tx != nil {
		return s.tx.get(ctx, table, pk)
	}
	return s.parent.get(ctx, table, pk)
}

func (s *authCodeStore) Consume(ctx context.Context, id string) (*store.AuthorizationCode, error) {
	rec, err := s.find(ctx, id)
	if err != nil {
		return nil, err
	}
	if s.parent.isExpired(rec.ExpiresAt) {
		return nil, store.ErrNotFound
	}
	if rec.ConsumedAt != nil {
		return rec, store.ErrAlreadyConsumed
	}
	now := s.parent.now()
	digest := digestKey(id)

	if s.tx != nil {
		if err := s.tx.stampConsumed(ctx, s.parent.names.authCodes, digest, now); err != nil {
			return nil, err
		}
		rec.ConsumedAt = &now
		return rec, nil
	}

	_, err = s.parent.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:           aws.String(s.parent.names.authCodes),
		Key:                 key(digest),
		UpdateExpression:    aws.String("SET #consumed = :now"),
		ConditionExpression: aws.String("attribute_exists(#pk) AND #consumed = :zero"),
		ExpressionAttributeNames: map[string]string{
			"#pk":       attrPK,
			"#consumed": attrConsumedAt,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":now":  avTime(now),
			":zero": avN(0),
		},
	})
	if err != nil {
		if isConditionalCheckFailed(err) {
			// Lost the race to a concurrent redemption.
			if replay, findErr := s.find(ctx, id); findErr == nil && replay.ConsumedAt != nil {
				return replay, store.ErrAlreadyConsumed
			}
			return nil, store.ErrAlreadyConsumed
		}
		return nil, wrapErr("authCodes.Consume", err)
	}
	rec.ConsumedAt = &now
	return rec, nil
}

func authCodeItem(code *store.AuthorizationCode) (item, error) {
	digest := digestKey(code.ID)
	stored := *code
	stored.ID = digest
	stored.ConsumedAt = nil

	entry, err := newItem(digest).doc(&stored)
	if err != nil {
		return nil, err
	}
	entry.expires(code.ExpiresAt)
	entry.set(attrClientID, code.ClientID)
	entry.set(attrGrantID, code.GrantID)
	entry.setTime(attrConsumedAt, timeOrZero(code.ConsumedAt))
	return entry, nil
}

var _ store.AuthorizationCodeStore = (*authCodeStore)(nil)
