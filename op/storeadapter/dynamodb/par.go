package oidcdynamo

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/libraz/go-oidc-provider/op/store"
)

// parStore holds RFC 9126 pushed authorization requests.
//
// The request_uri is a bearer reference, so the item is keyed on its
// digest. Consumption is conditional for the same reason authorization
// codes are: FAPI 2.0 requires that a request_uri cannot be replayed,
// and a read-then-write would let two concurrent authorize requests
// both claim it.
type parStore struct {
	parent *Store
	tx     *txBuffer
}

func (s *parStore) Save(ctx context.Context, par *store.PushedAuthRequest) error {
	if par == nil {
		return errors.New("oidcdynamo: nil pushed authorization request")
	}
	entry, err := parItem(par)
	if err != nil {
		return err
	}
	if s.tx != nil {
		return s.tx.putIfAbsent(s.parent.names.pars, entry)
	}
	placed, err := s.parent.putIfAbsent(ctx, s.parent.names.pars, entry)
	if err != nil {
		return wrapErr("pars.Save", err)
	}
	if !placed {
		return store.ErrAlreadyExists
	}
	return nil
}

func (s *parStore) Find(ctx context.Context, uri string) (*store.PushedAuthRequest, error) {
	rec, err := s.find(ctx, uri)
	if err != nil {
		return nil, err
	}
	if s.parent.isExpired(rec.ExpiresAt) {
		return nil, store.ErrNotFound
	}
	return rec, nil
}

func (s *parStore) find(ctx context.Context, uri string) (*store.PushedAuthRequest, error) {
	found, err := s.read(ctx, digestKey(uri))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, wrapErr("pars.Find", err)
	}
	var rec store.PushedAuthRequest
	if err := unmarshalDoc(found, &rec); err != nil {
		return nil, err
	}
	rec.URI = uri
	rec.ConsumedAt = optionalTime(found, attrConsumedAt)
	return &rec, nil
}

func (s *parStore) read(ctx context.Context, pk string) (item, error) {
	if s.tx != nil {
		return s.tx.get(ctx, s.parent.names.pars, pk)
	}
	return s.parent.get(ctx, s.parent.names.pars, pk)
}

// Consume redeems a request_uri exactly once. Expiry is deliberately
// not re-checked here: it is gated at presentation by Find, so a
// request_uri whose lifetime elapsed during an interactive login still
// redeems at code emission. Consuming twice is the replay that fails.
func (s *parStore) Consume(ctx context.Context, uri string) (*store.PushedAuthRequest, error) {
	rec, err := s.find(ctx, uri)
	if err != nil {
		return nil, err
	}
	if rec.ConsumedAt != nil {
		return rec, store.ErrAlreadyConsumed
	}
	now := s.parent.now()
	digest := digestKey(uri)

	if s.tx != nil {
		if err := s.tx.stampConsumed(ctx, s.parent.names.pars, digest, now); err != nil {
			return nil, err
		}
		rec.ConsumedAt = &now
		return rec, nil
	}

	_, err = s.parent.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:           aws.String(s.parent.names.pars),
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
			if replay, findErr := s.find(ctx, uri); findErr == nil && replay.ConsumedAt != nil {
				return replay, store.ErrAlreadyConsumed
			}
			return nil, store.ErrAlreadyConsumed
		}
		return nil, wrapErr("pars.Consume", err)
	}
	rec.ConsumedAt = &now
	return rec, nil
}

func parItem(par *store.PushedAuthRequest) (item, error) {
	digest := digestKey(par.URI)
	stored := *par
	stored.URI = digest
	stored.ConsumedAt = nil

	entry, err := newItem(digest).doc(&stored)
	if err != nil {
		return nil, err
	}
	entry.expires(par.ExpiresAt)
	entry.set(attrClientID, par.ClientID)
	entry.setTime(attrConsumedAt, timeOrZero(par.ConsumedAt))
	return entry, nil
}

var _ store.PushedAuthRequestStore = (*parStore)(nil)
