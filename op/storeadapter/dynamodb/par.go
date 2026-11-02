package oidcdynamo

import (
	"context"
	"errors"

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
	return s.parent.getVia(ctx, s.tx, s.parent.names.pars, pk)
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
	// A nil record on replay, per [store.PushedAuthRequestStore.Consume]:
	// the record carries the pushed authorization request, and a failed
	// consume must not hand it back.
	if rec.ConsumedAt != nil {
		return nil, store.ErrAlreadyConsumed
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

	_, err = s.parent.api.UpdateItem(ctx, stampConsumedInput(s.parent.names.pars, digest, now))
	if err != nil {
		if isConditionalCheckFailed(err) {
			// The record is withheld on replay, as on entry.
			_, err := rejectedConsume(ctx, func(ctx context.Context) (*store.PushedAuthRequest, error) {
				return s.find(ctx, uri)
			})
			return nil, err
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
