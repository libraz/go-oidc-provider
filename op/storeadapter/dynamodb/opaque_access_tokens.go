package oidcdynamo

import (
	"context"
	"errors"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// opaqueAccessTokenStore backs the opaque access-token format. The
// token is a bearer secret, so items are keyed on its digest — the same
// posture authorization codes and refresh tokens take.
type opaqueAccessTokenStore struct {
	parent *Store
	tx     *txBuffer
}

func (s *opaqueAccessTokenStore) Save(ctx context.Context, tok *store.OpaqueAccessToken) error {
	if tok == nil {
		return errors.New("oidcdynamo: nil opaque access token")
	}
	entry, err := opaqueItem(tok)
	if err != nil {
		return err
	}
	if s.tx != nil {
		return s.tx.putIfAbsent(s.parent.names.opaqueAccessTokens, entry)
	}
	placed, err := s.parent.putIfAbsent(ctx, s.parent.names.opaqueAccessTokens, entry)
	if err != nil {
		return wrapErr("opaqueAccessTokens.Save", err)
	}
	if !placed {
		return store.ErrAlreadyExists
	}
	return nil
}

func (s *opaqueAccessTokenStore) Find(ctx context.Context, id string) (*store.OpaqueAccessToken, error) {
	found, err := s.read(ctx, digestKey(id))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, wrapErr("opaqueAccessTokens.Find", err)
	}
	var rec store.OpaqueAccessToken
	if err := unmarshalDoc(found, &rec); err != nil {
		return nil, err
	}
	rec.ID = id
	rec.Revoked = readBool(found, attrRevoked)
	if s.parent.isExpired(rec.ExpiresAt) {
		return nil, store.ErrNotFound
	}
	return &rec, nil
}

func (s *opaqueAccessTokenStore) read(ctx context.Context, pk string) (item, error) {
	if s.tx != nil {
		return s.tx.get(ctx, s.parent.names.opaqueAccessTokens, pk)
	}
	return s.parent.get(ctx, s.parent.names.opaqueAccessTokens, pk)
}

// RevokeByID marks one token revoked. Revoking a token that is not
// there is not an error: /revocation is defined to answer 200 for an
// unknown token, so the substore has nothing to report.
func (s *opaqueAccessTokenStore) RevokeByID(ctx context.Context, id string) error {
	err := s.retire(ctx, digestKey(id))
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return wrapErr("opaqueAccessTokens.RevokeByID", err)
	}
	return nil
}

// retire marks one stored token revoked, reporting [store.ErrNotFound]
// when there is no row to mark. A handle obtained from a transaction
// buffers the write, so a cascade the caller rolls back does not leave
// the tokens retired.
func (s *opaqueAccessTokenStore) retire(ctx context.Context, pk string) error {
	if s.tx != nil {
		return s.tx.attach(ctx, s.parent.names.opaqueAccessTokens, pk, attrRevoked, avBool(true))
	}
	return s.parent.setRevoked(ctx, s.parent.names.opaqueAccessTokens, pk)
}

// RevokeByGrant retires every token of a grant and reports how many it
// touched. Inside a transaction the enumeration reads the index while
// each retirement is buffered, so the cascade covers the committed set
// and costs one of the transaction's actions per token.
func (s *opaqueAccessTokenStore) RevokeByGrant(ctx context.Context, grantID string) (int, error) {
	matches, err := s.parent.queryIndex(
		ctx, s.parent.names.opaqueAccessTokens, indexByGrant, attrGrantID, grantID,
	)
	if err != nil {
		return 0, wrapErr("opaqueAccessTokens.RevokeByGrant", err)
	}
	count := 0
	for _, match := range matches {
		pk := readS(match, attrPK)
		if pk == "" {
			continue
		}
		if err := s.retire(ctx, pk); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			return count, wrapErr("opaqueAccessTokens.RevokeByGrant", err)
		}
		count++
	}
	return count, nil
}

// RevokeByClient implements [store.RevokeByClient] for the dynamic
// registration cascade.
func (s *opaqueAccessTokenStore) RevokeByClient(ctx context.Context, clientID string) error {
	if clientID == "" {
		return nil
	}
	matches, err := s.parent.queryIndex(
		ctx, s.parent.names.opaqueAccessTokens, indexByClient, attrClientID, clientID,
	)
	if err != nil {
		return wrapErr("opaqueAccessTokens.RevokeByClient", err)
	}
	for _, match := range matches {
		pk := readS(match, attrPK)
		if pk == "" {
			continue
		}
		if err := s.retire(ctx, pk); err != nil && !errors.Is(err, store.ErrNotFound) {
			return wrapErr("opaqueAccessTokens.RevokeByClient", err)
		}
	}
	return nil
}

func (s *opaqueAccessTokenStore) GC(ctx context.Context, cutoff time.Time) (int, error) {
	return s.parent.gcExpired(ctx, s.parent.names.opaqueAccessTokens, cutoff, "opaqueAccessTokens.GC")
}

func opaqueItem(tok *store.OpaqueAccessToken) (item, error) {
	digest := digestKey(tok.ID)
	stored := *tok
	stored.ID = digest
	stored.Revoked = false

	entry, err := newItem(digest).doc(&stored)
	if err != nil {
		return nil, err
	}
	entry.expires(tok.ExpiresAt)
	entry.set(attrGrantID, tok.GrantID)
	entry.set(attrClientID, tok.ClientID)
	entry.setBool(attrRevoked, tok.Revoked)
	return entry, nil
}

var (
	_ store.OpaqueAccessTokenStore = (*opaqueAccessTokenStore)(nil)
	_ store.RevokeByClient         = (*opaqueAccessTokenStore)(nil)
)
