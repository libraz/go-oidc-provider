package oidcdynamo

import (
	"context"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/libraz/go-oidc-provider/op/store"
)

// accessTokenStore is the JTI registry every issuance path writes to.
// Userinfo, introspection, and revocation consult it, and the RFC 6749
// §4.1.2 code-replay cascade revokes through it by grant.
type accessTokenStore struct {
	parent *Store
	tx     *txBuffer
}

// Register persists rec. The write is conditional: a colliding jti is
// reachable only through an implementation bug, and silently
// overwriting the row a live token depends on would turn that bug into
// a revocation that never takes effect.
func (s *accessTokenStore) Register(ctx context.Context, rec store.AccessTokenRecord) error {
	entry, err := accessTokenItem(&rec)
	if err != nil {
		return err
	}
	if s.tx != nil {
		return s.tx.putIfAbsent(s.parent.names.accessTokens, entry)
	}
	placed, err := s.parent.putIfAbsent(ctx, s.parent.names.accessTokens, entry)
	if err != nil {
		return wrapErr("accessTokens.Register", err)
	}
	if !placed {
		return store.ErrAlreadyExists
	}
	return nil
}

// Find returns the registered record for jti. A jti that was never
// registered yields (nil, nil) rather than [store.ErrNotFound]: the
// registry is consulted on every introspection and userinfo call, and
// the caller distinguishes "absent" from "lookup failed" by the error
// being nil.
func (s *accessTokenStore) Find(ctx context.Context, jti string) (*store.AccessTokenRecord, error) {
	found, err := s.read(ctx, jti)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil //nolint:nilnil // registry contract: an unregistered jti is (nil, nil).
		}
		return nil, wrapErr("accessTokens.Find", err)
	}
	var rec store.AccessTokenRecord
	if err := unmarshalDoc(found, &rec); err != nil {
		return nil, err
	}
	rec.Revoked = readBool(found, attrRevoked)
	return &rec, nil
}

func (s *accessTokenStore) read(ctx context.Context, pk string) (item, error) {
	if s.tx != nil {
		return s.tx.get(ctx, s.parent.names.accessTokens, pk)
	}
	return s.parent.get(ctx, s.parent.names.accessTokens, pk)
}

// RevokeByJTI retires one token. It is idempotent and silent about a
// record that is not there: RFC 7009 §2.2 has the revocation endpoint
// answer 200 for an unknown token either way, so the substore has
// nothing to report.
func (s *accessTokenStore) RevokeByJTI(ctx context.Context, jti string) error {
	err := s.retire(ctx, jti)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return wrapErr("accessTokens.RevokeByJTI", err)
	}
	return nil
}

// retire marks one registered token revoked, reporting
// [store.ErrNotFound] when there is no row to mark.
//
// A handle obtained from a transaction buffers the write like every
// other write it makes: the registry carries the half of a revocation
// cascade that retires what the client already holds, and a write that
// went straight to the table could not be taken back by a Rollback.
func (s *accessTokenStore) retire(ctx context.Context, pk string) error {
	if s.tx != nil {
		return s.tx.attach(ctx, s.parent.names.accessTokens, pk, attrRevoked, avBool(true))
	}
	return s.parent.setRevoked(ctx, s.parent.names.accessTokens, pk)
}

// RevokeByGrant marks every access token of a grant revoked and reports
// how many it touched. A token already revoked is still counted: the
// caller uses the number for audit, not for control flow.
//
// Inside a transaction the enumeration reads the index while each
// retirement is buffered, so the cascade covers the committed set and
// costs one of the transaction's actions per token.
func (s *accessTokenStore) RevokeByGrant(ctx context.Context, grantID string) (int, error) {
	matches, err := s.parent.queryIndex(
		ctx, s.parent.names.accessTokens, indexByGrant, attrGrantID, grantID,
	)
	if err != nil {
		return 0, wrapErr("accessTokens.RevokeByGrant", err)
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
			return count, wrapErr("accessTokens.RevokeByGrant", err)
		}
		count++
	}
	return count, nil
}

// GC deletes records that expired before cutoff. DynamoDB's own TTL
// reclaims them eventually; this exists so a deployment can force the
// sweep and so the contract's GC semantics hold on every backend.
func (s *accessTokenStore) GC(ctx context.Context, cutoff time.Time) (int, error) {
	return s.parent.gcExpired(ctx, s.parent.names.accessTokens, cutoff, "accessTokens.GC")
}

func accessTokenItem(rec *store.AccessTokenRecord) (item, error) {
	entry, err := newItem(rec.JTI).doc(rec)
	if err != nil {
		return nil, err
	}
	entry.expires(rec.ExpiresAt)
	entry.set(attrGrantID, rec.GrantID)
	entry.set(attrClientID, rec.ClientID)
	entry.setBool(attrRevoked, rec.Revoked)
	return entry, nil
}

// setRevoked flips the revoked flag on an existing item, reporting
// [store.ErrNotFound] when there is nothing to revoke.
func (s *Store) setRevoked(ctx context.Context, table, pk string) error {
	_, err := s.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:           aws.String(table),
		Key:                 key(pk),
		UpdateExpression:    aws.String("SET #revoked = :true"),
		ConditionExpression: aws.String("attribute_exists(#pk)"),
		ExpressionAttributeNames: map[string]string{
			"#pk":      attrPK,
			"#revoked": attrRevoked,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":true": avBool(true),
		},
	})
	if err != nil {
		if isConditionalCheckFailed(err) {
			return store.ErrNotFound
		}
		return err
	}
	return nil
}

// gcExpired deletes every item in table whose expiry is strictly
// before cutoff, returning the count. The boundary matters: a record
// expiring exactly at the sweep instant is still inside its lifetime,
// so removing it would retire a token the OP would still have honoured.
//
// It scans, which is acceptable because the operation is a maintenance
// sweep and never a request path, and a TTL-carrying table is expected
// to be mostly reclaimed by DynamoDB already.
//
// The sweep runs on the table directly even when it is reached through
// a substore handle bound to a transaction: it removes records that are
// already outside their lifetime, which no decision depends on, and
// buffering an unbounded number of deletes would push the transaction
// past its action ceiling for no gain.
func (s *Store) gcExpired(ctx context.Context, table string, cutoff time.Time, op string) (int, error) {
	found, err := s.scanAll(ctx, table, 0)
	if err != nil {
		return 0, wrapErr(op, err)
	}
	deleted := 0
	for _, entry := range found {
		expiresAt := readTime(entry, attrExpiresAt)
		if expiresAt.IsZero() || !expiresAt.Before(cutoff) {
			continue
		}
		pk := readS(entry, attrPK)
		if pk == "" {
			continue
		}
		existed, err := s.deleteKey(ctx, table, pk)
		if err != nil {
			return deleted, wrapErr(op, err)
		}
		if existed {
			deleted++
		}
	}
	return deleted, nil
}

var _ store.AccessTokenRegistry = (*accessTokenStore)(nil)
