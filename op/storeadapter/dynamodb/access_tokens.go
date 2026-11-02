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
	links := linkItems(s.parent.names.accessTokens, entry, attrGrantID, attrClientID)
	if s.tx != nil {
		if err := s.tx.stageLinks(links); err != nil {
			return err
		}
		return s.tx.putIfAbsent(s.parent.names.accessTokens, entry)
	}
	if err := s.parent.putLinks(ctx, links); err != nil {
		return wrapErr("accessTokens.Register", err)
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
	return s.parent.getVia(ctx, s.tx, s.parent.names.accessTokens, pk)
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
// how many it newly revoked. A token already revoked is not counted.
//
// Inside a transaction the enumeration reads the links and index while each
// retirement is buffered, so the cascade covers the committed set and
// costs one of the transaction's actions per token. The enumeration is
// outside the buffer, so the settled-handle guard is explicit: a grant
// with no registered tokens must not answer a leaked handle with a
// count of zero and no error.
func (s *accessTokenStore) RevokeByGrant(ctx context.Context, grantID string) (int, error) {
	if err := s.tx.assertOpen(); err != nil {
		return 0, err
	}
	keys, err := s.parent.enumerateCommitted(
		ctx, s.parent.names.accessTokens, indexByGrant, attrGrantID, grantID,
	)
	if err != nil {
		return 0, wrapErr("accessTokens.RevokeByGrant", err)
	}
	count := 0
	for _, pk := range keys {
		flipped, err := s.parent.flipRevoked(ctx, s.tx, s.parent.names.accessTokens, pk)
		if err != nil {
			return count, wrapErr("accessTokens.RevokeByGrant", err)
		}
		if flipped {
			count++
		}
	}
	return count, nil
}

// RevokeByClient implements [store.RevokeByClient]. The dynamic
// registration cascade calls it after a client is deleted so the
// registry rows shadowing that client's outstanding JWT access tokens
// are retired at once rather than each waiting out its own expiry.
//
// The settled-handle guard precedes the empty-client short-circuit, so a
// leaked handle reports the closed transaction whatever it was passed.
func (s *accessTokenStore) RevokeByClient(ctx context.Context, clientID string) error {
	if err := s.tx.assertOpen(); err != nil {
		return err
	}
	if clientID == "" {
		return nil
	}
	keys, err := s.parent.enumerateCommitted(
		ctx, s.parent.names.accessTokens, indexByClient, attrClientID, clientID,
	)
	if err != nil {
		return wrapErr("accessTokens.RevokeByClient", err)
	}
	for _, pk := range keys {
		if err := s.retire(ctx, pk); err != nil && !errors.Is(err, store.ErrNotFound) {
			return wrapErr("accessTokens.RevokeByClient", err)
		}
	}
	return nil
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

// flipRevoked marks one item revoked only while it is still live,
// reporting whether this call flipped it. A missing or already revoked
// item reports false, so a count of flips is not inflated by a repeated
// cascade. A non-nil tx buffers the write and re-asserts the guard at
// commit.
func (s *Store) flipRevoked(ctx context.Context, tx *txBuffer, table, pk string) (bool, error) {
	if tx != nil {
		found, err := tx.get(ctx, table, pk)
		if errors.Is(err, store.ErrNotFound) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if readBool(found, attrRevoked) {
			return false, nil
		}
		return true, tx.attachGuarded(ctx, table, pk, attrRevoked, avBool(true), attrRevoked)
	}
	_, err := s.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:           aws.String(table),
		Key:                 key(pk),
		UpdateExpression:    aws.String("SET #revoked = :true"),
		ConditionExpression: aws.String("attribute_exists(#pk) AND #revoked = :false"),
		ExpressionAttributeNames: map[string]string{
			"#pk":      attrPK,
			"#revoked": attrRevoked,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":true":  avBool(true),
			":false": avBool(false),
		},
	})
	if isConditionalCheckFailed(err) {
		return false, nil
	}
	return err == nil, err
}

// gcExpired deletes every item in table whose expiry is strictly
// before cutoff, returning the count. The boundary matters: a record
// expiring exactly at the sweep instant is still inside its lifetime,
// so removing it would retire a token the OP would still have honoured.
//
// It scans, which is acceptable because the operation is a maintenance
// sweep and never a request path. The scan returns only the keys of
// expired items, and each page is deleted before the next is fetched,
// so working memory is one page however large the table is.
//
// The scan only nominates: each delete re-asserts the expiry, so an
// item extended or cleared to never-expire after the page was read —
// a tombstone a concurrent cascade just widened — survives and is not
// counted.
//
// The sweep runs on the table directly even when it is reached through
// a substore handle bound to a transaction: it removes records that are
// already outside their lifetime, which no decision depends on, and
// buffering an unbounded number of deletes would push the transaction
// past its action ceiling for no gain.
func (s *Store) gcExpired(ctx context.Context, table string, cutoff time.Time, op string) (int, error) {
	values := map[string]types.AttributeValue{":never": avN(0), ":cutoff": avTime(cutoff)}
	return s.gcWhere(ctx, table, op, expiredBeforeCondition, values, false)
}

// gcWhere is the sweep behind [Store.gcExpired]: it deletes every item
// of table matching condition, re-asserting it on each delete. The
// condition and values may reference #expires and the placeholders in
// values; consistent selects a strongly consistent scan.
func (s *Store) gcWhere(
	ctx context.Context, table, op, condition string, values map[string]types.AttributeValue, consistent bool,
) (int, error) {
	names := expiryNames(nil)
	var (
		deleted int
		start   map[string]types.AttributeValue
	)
	for {
		page, err := s.api.Scan(ctx, &dynamodb.ScanInput{
			TableName:                 aws.String(table),
			FilterExpression:          aws.String(condition),
			ProjectionExpression:      aws.String("#pk"),
			ExpressionAttributeNames:  names,
			ExpressionAttributeValues: values,
			ExclusiveStartKey:         start,
			ConsistentRead:            aws.Bool(consistent),
		})
		if err != nil {
			return deleted, wrapErr(op, err)
		}
		for _, entry := range page.Items {
			_, err := s.api.DeleteItem(ctx, &dynamodb.DeleteItemInput{
				TableName:                 aws.String(table),
				Key:                       key(readS(entry, attrPK)),
				ConditionExpression:       aws.String("attribute_exists(#pk) AND " + condition),
				ExpressionAttributeNames:  names,
				ExpressionAttributeValues: values,
			})
			if isConditionalCheckFailed(err) {
				continue
			}
			if err != nil {
				return deleted, wrapErr(op, err)
			}
			deleted++
		}
		if len(page.LastEvaluatedKey) == 0 {
			return deleted, nil
		}
		start = page.LastEvaluatedKey
	}
}

// expiredBeforeCondition holds for an item whose expiry is set and
// strictly before :cutoff (see [Store.gcExpired]).
const expiredBeforeCondition = hasExpiryCondition + " AND #expires < :cutoff"

var (
	_ store.AccessTokenRegistry = (*accessTokenStore)(nil)
	_ store.RevokeByClient      = (*accessTokenStore)(nil)
)
