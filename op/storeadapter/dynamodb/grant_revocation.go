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

// grantRevocationStore backs the grant-tombstone strategy for revoking
// JWT access tokens: a cascade writes one row per revoked grant rather
// than one per token, and /revocation by jti writes a single denylist
// row.
//
// Both kinds share a table under distinct key prefixes. IsRevoked reads
// at most one of each, so co-locating them halves the provisioning
// surface without costing a query.
type grantRevocationStore struct {
	parent *Store
	tx     *txBuffer
}

const (
	tombstonePrefix = "grant#"
	denylistPrefix  = "jti#"
)

// RevokeGrant writes a tombstone covering every token issued under the
// grant before RevokedAt. Both of the row's horizons only ever widen:
// the record has to outlive the longest-lived token it invalidates, and
// a later revocation instant is the point of a second cascade, because a
// token minted after the previous one must fall inside the new window.
//
// Widening is expressed as two guarded updates rather than as a read
// followed by a replacement. Cascades against one grant arrive in
// parallel — a logout and a replay detection can run at the same
// instant — and a read-modify-write would let the one that read first
// write last, narrowing the window it found and quietly restoring every
// access token the other had just killed.
func (s *grantRevocationStore) RevokeGrant(ctx context.Context, t store.GrantTombstone) error {
	pk := tombstonePrefix + t.GrantID
	if s.tx != nil {
		return s.revokeGrantStaged(ctx, pk, t)
	}
	if err := s.widenRevokedAt(ctx, pk, t); err != nil {
		return err
	}
	return s.widenLifetime(ctx, pk, t.ExpiresAt)
}

// widenRevokedAt advances the revocation instant, and writes the row
// when the grant has no tombstone yet. The document rides along with it
// so the reason recorded is the one of the cascade that set the instant;
// the projected attributes, not the document, are what IsRevoked and GC
// read.
func (s *grantRevocationStore) widenRevokedAt(ctx context.Context, pk string, t store.GrantTombstone) error {
	entry, err := newItem(pk).doc(&t)
	if err != nil {
		return err
	}
	_, err = s.parent.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:        aws.String(s.parent.names.grantTombstones),
		Key:              key(pk),
		UpdateExpression: aws.String("SET #doc = :doc, #revoked = :revoked"),
		ConditionExpression: aws.String(
			"attribute_not_exists(#pk) OR attribute_not_exists(#revoked) OR #revoked < :revoked",
		),
		ExpressionAttributeNames: map[string]string{
			"#pk":      attrPK,
			"#doc":     attrDoc,
			"#revoked": attrRevokedAt,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":doc":     entry[attrDoc],
			":revoked": avTime(t.RevokedAt),
		},
	})
	if err != nil && !isConditionalCheckFailed(err) {
		return wrapErr("grantRevocations.RevokeGrant.revokedAt", err)
	}
	// A rejected guard means the stored instant is already at or past the
	// one supplied, which is the outcome the call asked for.
	return nil
}

// widenLifetime extends the row's retention. A zero ExpiresAt means "no
// expiry" and is therefore the widest horizon of all, so it is reached
// by clearing the TTL rather than by comparing against a larger number —
// and a row that already carries it is never narrowed to a finite one.
func (s *grantRevocationStore) widenLifetime(ctx context.Context, pk string, at time.Time) error {
	in := &dynamodb.UpdateItemInput{
		TableName: aws.String(s.parent.names.grantTombstones),
		Key:       key(pk),
		ExpressionAttributeNames: map[string]string{
			"#pk":      attrPK,
			"#expires": attrExpiresAt,
			"#ttl":     attrTTL,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{":never": avN(0)},
	}
	if at.IsZero() {
		in.UpdateExpression = aws.String("SET #expires = :never REMOVE #ttl")
		in.ConditionExpression = aws.String(
			"attribute_not_exists(#pk) OR attribute_not_exists(#expires) OR #expires <> :never",
		)
	} else {
		ttl, _ := avTTL(at)
		in.UpdateExpression = aws.String("SET #expires = :expires, #ttl = :ttl")
		in.ConditionExpression = aws.String(
			"attribute_not_exists(#pk) OR attribute_not_exists(#expires) OR " +
				"(#expires <> :never AND #expires < :expires)",
		)
		in.ExpressionAttributeValues[":expires"] = avTime(at)
		in.ExpressionAttributeValues[":ttl"] = ttl
	}
	if _, err := s.parent.api.UpdateItem(ctx, in); err != nil && !isConditionalCheckFailed(err) {
		return wrapErr("grantRevocations.RevokeGrant.lifetime", err)
	}
	return nil
}

// revokeGrantStaged widens the tombstone inside a caller-owned
// transaction. A transaction cannot issue the two guarded updates —
// TransactWriteItems carries no read — so the widening is computed
// against the row as the transaction read it and the staged write
// asserts that state again on commit: a cascade that lands meanwhile
// aborts the transaction instead of narrowing the window it wrote.
func (s *grantRevocationStore) revokeGrantStaged(ctx context.Context, pk string, t store.GrantTombstone) error {
	existing, err := s.tx.get(ctx, s.parent.names.grantTombstones, pk)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return wrapErr("grantRevocations.RevokeGrant.read", err)
	}
	if existing != nil {
		if prior := readTime(existing, attrExpiresAt); prior.After(t.ExpiresAt) {
			t.ExpiresAt = prior
		}
		if priorRevoked := readTime(existing, attrRevokedAt); priorRevoked.After(t.RevokedAt) {
			t.RevokedAt = priorRevoked
		}
	}
	entry, err := newItem(pk).doc(&t)
	if err != nil {
		return err
	}
	entry.expires(t.ExpiresAt)
	entry.setTime(attrRevokedAt, t.RevokedAt)
	return s.tx.putGuarded(
		ctx, s.parent.names.grantTombstones, pk, entry, attrRevokedAt, attrExpiresAt,
	)
}

// RevokeJTI denylists one access token by id.
func (s *grantRevocationStore) RevokeJTI(ctx context.Context, r store.RevokedJTI) error {
	pk := denylistPrefix + r.JTI
	entry, err := newItem(pk).doc(&r)
	if err != nil {
		return err
	}
	entry.expires(r.ExpiresAt)
	entry.set(attrGrantID, r.GrantID)

	if s.tx != nil {
		return s.tx.put(s.parent.names.grantTombstones, pk, entry)
	}
	if err := s.parent.put(ctx, s.parent.names.grantTombstones, entry); err != nil {
		return wrapErr("grantRevocations.RevokeJTI", err)
	}
	return nil
}

// IsRevoked reports whether a token is dead, by either route: its jti
// is denylisted, or its grant carries a tombstone stamped at or before
// the token was issued. The iat comparison is what keeps a tombstone
// from invalidating tokens minted after the revocation.
func (s *grantRevocationStore) IsRevoked(
	ctx context.Context,
	grantID, jti string,
	iat time.Time,
) (bool, error) {
	if jti != "" {
		found, err := s.read(ctx, denylistPrefix+jti)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return false, wrapErr("grantRevocations.IsRevoked.jti", err)
		}
		if found != nil && !s.parent.expired(found) {
			return true, nil
		}
	}
	if grantID == "" {
		return false, nil
	}
	found, err := s.read(ctx, tombstonePrefix+grantID)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, wrapErr("grantRevocations.IsRevoked.grant", err)
	}
	if s.parent.expired(found) {
		return false, nil
	}
	revokedAt := readTime(found, attrRevokedAt)
	if revokedAt.IsZero() {
		return true, nil
	}
	// A token issued strictly after the revocation instant survives.
	return !iat.After(revokedAt), nil
}

func (s *grantRevocationStore) GC(ctx context.Context, cutoff time.Time) (int, error) {
	return s.parent.gcExpired(ctx, s.parent.names.grantTombstones, cutoff, "grantRevocations.GC")
}

func (s *grantRevocationStore) read(ctx context.Context, pk string) (item, error) {
	if s.tx != nil {
		return s.tx.get(ctx, s.parent.names.grantTombstones, pk)
	}
	return s.parent.get(ctx, s.parent.names.grantTombstones, pk)
}

var _ store.GrantRevocationStore = (*grantRevocationStore)(nil)
