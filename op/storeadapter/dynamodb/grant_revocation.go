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
// grant before RevokedAt. A tombstone with [store.GrantTombstone.AccessTokensOnly]
// widens the access-token cutoff, any other the whole-grant cutoff; the
// two are separate attributes so IsIssuanceRevoked can honour only the
// second. The row's horizons only ever widen:
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

// cutoffAttr names the attribute a tombstone's RevokedAt widens.
func cutoffAttr(t store.GrantTombstone) string {
	if t.AccessTokensOnly {
		return attrAccessRevokedAt
	}
	return attrRevokedAt
}

// widenRevokedAt advances the revocation instant of t's scope, and
// writes the row when the grant has no tombstone yet. The document rides
// along with a whole-grant instant so the reason recorded is the one of
// the cascade that set it; an access-token-only one only fills a missing
// document. The projected attributes, not the document, are what
// IsRevoked and GC read.
func (s *grantRevocationStore) widenRevokedAt(ctx context.Context, pk string, t store.GrantTombstone) error {
	entry, err := newItem(pk).doc(&t)
	if err != nil {
		return err
	}
	in := &dynamodb.UpdateItemInput{
		TableName:        aws.String(s.parent.names.grantTombstones),
		Key:              key(pk),
		UpdateExpression: aws.String("SET #doc = :doc, #revoked = :revoked"),
		// A stored whole-grant instant of 0 revokes everything, the widest
		// window there is, so no finite instant replaces it.
		ConditionExpression: aws.String(
			"attribute_not_exists(#pk) OR attribute_not_exists(#revoked) OR (#revoked <> :all AND #revoked < :revoked)",
		),
		ExpressionAttributeNames: map[string]string{
			"#pk":      attrPK,
			"#doc":     attrDoc,
			"#revoked": cutoffAttr(t),
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":doc":     entry[attrDoc],
			":revoked": avTime(t.RevokedAt),
			":all":     avN(0),
		},
	}
	if t.AccessTokensOnly {
		in.UpdateExpression = aws.String("SET #doc = if_not_exists(#doc, :doc), #revoked = :revoked")
		in.ConditionExpression = aws.String(
			"attribute_not_exists(#pk) OR attribute_not_exists(#revoked) OR #revoked < :revoked",
		)
		delete(in.ExpressionAttributeValues, ":all")
	}
	_, err = s.parent.api.UpdateItem(ctx, in)
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
	cutoff := cutoffAttr(t)
	if existing != nil {
		if prior := readTime(existing, attrExpiresAt); prior.After(t.ExpiresAt) {
			t.ExpiresAt = prior
		}
		t.RevokedAt = widerCutoff(existing, t)
	}
	entry, err := newItem(pk).doc(&t)
	if err != nil {
		return err
	}
	if existing != nil && t.AccessTokensOnly && existing[attrDoc] != nil {
		entry[attrDoc] = existing[attrDoc]
	}
	entry.expires(t.ExpiresAt)
	entry.setTime(cutoff, t.RevokedAt)
	// The other scope's cutoff is carried over unchanged.
	for _, attr := range []string{attrRevokedAt, attrAccessRevokedAt} {
		if prior, ok := existing[attr]; ok && attr != cutoff {
			entry[attr] = prior
		}
	}
	return s.tx.putGuarded(
		ctx, s.parent.names.grantTombstones, pk, entry, attrRevokedAt, attrAccessRevokedAt, attrExpiresAt,
	)
}

// widerCutoff returns the wider of t's instant and the one existing
// stores for t's scope. A stored whole-grant 0 revokes everything and is
// kept.
func widerCutoff(existing item, t store.GrantTombstone) time.Time {
	cutoff := cutoffAttr(t)
	_, stored := existing[cutoff]
	prior := readTime(existing, cutoff)
	switch {
	case stored && prior.IsZero() && !t.AccessTokensOnly:
		return time.Time{}
	case prior.After(t.RevokedAt):
		return prior
	}
	return t.RevokedAt
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
	if err := s.parent.overwrite(ctx, s.parent.names.grantTombstones, entry); err != nil {
		return wrapErr("grantRevocations.RevokeJTI", err)
	}
	return nil
}

// IsRevoked reports whether a token is dead, by either route: its jti
// is denylisted, or its grant carries a tombstone, of either scope,
// stamped at or before the token was issued. The iat comparison is what
// keeps a tombstone from invalidating tokens minted after the revocation.
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
	found, err := s.liveTombstone(ctx, grantID, "grantRevocations.IsRevoked.grant")
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if legacyTombstone(found) {
		return true, nil
	}
	return coversWhole(found, iat) || coversAccess(found, iat), nil
}

// IsIssuanceRevoked implements [store.IssuanceRevocationChecker]: only
// the whole-grant cutoff refuses issuance.
func (s *grantRevocationStore) IsIssuanceRevoked(ctx context.Context, grantID string, issuedAt time.Time) (bool, error) {
	if err := s.tx.assertOpen(); err != nil {
		return false, err
	}
	if grantID == "" {
		return false, nil
	}
	found, err := s.liveTombstone(ctx, grantID, "grantRevocations.IsIssuanceRevoked")
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if legacyTombstone(found) {
		return true, nil
	}
	return coversWhole(found, issuedAt), nil
}

// liveTombstone reads a grant's tombstone, reporting [store.ErrNotFound]
// for one that is absent or past its expiry.
func (s *grantRevocationStore) liveTombstone(ctx context.Context, grantID, op string) (item, error) {
	found, err := s.read(ctx, tombstonePrefix+grantID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, wrapErr(op, err)
	}
	if s.parent.expired(found) {
		return nil, store.ErrNotFound
	}
	return found, nil
}

// legacyTombstone reports a row carrying neither cutoff, which revokes
// everything issued under the grant.
func legacyTombstone(found item) bool {
	_, whole := found[attrRevokedAt]
	_, access := found[attrAccessRevokedAt]
	return !whole && !access
}

// coversWhole applies "revoked iff iat <= cutoff" to the whole-grant
// cutoff. A stored zero instant revokes everything, as it always has;
// only an absent attribute means no whole-grant cutoff.
func coversWhole(found item, iat time.Time) bool {
	if _, ok := found[attrRevokedAt]; !ok {
		return false
	}
	cutoff := readTime(found, attrRevokedAt)
	return cutoff.IsZero() || !iat.After(cutoff)
}

// coversAccess applies the same rule to the access-token-only cutoff,
// where a zero or absent instant covers nothing.
func coversAccess(found item, iat time.Time) bool {
	cutoff := readTime(found, attrAccessRevokedAt)
	return !cutoff.IsZero() && !iat.After(cutoff)
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

var (
	_ store.GrantRevocationStore      = (*grantRevocationStore)(nil)
	_ store.IssuanceRevocationChecker = (*grantRevocationStore)(nil)
)
