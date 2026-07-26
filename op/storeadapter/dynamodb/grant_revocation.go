package oidcdynamo

import (
	"context"
	"errors"
	"time"

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
// grant before RevokedAt. Re-revoking extends the tombstone's own
// expiry rather than shortening it: the record has to outlive the
// longest-lived token it invalidates.
func (s *grantRevocationStore) RevokeGrant(ctx context.Context, t store.GrantTombstone) error {
	pk := tombstonePrefix + t.GrantID
	existing, err := s.read(ctx, pk)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return wrapErr("grantRevocations.RevokeGrant.read", err)
	}
	if existing != nil {
		// Both horizons only ever widen. ExpiresAt has to outlive the
		// longest-lived token the tombstone invalidates, and RevokedAt
		// advancing is the point of a second cascade: a token minted
		// after the previous one must fall inside the new window.
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

	if s.tx != nil {
		return s.tx.put(s.parent.names.grantTombstones, pk, entry)
	}
	if err := s.parent.put(ctx, s.parent.names.grantTombstones, entry); err != nil {
		return wrapErr("grantRevocations.RevokeGrant", err)
	}
	return nil
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
