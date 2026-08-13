package oidcdynamo

import (
	"context"
	"errors"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/patterns"
)

// jtiStore records consumed JWT IDs for replay detection.
//
// The raw jti is hashed before it reaches the table so the leakage
// surface (a table export, a stream consumer, a backup) only ever sees
// the digest. Hashing also bounds the stored length: RFC 7519 sets no
// upper bound on a jti, and DynamoDB caps a partition key at 2048
// bytes.
type jtiStore struct {
	parent *Store
}

// Mark records jti as consumed, reporting [store.ErrAlreadyConsumed]
// when it was already present and still live. An entry whose expiry has
// passed is overwritten rather than treated as a replay: the JWT it
// guarded can no longer be redeemed on its own merits, so keeping the
// marker would only reject a legitimate fresh jti that happened to
// collide.
//
// Both outcomes are one conditional write. Taking over a stale marker is
// as much a decision as refusing a live one, and reading the stored
// entry to judge it would let two proofs carrying the same jti find the
// same expired marker and both be accepted — the replay this store
// exists to catch.
func (s *jtiStore) Mark(ctx context.Context, jti string, expiresAt time.Time) error {
	i := newItem(patterns.Digest(jti)).expires(expiresAt)

	placed, err := s.parent.putIfKeyFreeAtExpiry(ctx, s.parent.names.jtis, i)
	if err != nil {
		return wrapErr("jtis.Mark", err)
	}
	if !placed {
		return store.ErrAlreadyConsumed
	}
	return nil
}

// Has reports whether jti has previously been marked. An entry past its
// expiry reads as absent so a stale marker DynamoDB has not reclaimed
// yet cannot reject a fresh token.
func (s *jtiStore) Has(ctx context.Context, jti string) (bool, error) {
	found, err := s.parent.get(ctx, s.parent.names.jtis, patterns.Digest(jti))
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, wrapErr("jtis.Has", err)
	}
	return !s.jtiExpired(found), nil
}

// jtiExpired applies the inclusive expiry bound [store.ConsumedJTIStore]
// pins for replay markers: a marker is expired from its expiresAt
// onwards. The substore does not reuse the store-wide [Store.expired]
// helper, which keeps a record live at its own expiry instant, because
// Mark and Has must agree on the boundary or a caller can observe a jti
// as consumed and still consume it again.
func (s *jtiStore) jtiExpired(found item) bool {
	return patterns.IsExpiredInclusive(readTime(found, attrExpiresAt), s.parent.now())
}

var _ store.ConsumedJTIStore = (*jtiStore)(nil)
