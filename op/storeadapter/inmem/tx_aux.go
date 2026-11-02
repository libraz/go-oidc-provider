package inmem

import (
	"context"
	"errors"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/patterns"
)

// This file holds the transactional staging for the three auxiliary
// atomic-cluster substores: the JWT access-token registry, the opaque
// access-token store, and the grant-revocation store. They follow the
// same overlay discipline as the authorization-code, refresh-token,
// grant, and PAR staging in tx.go: a transaction reads through the
// overlay onto the parent map and writes only into the overlay, so
// [Store.BeginTx] allocates a fixed number of empty maps regardless of
// how many records the parent holds, and a rollback needs to discard
// nothing but the overlay.
//
// Reading through an overlay is what makes the read-your-own-writes
// guarantee in [store.Tx] hold field by field: a lookup consults the
// staged record first, so a revocation staged earlier in the same
// transaction is visible to every later read on it, while a direct
// reader outside the transaction sees nothing until Commit copies the
// overlay into the parent. Records pulled from the parent map are
// cloned on the way into the overlay so a staged mutation cannot reach
// a record a rollback is about to abandon.

// overlay is the staged view of one parent map: records written in the
// transaction, plus keys deleted in it. Parent records are cloned on the
// way into a lookup so a staged mutation cannot write through to the
// committed map.
type overlay[V any] struct {
	base    map[string]V
	clone   func(V) V
	written map[string]V
	deleted map[string]struct{}

	// onPut and onDrop, when set, run for every row a commit writes into or
	// removes from base, so secondary indexes follow the primary map.
	onPut  func(key string, rec V)
	onDrop func(key string, rec V)
}

func newOverlay[V any](base map[string]V, clone func(V) V) *overlay[V] {
	return &overlay[V]{
		base:    base,
		clone:   clone,
		written: make(map[string]V),
		deleted: make(map[string]struct{}),
	}
}

// lookup returns the record visible to this transaction, or the zero
// value (nil for the pointer records staged here).
func (s *overlay[V]) lookup(key string) V {
	var none V
	if rec, ok := s.written[key]; ok {
		return rec
	}
	if _, gone := s.deleted[key]; gone {
		return none
	}
	if rec, ok := s.base[key]; ok {
		return s.clone(rec)
	}
	return none
}

func (s *overlay[V]) stage(key string, rec V) {
	delete(s.deleted, key)
	s.written[key] = rec
}

func (s *overlay[V]) drop(key string) {
	delete(s.written, key)
	s.deleted[key] = struct{}{}
}

// iter calls fn for every record visible to this transaction, with the
// staged view taking precedence over the parent map.
func (s *overlay[V]) iter(fn func(string, V)) {
	for key, rec := range s.written {
		fn(key, rec)
	}
	for key, rec := range s.base {
		if _, staged := s.written[key]; staged {
			continue
		}
		if _, gone := s.deleted[key]; gone {
			continue
		}
		fn(key, rec)
	}
}

func (s *overlay[V]) flushLocked() {
	for key := range s.deleted {
		if rec, ok := s.base[key]; ok && s.onDrop != nil {
			s.onDrop(key, rec)
		}
		delete(s.base, key)
	}
	for key, rec := range s.written {
		s.base[key] = rec
		if s.onPut != nil {
			s.onPut(key, rec)
		}
	}
}

func (s *overlay[V]) clear() {
	clear(s.written)
	clear(s.deleted)
}

// --- staging: JWT access-token registry --------------------------------------

type txAccessTokens struct{ tx *tx }

func (s txAccessTokens) Register(ctx context.Context, rec store.AccessTokenRecord) error {
	if err := s.tx.guard(ctx); err != nil {
		return err
	}
	if rec.JTI == "" {
		return errors.New("inmem: AccessTokenRecord requires a non-empty JTI")
	}
	st := s.tx.atStaging
	if st.lookup(rec.JTI) != nil {
		return store.ErrAlreadyExists
	}
	st.stage(rec.JTI, cloneAccessToken(&rec))
	return nil
}

func (s txAccessTokens) Find(ctx context.Context, jti string) (*store.AccessTokenRecord, error) {
	if err := s.tx.guard(ctx); err != nil {
		return nil, err
	}
	if jti == "" {
		return nil, nil //nolint:nilnil // contract permits (nil, nil) for absent records.
	}
	rec := s.tx.atStaging.lookup(jti)
	if rec == nil {
		return nil, nil //nolint:nilnil // contract permits (nil, nil) for absent records.
	}
	return cloneAccessToken(rec), nil
}

func (s txAccessTokens) RevokeByJTI(ctx context.Context, jti string) error {
	if err := s.tx.guard(ctx); err != nil {
		return err
	}
	if jti == "" {
		return nil
	}
	st := s.tx.atStaging
	rec := st.lookup(jti)
	if rec == nil {
		return nil
	}
	updated := cloneAccessToken(rec)
	updated.Revoked = true
	st.stage(jti, updated)
	return nil
}

func (s txAccessTokens) RevokeByGrant(ctx context.Context, grantID string) (int, error) {
	if err := s.tx.guard(ctx); err != nil {
		return 0, err
	}
	if grantID == "" {
		return 0, nil
	}
	ids := s.tx.owner.accessTokens.idx.byGrant[grantID]
	return revokeStaged(accessTokenRowOps, s.tx.atStaging, cloneAccessToken, ids, matchAnyToken), nil
}

func (s txAccessTokens) GC(ctx context.Context, cutoff time.Time) (int, error) {
	if err := s.tx.guard(ctx); err != nil {
		return 0, err
	}
	st := s.tx.atStaging
	n := 0
	st.iter(func(jti string, rec *store.AccessTokenRecord) {
		if !patterns.IsExpiredStrict(rec.ExpiresAt, cutoff) {
			return
		}
		st.drop(jti)
		n++
	})
	return n, nil
}

// --- staging: opaque access tokens -------------------------------------------

type txOpaqueAccessTokens struct{ tx *tx }

func (s txOpaqueAccessTokens) Save(ctx context.Context, tok *store.OpaqueAccessToken) error {
	if err := s.tx.guard(ctx); err != nil {
		return err
	}
	if tok == nil {
		return errors.New("inmem: nil opaque access token")
	}
	if tok.ID == "" {
		return errors.New("inmem: OpaqueAccessToken requires a non-empty ID")
	}
	st := s.tx.oatStaging
	key := hashKey(tok.ID)
	if st.lookup(key) != nil {
		return store.ErrAlreadyExists
	}
	stored := cloneOpaqueAccessToken(tok)
	// The staged record carries the digest in place of the raw bearer
	// secret, exactly as the committed map does.
	stored.ID = key
	st.stage(key, stored)
	return nil
}

func (s txOpaqueAccessTokens) Find(ctx context.Context, id string) (*store.OpaqueAccessToken, error) {
	if err := s.tx.guard(ctx); err != nil {
		return nil, err
	}
	if id == "" {
		return nil, store.ErrNotFound
	}
	key := hashKey(id)
	rec := s.tx.oatStaging.lookup(key)
	if rec == nil {
		return nil, store.ErrNotFound
	}
	if !constantTimeKeyMatch(rec.ID, key) {
		return nil, store.ErrNotFound
	}
	out := cloneOpaqueAccessToken(rec)
	out.ID = id
	return out, nil
}

func (s txOpaqueAccessTokens) RevokeByID(ctx context.Context, id string) error {
	if err := s.tx.guard(ctx); err != nil {
		return err
	}
	if id == "" {
		return nil
	}
	st := s.tx.oatStaging
	key := hashKey(id)
	rec := st.lookup(key)
	if rec == nil {
		return nil
	}
	updated := cloneOpaqueAccessToken(rec)
	updated.Revoked = true
	st.stage(key, updated)
	return nil
}

func (s txOpaqueAccessTokens) RevokeByGrant(ctx context.Context, grantID string) (int, error) {
	if err := s.tx.guard(ctx); err != nil {
		return 0, err
	}
	if grantID == "" {
		return 0, nil
	}
	ids := s.tx.owner.opaqueAccessTokens.idx.byGrant[grantID]
	return revokeStaged(opaqueTokenRowOps, s.tx.oatStaging, cloneOpaqueAccessToken, ids, matchAnyToken), nil
}

// RevokeByChain implements [store.OpaqueAccessTokenChainRevoker] through
// the overlay.
func (s txOpaqueAccessTokens) RevokeByChain(ctx context.Context, grantID, chainID string) (int, error) {
	if err := s.tx.guard(ctx); err != nil {
		return 0, err
	}
	if grantID == "" || chainID == "" {
		return 0, nil
	}
	ids := s.tx.owner.opaqueAccessTokens.idx.byGrant[grantID]
	return revokeStaged(opaqueTokenRowOps, s.tx.oatStaging, cloneOpaqueAccessToken, ids, matchChain(chainID)), nil
}

func (s txOpaqueAccessTokens) GC(ctx context.Context, cutoff time.Time) (int, error) {
	if err := s.tx.guard(ctx); err != nil {
		return 0, err
	}
	st := s.tx.oatStaging
	n := 0
	st.iter(func(key string, rec *store.OpaqueAccessToken) {
		if !patterns.IsExpiredStrict(rec.ExpiresAt, cutoff) {
			return
		}
		st.drop(key)
		n++
	})
	return n, nil
}

// --- staging: grant revocation -----------------------------------------------

// grantRevocationStaging overlays both physical maps the substore
// fronts. The tombstone and denylist overlays are independent, so a
// transaction that only writes a JTI denylist row leaves the tombstone
// overlay empty and pays nothing for it.
type grantRevocationStaging struct {
	tombstones *overlay[*tombstoneRow]
	denylist   *overlay[*store.RevokedJTI]
}

func newGrantRevocationStaging(parent *grantRevocationStore) *grantRevocationStaging {
	return &grantRevocationStaging{
		tombstones: newOverlay(parent.tombstones, func(r *tombstoneRow) *tombstoneRow {
			out := *r
			return &out
		}),
		denylist: newOverlay(parent.denylist, func(r *store.RevokedJTI) *store.RevokedJTI {
			out := *r
			return &out
		}),
	}
}

func (s *grantRevocationStaging) flushLocked() {
	s.tombstones.flushLocked()
	s.denylist.flushLocked()
}

func (s *grantRevocationStaging) clear() {
	s.tombstones.clear()
	s.denylist.clear()
}

type txGrantRevocations struct{ tx *tx }

// RevokeGrant stages the same idempotent merge the non-transactional
// substore performs: a second call against the same GrantID extends
// RevokedAt and ExpiresAt to the later of the supplied and existing
// values, and latches Reason onto the first hint. The merge reads
// through the overlay, so two calls inside one transaction compose
// exactly as two committed calls would.
func (s txGrantRevocations) RevokeGrant(ctx context.Context, t store.GrantTombstone) error {
	if err := s.tx.guard(ctx); err != nil {
		return err
	}
	if t.GrantID == "" {
		return nil
	}
	st := s.tx.grvStaging
	merged := st.tombstones.lookup(t.GrantID)
	if merged == nil {
		merged = newTombstoneRow(t)
	} else {
		merged.merge(t)
	}
	st.tombstones.stage(t.GrantID, merged)
	return nil
}

// RevokeJTI stages a denylist row. A second call against the same JTI
// is a no-op so the audit trail keeps the instant the row was first
// written.
func (s txGrantRevocations) RevokeJTI(ctx context.Context, r store.RevokedJTI) error {
	if err := s.tx.guard(ctx); err != nil {
		return err
	}
	if r.JTI == "" {
		return nil
	}
	st := s.tx.grvStaging
	if st.denylist.lookup(r.JTI) != nil {
		return nil
	}
	clone := r
	st.denylist.stage(r.JTI, &clone)
	return nil
}

func (s txGrantRevocations) IsRevoked(ctx context.Context, grantID, jti string, iat time.Time) (bool, error) {
	if err := s.tx.guard(ctx); err != nil {
		return false, err
	}
	st := s.tx.grvStaging
	if jti != "" && st.denylist.lookup(jti) != nil {
		return true, nil
	}
	if grantID == "" {
		return false, nil
	}
	tomb := st.tombstones.lookup(grantID)
	return tomb != nil && tomb.revokes(iat), nil
}

// IsIssuanceRevoked implements [store.IssuanceRevocationChecker] through
// the overlay.
func (s txGrantRevocations) IsIssuanceRevoked(ctx context.Context, grantID string, issuedAt time.Time) (bool, error) {
	if err := s.tx.guard(ctx); err != nil {
		return false, err
	}
	if grantID == "" {
		return false, nil
	}
	tomb := s.tx.grvStaging.tombstones.lookup(grantID)
	return tomb != nil && tomb.refusesIssuance(issuedAt), nil
}

func (s txGrantRevocations) GC(ctx context.Context, cutoff time.Time) (int, error) {
	if err := s.tx.guard(ctx); err != nil {
		return 0, err
	}
	st := s.tx.grvStaging
	n := 0
	st.tombstones.iter(func(id string, rec *tombstoneRow) {
		if !patterns.IsExpiredStrict(rec.expiresAt, cutoff) {
			return
		}
		st.tombstones.drop(id)
		n++
	})
	st.denylist.iter(func(jti string, rec *store.RevokedJTI) {
		if !patterns.IsExpiredStrict(rec.ExpiresAt, cutoff) {
			return
		}
		st.denylist.drop(jti)
		n++
	})
	return n, nil
}
