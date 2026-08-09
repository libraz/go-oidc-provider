package inmem

import (
	"context"
	"errors"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
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

// --- staging: JWT access-token registry --------------------------------------

type accessTokenStaging struct {
	parent  *accessTokenStore
	written map[string]*store.AccessTokenRecord
	deleted map[string]struct{}
}

func newAccessTokenStaging(parent *accessTokenStore) *accessTokenStaging {
	return &accessTokenStaging{
		parent:  parent,
		written: make(map[string]*store.AccessTokenRecord),
		deleted: make(map[string]struct{}),
	}
}

// lookup returns the record visible to this transaction, or nil. Parent
// records are cloned so a caller that stages a mutation on the result
// cannot write through to the committed map.
func (s *accessTokenStaging) lookup(jti string) *store.AccessTokenRecord {
	if rec, ok := s.written[jti]; ok {
		return rec
	}
	if _, gone := s.deleted[jti]; gone {
		return nil
	}
	if rec, ok := s.parent.m[jti]; ok {
		return cloneAccessToken(rec)
	}
	return nil
}

func (s *accessTokenStaging) stage(jti string, rec *store.AccessTokenRecord) {
	delete(s.deleted, jti)
	s.written[jti] = rec
}

func (s *accessTokenStaging) drop(jti string) {
	delete(s.written, jti)
	s.deleted[jti] = struct{}{}
}

// iter calls fn for every record visible to this transaction, with the
// staged view taking precedence over the parent map.
func (s *accessTokenStaging) iter(fn func(string, *store.AccessTokenRecord)) {
	for jti, rec := range s.written {
		fn(jti, rec)
	}
	for jti, rec := range s.parent.m {
		if _, staged := s.written[jti]; staged {
			continue
		}
		if _, gone := s.deleted[jti]; gone {
			continue
		}
		fn(jti, rec)
	}
}

func (s *accessTokenStaging) flushLocked() {
	for jti := range s.deleted {
		delete(s.parent.m, jti)
	}
	for jti, rec := range s.written {
		s.parent.m[jti] = rec
	}
}

func (s *accessTokenStaging) clear() {
	clear(s.written)
	clear(s.deleted)
}

type txAccessTokens struct{ tx *tx }

func (s txAccessTokens) Register(ctx context.Context, rec store.AccessTokenRecord) error {
	if s.tx.closed.Load() {
		return errTxClosed
	}
	if err := ctx.Err(); err != nil {
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
	if s.tx.closed.Load() {
		return nil, errTxClosed
	}
	if err := ctx.Err(); err != nil {
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
	if s.tx.closed.Load() {
		return errTxClosed
	}
	if err := ctx.Err(); err != nil {
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
	if s.tx.closed.Load() {
		return 0, errTxClosed
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if grantID == "" {
		return 0, nil
	}
	st := s.tx.atStaging
	n := 0
	st.iter(func(jti string, rec *store.AccessTokenRecord) {
		if rec.GrantID != grantID || rec.Revoked {
			return
		}
		updated := cloneAccessToken(rec)
		updated.Revoked = true
		st.stage(jti, updated)
		n++
	})
	return n, nil
}

func (s txAccessTokens) GC(ctx context.Context, cutoff time.Time) (int, error) {
	if s.tx.closed.Load() {
		return 0, errTxClosed
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	st := s.tx.atStaging
	n := 0
	st.iter(func(jti string, rec *store.AccessTokenRecord) {
		if rec.ExpiresAt.IsZero() || !rec.ExpiresAt.Before(cutoff) {
			return
		}
		st.drop(jti)
		n++
	})
	return n, nil
}

// --- staging: opaque access tokens -------------------------------------------

type opaqueAccessTokenStaging struct {
	parent  *opaqueAccessTokenStore
	written map[string]*store.OpaqueAccessToken
	deleted map[string]struct{}
}

func newOpaqueAccessTokenStaging(parent *opaqueAccessTokenStore) *opaqueAccessTokenStaging {
	return &opaqueAccessTokenStaging{
		parent:  parent,
		written: make(map[string]*store.OpaqueAccessToken),
		deleted: make(map[string]struct{}),
	}
}

// lookup takes the SHA-256 digest of the raw bearer id, matching the
// key discipline of the non-transactional substore.
func (s *opaqueAccessTokenStaging) lookup(key string) *store.OpaqueAccessToken {
	if rec, ok := s.written[key]; ok {
		return rec
	}
	if _, gone := s.deleted[key]; gone {
		return nil
	}
	if rec, ok := s.parent.m[key]; ok {
		return cloneOpaqueAccessToken(rec)
	}
	return nil
}

func (s *opaqueAccessTokenStaging) stage(key string, rec *store.OpaqueAccessToken) {
	delete(s.deleted, key)
	s.written[key] = rec
}

func (s *opaqueAccessTokenStaging) drop(key string) {
	delete(s.written, key)
	s.deleted[key] = struct{}{}
}

func (s *opaqueAccessTokenStaging) iter(fn func(string, *store.OpaqueAccessToken)) {
	for key, rec := range s.written {
		fn(key, rec)
	}
	for key, rec := range s.parent.m {
		if _, staged := s.written[key]; staged {
			continue
		}
		if _, gone := s.deleted[key]; gone {
			continue
		}
		fn(key, rec)
	}
}

func (s *opaqueAccessTokenStaging) flushLocked() {
	for key := range s.deleted {
		delete(s.parent.m, key)
	}
	for key, rec := range s.written {
		s.parent.m[key] = rec
	}
}

func (s *opaqueAccessTokenStaging) clear() {
	clear(s.written)
	clear(s.deleted)
}

type txOpaqueAccessTokens struct{ tx *tx }

func (s txOpaqueAccessTokens) Save(ctx context.Context, tok *store.OpaqueAccessToken) error {
	if s.tx.closed.Load() {
		return errTxClosed
	}
	if err := ctx.Err(); err != nil {
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
	if s.tx.closed.Load() {
		return nil, errTxClosed
	}
	if err := ctx.Err(); err != nil {
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
	if s.tx.closed.Load() {
		return errTxClosed
	}
	if err := ctx.Err(); err != nil {
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
	if s.tx.closed.Load() {
		return 0, errTxClosed
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if grantID == "" {
		return 0, nil
	}
	st := s.tx.oatStaging
	n := 0
	st.iter(func(key string, rec *store.OpaqueAccessToken) {
		if rec.GrantID != grantID || rec.Revoked {
			return
		}
		updated := cloneOpaqueAccessToken(rec)
		updated.Revoked = true
		st.stage(key, updated)
		n++
	})
	return n, nil
}

func (s txOpaqueAccessTokens) GC(ctx context.Context, cutoff time.Time) (int, error) {
	if s.tx.closed.Load() {
		return 0, errTxClosed
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	st := s.tx.oatStaging
	n := 0
	st.iter(func(key string, rec *store.OpaqueAccessToken) {
		if rec.ExpiresAt.IsZero() || !rec.ExpiresAt.Before(cutoff) {
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
	parent *grantRevocationStore

	tombstonesWritten map[string]*store.GrantTombstone
	tombstonesDeleted map[string]struct{}

	denylistWritten map[string]*store.RevokedJTI
	denylistDeleted map[string]struct{}
}

func newGrantRevocationStaging(parent *grantRevocationStore) *grantRevocationStaging {
	return &grantRevocationStaging{
		parent:            parent,
		tombstonesWritten: make(map[string]*store.GrantTombstone),
		tombstonesDeleted: make(map[string]struct{}),
		denylistWritten:   make(map[string]*store.RevokedJTI),
		denylistDeleted:   make(map[string]struct{}),
	}
}

func (s *grantRevocationStaging) lookupTombstone(grantID string) *store.GrantTombstone {
	if rec, ok := s.tombstonesWritten[grantID]; ok {
		return rec
	}
	if _, gone := s.tombstonesDeleted[grantID]; gone {
		return nil
	}
	if rec, ok := s.parent.tombstones[grantID]; ok {
		out := *rec
		return &out
	}
	return nil
}

func (s *grantRevocationStaging) lookupDenylist(jti string) *store.RevokedJTI {
	if rec, ok := s.denylistWritten[jti]; ok {
		return rec
	}
	if _, gone := s.denylistDeleted[jti]; gone {
		return nil
	}
	if rec, ok := s.parent.denylist[jti]; ok {
		out := *rec
		return &out
	}
	return nil
}

func (s *grantRevocationStaging) iterTombstones(fn func(string, *store.GrantTombstone)) {
	for id, rec := range s.tombstonesWritten {
		fn(id, rec)
	}
	for id, rec := range s.parent.tombstones {
		if _, staged := s.tombstonesWritten[id]; staged {
			continue
		}
		if _, gone := s.tombstonesDeleted[id]; gone {
			continue
		}
		fn(id, rec)
	}
}

func (s *grantRevocationStaging) iterDenylist(fn func(string, *store.RevokedJTI)) {
	for jti, rec := range s.denylistWritten {
		fn(jti, rec)
	}
	for jti, rec := range s.parent.denylist {
		if _, staged := s.denylistWritten[jti]; staged {
			continue
		}
		if _, gone := s.denylistDeleted[jti]; gone {
			continue
		}
		fn(jti, rec)
	}
}

func (s *grantRevocationStaging) flushLocked() {
	for id := range s.tombstonesDeleted {
		delete(s.parent.tombstones, id)
	}
	for id, rec := range s.tombstonesWritten {
		s.parent.tombstones[id] = rec
	}
	for jti := range s.denylistDeleted {
		delete(s.parent.denylist, jti)
	}
	for jti, rec := range s.denylistWritten {
		s.parent.denylist[jti] = rec
	}
}

func (s *grantRevocationStaging) clear() {
	clear(s.tombstonesWritten)
	clear(s.tombstonesDeleted)
	clear(s.denylistWritten)
	clear(s.denylistDeleted)
}

type txGrantRevocations struct{ tx *tx }

// RevokeGrant stages the same idempotent merge the non-transactional
// substore performs: a second call against the same GrantID extends
// RevokedAt and ExpiresAt to the later of the supplied and existing
// values, and latches Reason onto the first hint. The merge reads
// through the overlay, so two calls inside one transaction compose
// exactly as two committed calls would.
func (s txGrantRevocations) RevokeGrant(ctx context.Context, t store.GrantTombstone) error {
	if s.tx.closed.Load() {
		return errTxClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if t.GrantID == "" {
		return nil
	}
	st := s.tx.grvStaging
	merged := st.lookupTombstone(t.GrantID)
	if merged == nil {
		clone := t
		merged = &clone
	} else {
		if t.RevokedAt.After(merged.RevokedAt) {
			merged.RevokedAt = t.RevokedAt
		}
		if t.ExpiresAt.After(merged.ExpiresAt) {
			merged.ExpiresAt = t.ExpiresAt
		}
		if merged.Reason == "" && t.Reason != "" {
			merged.Reason = t.Reason
		}
	}
	delete(st.tombstonesDeleted, t.GrantID)
	st.tombstonesWritten[t.GrantID] = merged
	return nil
}

// RevokeJTI stages a denylist row. A second call against the same JTI
// is a no-op so the audit trail keeps the instant the row was first
// written.
func (s txGrantRevocations) RevokeJTI(ctx context.Context, r store.RevokedJTI) error {
	if s.tx.closed.Load() {
		return errTxClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.JTI == "" {
		return nil
	}
	st := s.tx.grvStaging
	if st.lookupDenylist(r.JTI) != nil {
		return nil
	}
	clone := r
	delete(st.denylistDeleted, r.JTI)
	st.denylistWritten[r.JTI] = &clone
	return nil
}

func (s txGrantRevocations) IsRevoked(ctx context.Context, grantID, jti string, iat time.Time) (bool, error) {
	if s.tx.closed.Load() {
		return false, errTxClosed
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	st := s.tx.grvStaging
	if jti != "" && st.lookupDenylist(jti) != nil {
		return true, nil
	}
	if grantID == "" {
		return false, nil
	}
	tomb := st.lookupTombstone(grantID)
	if tomb == nil {
		return false, nil
	}
	// "revoked iff iat <= RevokedAt": equivalently, NOT iat.After.
	return !iat.After(tomb.RevokedAt), nil
}

func (s txGrantRevocations) GC(ctx context.Context, cutoff time.Time) (int, error) {
	if s.tx.closed.Load() {
		return 0, errTxClosed
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	st := s.tx.grvStaging
	n := 0
	st.iterTombstones(func(id string, rec *store.GrantTombstone) {
		if rec.ExpiresAt.IsZero() || !rec.ExpiresAt.Before(cutoff) {
			return
		}
		delete(st.tombstonesWritten, id)
		st.tombstonesDeleted[id] = struct{}{}
		n++
	})
	st.iterDenylist(func(jti string, rec *store.RevokedJTI) {
		if rec.ExpiresAt.IsZero() || !rec.ExpiresAt.Before(cutoff) {
			return
		}
		delete(st.denylistWritten, jti)
		st.denylistDeleted[jti] = struct{}{}
		n++
	})
	return n, nil
}
