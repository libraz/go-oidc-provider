package inmem

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// accessTokenStore is the inmem implementation of
// [store.AccessTokenRegistry]. It keeps every issued JWT access-token
// shadow row keyed by JTI; revocation flips a boolean so audit
// downstream can still recover the issuance metadata. The periodic GC
// sweep drops rows whose ExpiresAt is past the supplied cutoff,
// bounding storage to the active TTL plus the configured grace.
type accessTokenStore struct {
	mu  sync.RWMutex
	m   map[string]*store.AccessTokenRecord
	idx tokenIndex
}

func newAccessTokenStore() *accessTokenStore {
	return &accessTokenStore{m: make(map[string]*store.AccessTokenRecord), idx: newTokenIndex()}
}

// Register implements [store.AccessTokenRegistry].
func (s *accessTokenStore) Register(_ context.Context, rec store.AccessTokenRecord) error {
	if rec.JTI == "" {
		return errors.New("inmem: AccessTokenRecord requires a non-empty JTI")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.m[rec.JTI]; exists {
		return store.ErrAlreadyExists
	}
	stored := cloneAccessToken(&rec)
	s.m[rec.JTI] = stored
	accessTokenRowOps.track(s.idx, rec.JTI, stored)
	return nil
}

// Find implements [store.AccessTokenRegistry]. Returns (nil, nil) when
// the record is absent so callers can distinguish "not registered"
// from a genuine error path.
func (s *accessTokenStore) Find(_ context.Context, jti string) (*store.AccessTokenRecord, error) {
	if jti == "" {
		return nil, nil //nolint:nilnil // contract permits (nil, nil) for absent records.
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.m[jti]
	if !ok {
		return nil, nil //nolint:nilnil // contract permits (nil, nil) for absent records.
	}
	return cloneAccessToken(rec), nil
}

// RevokeByJTI implements [store.AccessTokenRegistry]. The call is
// idempotent: a missing record returns nil so the revocation endpoint
// can stay aligned with RFC 7009 §2.2.
func (s *accessTokenStore) RevokeByJTI(_ context.Context, jti string) error {
	if jti == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.m[jti]
	if !ok {
		return nil
	}
	rec.Revoked = true
	return nil
}

// RevokeByGrant implements [store.AccessTokenRegistry]. Returns the
// number of rows the call flipped (rows already revoked are not
// counted; the caller can detect "first-time cascade" by inspecting
// the return).
func (s *accessTokenStore) RevokeByGrant(_ context.Context, grantID string) (int, error) {
	if grantID == "" {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return revokeIndexed(accessTokenRowOps, s.m, s.idx.byGrant[grantID], matchAnyToken), nil
}

// RevokeByClient implements [store.RevokeByClient]. The DCR delete
// cascade probes for it so a deleted client takes its outstanding
// JWT access-token registry rows with it. A non-existent client is
// a no-op.
func (s *accessTokenStore) RevokeByClient(_ context.Context, clientID string) error {
	if clientID == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	revokeIndexed(accessTokenRowOps, s.m, s.idx.byClient[clientID], matchAnyToken)
	return nil
}

// GC implements [store.AccessTokenRegistry]. Drops every record whose
// ExpiresAt is strictly before cutoff. The zero time is treated as
// "no expiry" and is never collected; callers that need the original
// behaviour (drop everything) supply an explicit far-future cutoff.
func (s *accessTokenStore) GC(_ context.Context, cutoff time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return gcRows(accessTokenRowOps, s.m, s.idx, cutoff), nil
}

// accessTokenRowOps adapts [store.AccessTokenRecord] to the shared token-row helpers.
//
//nolint:gochecknoglobals // field accessors; immutable after package init.
var accessTokenRowOps = tokenRowOps[*store.AccessTokenRecord]{
	grantID:    func(r *store.AccessTokenRecord) string { return r.GrantID },
	clientID:   func(r *store.AccessTokenRecord) string { return r.ClientID },
	expiresAt:  func(r *store.AccessTokenRecord) time.Time { return r.ExpiresAt },
	revoked:    func(r *store.AccessTokenRecord) bool { return r.Revoked },
	setRevoked: func(r *store.AccessTokenRecord) { r.Revoked = true },
}

// matchAnyToken accepts every row of an index bucket: the index key already
// fixed the attribute being matched.
func matchAnyToken[V any](V) bool { return true }

// overlay returns the transactional view of the registry; a commit keeps the
// grant and client indexes in step with the rows it writes and drops.
func (s *accessTokenStore) overlay() *overlay[*store.AccessTokenRecord] {
	o := newOverlay(s.m, cloneAccessToken)
	o.onPut = func(key string, rec *store.AccessTokenRecord) { accessTokenRowOps.track(s.idx, key, rec) }
	o.onDrop = func(key string, rec *store.AccessTokenRecord) { accessTokenRowOps.untrack(s.idx, key, rec) }
	return o
}

func cloneAccessToken(rec *store.AccessTokenRecord) *store.AccessTokenRecord {
	if rec == nil {
		return nil
	}
	out := *rec
	out.Scopes = slices.Clone(rec.Scopes)
	return &out
}
