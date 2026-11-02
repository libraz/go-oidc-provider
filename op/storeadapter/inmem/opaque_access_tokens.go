package inmem

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// opaqueAccessTokenStore is the inmem implementation of
// [store.OpaqueAccessTokenStore]. Records are keyed by the SHA-256
// hash of the raw bearer id; the raw value is never retained inside
// the OP process so a heap dump cannot reconstruct an issued
// credential.
//
// The store mirrors the shape of [accessTokenStore] and layers
// hash-on-store on top: Save hashes the raw id before persisting and
// clears the stored record's ID field; Find hashes the presented id
// and looks the digest up.
type opaqueAccessTokenStore struct {
	mu  sync.RWMutex
	m   map[string]*store.OpaqueAccessToken
	idx tokenIndex
}

func newOpaqueAccessTokenStore() *opaqueAccessTokenStore {
	return &opaqueAccessTokenStore{m: make(map[string]*store.OpaqueAccessToken), idx: newTokenIndex()}
}

// Save implements [store.OpaqueAccessTokenStore]. The raw ID is hashed
// before insertion; the stored record carries the digest in place of
// the raw value so a heap dump cannot recover the bearer secret.
func (s *opaqueAccessTokenStore) Save(_ context.Context, tok *store.OpaqueAccessToken) error {
	if tok == nil {
		return errors.New("inmem: nil opaque access token")
	}
	if tok.ID == "" {
		return errors.New("inmem: OpaqueAccessToken requires a non-empty ID")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hashKey(tok.ID)
	if _, exists := s.m[key]; exists {
		return store.ErrAlreadyExists
	}
	stored := cloneOpaqueAccessToken(tok)
	// Drop the raw ID from the stored record. The map key is the
	// hashed token; the stored record carries the digest so callers
	// inspecting the underlying map see only the hash, never the
	// bearer secret. Find restores the raw ID from the lookup
	// parameter before handing the record back.
	stored.ID = key
	s.m[key] = stored
	opaqueTokenRowOps.track(s.idx, key, stored)
	return nil
}

// Find implements [store.OpaqueAccessTokenStore]. The presented id is
// hashed before lookup; revoked or expired records are returned with
// their flags intact so callers (introspection, userinfo) can inspect
// the metadata themselves.
func (s *opaqueAccessTokenStore) Find(_ context.Context, id string) (*store.OpaqueAccessToken, error) {
	if id == "" {
		return nil, store.ErrNotFound
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := hashKey(id)
	rec, ok := s.m[key]
	if !ok {
		return nil, store.ErrNotFound
	}
	if !constantTimeKeyMatch(rec.ID, key) {
		// Defensive: the digest stored alongside the record diverged
		// from the map key. The reference impl maintains the
		// invariant; the check guards against a future refactor.
		return nil, store.ErrNotFound
	}
	out := cloneOpaqueAccessToken(rec)
	// Restore the raw ID for the caller so the returned record is
	// indistinguishable from what was passed to Save. The stored
	// record retains the digest.
	out.ID = id
	return out, nil
}

// RevokeByID implements [store.OpaqueAccessTokenStore]. The call is
// idempotent: a missing record returns nil so the revocation endpoint
// stays aligned with RFC 7009 §2.2.
func (s *opaqueAccessTokenStore) RevokeByID(_ context.Context, id string) error {
	if id == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hashKey(id)
	rec, ok := s.m[key]
	if !ok {
		return nil
	}
	rec.Revoked = true
	return nil
}

// RevokeByGrant implements [store.OpaqueAccessTokenStore]. Returns the
// number of rows the call flipped (rows already revoked are not
// counted; the caller can detect "first-time cascade" by inspecting
// the return).
func (s *opaqueAccessTokenStore) RevokeByGrant(_ context.Context, grantID string) (int, error) {
	if grantID == "" {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return revokeIndexed(opaqueTokenRowOps, s.m, s.idx.byGrant[grantID], matchAnyToken), nil
}

// RevokeByChain implements [store.OpaqueAccessTokenChainRevoker].
func (s *opaqueAccessTokenStore) RevokeByChain(_ context.Context, grantID, chainID string) (int, error) {
	if grantID == "" || chainID == "" {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return revokeIndexed(opaqueTokenRowOps, s.m, s.idx.byGrant[grantID], matchChain(chainID)), nil
}

// matchChain accepts the opaque rows minted under chainID.
func matchChain(chainID string) func(*store.OpaqueAccessToken) bool {
	return func(r *store.OpaqueAccessToken) bool { return r.ChainID == chainID }
}

// RevokeByClient implements [store.RevokeByClient]. The DCR delete
// cascade probes for it so a deleted client takes its outstanding
// opaque access-token rows with it. A non-existent client is a
// no-op.
func (s *opaqueAccessTokenStore) RevokeByClient(_ context.Context, clientID string) error {
	if clientID == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	revokeIndexed(opaqueTokenRowOps, s.m, s.idx.byClient[clientID], matchAnyToken)
	return nil
}

// GC implements [store.OpaqueAccessTokenStore]. Drops every record
// whose ExpiresAt is strictly before cutoff. Records whose ExpiresAt
// is the zero time opt out of GC so callers cannot inadvertently drop
// a row that was registered without a TTL.
func (s *opaqueAccessTokenStore) GC(_ context.Context, cutoff time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return gcRows(opaqueTokenRowOps, s.m, s.idx, cutoff), nil
}

// opaqueTokenRowOps adapts [store.OpaqueAccessToken] to the shared token-row helpers.
//
//nolint:gochecknoglobals // field accessors; immutable after package init.
var opaqueTokenRowOps = tokenRowOps[*store.OpaqueAccessToken]{
	grantID:    func(r *store.OpaqueAccessToken) string { return r.GrantID },
	clientID:   func(r *store.OpaqueAccessToken) string { return r.ClientID },
	expiresAt:  func(r *store.OpaqueAccessToken) time.Time { return r.ExpiresAt },
	revoked:    func(r *store.OpaqueAccessToken) bool { return r.Revoked },
	setRevoked: func(r *store.OpaqueAccessToken) { r.Revoked = true },
}

// overlay returns the transactional view of the store; a commit keeps the
// grant and client indexes in step with the rows it writes and drops.
func (s *opaqueAccessTokenStore) overlay() *overlay[*store.OpaqueAccessToken] {
	o := newOverlay(s.m, cloneOpaqueAccessToken)
	o.onPut = func(key string, rec *store.OpaqueAccessToken) { opaqueTokenRowOps.track(s.idx, key, rec) }
	o.onDrop = func(key string, rec *store.OpaqueAccessToken) { opaqueTokenRowOps.untrack(s.idx, key, rec) }
	return o
}

func cloneOpaqueAccessToken(rec *store.OpaqueAccessToken) *store.OpaqueAccessToken {
	if rec == nil {
		return nil
	}
	out := *rec
	out.Scope = slices.Clone(rec.Scope)
	out.AMR = slices.Clone(rec.AMR)
	out.AuthorizationDetails = cloneObjectArray(rec.AuthorizationDetails)
	out.Claims = cloneMap(rec.Claims)
	return &out
}
