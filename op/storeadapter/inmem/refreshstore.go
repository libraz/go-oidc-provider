package inmem

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// --- RefreshTokenStore -------------------------------------------------------

type refreshStore struct {
	mu             sync.RWMutex
	clock          Clock
	m              map[string]*store.RefreshToken
	byClient       refreshIndex
	byGrant        refreshIndex
	byParent       refreshIndex
	retries        map[string]retryResponse
	retriesSinceGC uint32
}

// retryResponse is one sealed token response held for the RFC 9700
// delivery grace window, keyed by the hashed predecessor the client
// would re-present. expiresAt is the predecessor's own refresh-token
// expiry: [store.RefreshRetryResponseStore] forbids retaining the bytes
// past it, so the entry carries the bound rather than deriving it from
// whichever record happens to still be in the map at read time.
type retryResponse struct {
	sealed    []byte
	expiresAt time.Time
}

// retryResponseFullGCSaveInterval is how many retryable rotations pass
// between full sweeps of the retry map. Every rotation adds an entry and
// none of them is ever read more than once, so the map needs reclamation;
// sweeping on each rotation would make every refresh cost O(total
// entries).
const retryResponseFullGCSaveInterval uint32 = 64

// retryReclaimable reports whether a sealed retry response may be dropped.
// Both paths that decide retention — the read that serves a retry and the
// amortised sweep — consult this one predicate, so the store can never
// serve bytes the sweep has already judged dead, nor keep bytes no read
// would return. A predecessor that carried no expiry (zero) opts out of
// expiry exactly as its own record does under Find.
func retryReclaimable(rec retryResponse, now time.Time) bool {
	return isExpiredAtStrict(rec.expiresAt, now)
}

func newRefreshStore(c Clock) *refreshStore {
	return &refreshStore{
		clock:    c,
		m:        make(map[string]*store.RefreshToken),
		byClient: make(refreshIndex),
		byGrant:  make(refreshIndex),
		byParent: make(refreshIndex),
		retries:  make(map[string]retryResponse),
	}
}

func (s *refreshStore) Save(_ context.Context, token *store.RefreshToken) error {
	if token == nil {
		return errors.New("inmem: nil refresh token")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hashKey(token.ID)
	if _, exists := s.m[key]; exists {
		return store.ErrAlreadyExists
	}
	// Close the replay-revocation TOCTOU (RFC 9700 §2.2.2): a rotation
	// Save and a concurrent RevokeChain both take this mutex, so the
	// parent-still-alive check below and the insert form a single
	// critical section that no chain-revocation walk can interleave. If
	// the parent link was already tombstoned by a racing cascade, the
	// rotated descendant descends from a revoked chain and MUST NOT
	// become redeemable, so the row is never inserted and the caller is
	// told the chain is retired — see [store.RefreshTokenStore.Save].
	// The happy-path parent (consumed by legitimate rotation,
	// Revoked == false) is untouched, and a parent that is absent
	// altogether proves no revocation.
	if err := s.assertParentAliveLocked(token.ParentID); err != nil {
		return err
	}
	stored := storeRefresh(token, key)
	s.m[key] = stored
	s.indexRefreshLocked(key, stored)
	return nil
}

// SaveRotationWithRetry persists a successor and its sealed retry response in
// one mutex-held critical section. The retry key is the hashed predecessor, so
// an in-memory dump cannot turn the lookup key into a bearer credential.
func (s *refreshStore) SaveRotationWithRetry(_ context.Context, token *store.RefreshToken, sealed []byte) error {
	if token == nil || token.ParentID == nil || len(sealed) == 0 {
		return errors.New("inmem: retryable refresh rotation requires successor, parent, and sealed response")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hashKey(token.ID)
	if _, exists := s.m[key]; exists {
		return store.ErrAlreadyExists
	}
	if err := s.assertParentAliveLocked(token.ParentID); err != nil {
		return err
	}
	parentKey := hashKey(*token.ParentID)
	stored := storeRefresh(token, key)
	s.m[key] = stored
	s.indexRefreshLocked(key, stored)
	s.maybeGCRetriesLocked(s.clock.Now())
	s.retries[parentKey] = retryResponse{
		sealed:    append([]byte(nil), sealed...),
		expiresAt: retryRetention(s.m[parentKey], token),
	}
	return nil
}

// retryRetention returns the instant past which the sealed response
// belonging to predecessor must no longer be served. The predecessor's
// own ExpiresAt is that bound. A predecessor the store cannot resolve
// (nil) leaves no expiry to read, so the successor's own bounds the
// entry instead: a rotation never dates its successor earlier than the
// token it replaces, so the fallback over-retains and never
// under-retains.
func retryRetention(predecessor, successor *store.RefreshToken) time.Time {
	if predecessor != nil {
		return predecessor.ExpiresAt
	}
	return successor.ExpiresAt
}

// gcRetriesLocked drops every sealed retry response whose predecessor has
// expired. LoadRetryResponse already refuses to serve them, so the sweep
// cannot change what a caller observes; without it a long-running process
// would accumulate one encrypted token response per rotation for the
// lifetime of the process. The caller must hold refreshStore.mu for
// writing.
func (s *refreshStore) gcRetriesLocked(now time.Time) {
	for key, rec := range s.retries {
		if retryReclaimable(rec, now) {
			delete(s.retries, key)
		}
	}
	s.retriesSinceGC = 0
}

func (s *refreshStore) maybeGCRetriesLocked(now time.Time) {
	s.retriesSinceGC++
	if !sweepDue(s.retriesSinceGC, retryResponseFullGCSaveInterval, len(s.retries)) {
		return
	}
	s.gcRetriesLocked(now)
}

// assertParentAliveLocked reports [store.ErrAlreadyConsumed] when parentID
// names a record that a revocation cascade has already tombstoned, so a
// rotation can never extend a retired chain (RFC 9700 §2.2.2). A root save
// (nil parentID) and a parent that no longer exists both pass: neither is
// evidence of a revocation. The caller must hold refreshStore.mu for
// writing.
func (s *refreshStore) assertParentAliveLocked(parentID *string) error {
	if parentID == nil {
		return nil
	}
	if parent, ok := s.m[hashKey(*parentID)]; ok && parent.Revoked {
		return store.ErrAlreadyConsumed
	}
	return nil
}

// LoadRetryResponse returns the sealed response held against
// predecessorID, or [store.ErrNotFound] once the predecessor's own
// lifetime is over: the grace window exists to re-deliver a response the
// client can still use, and a refresh token past its expiry is one the
// endpoint would refuse anyway.
func (s *refreshStore) LoadRetryResponse(_ context.Context, predecessorID string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.retries[hashKey(predecessorID)]
	if !ok || retryReclaimable(rec, s.clock.Now()) {
		return nil, store.ErrNotFound
	}
	return append([]byte(nil), rec.sealed...), nil
}

func (s *refreshStore) Find(_ context.Context, id string) (*store.RefreshToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := hashKey(id)
	rec, ok := s.m[key]
	if !ok {
		return nil, store.ErrNotFound
	}
	if !constantTimeKeyMatch(rec.ID, key) {
		return nil, store.ErrNotFound
	}
	if isExpired(rec.ExpiresAt, s.clock) {
		return nil, store.ErrNotFound
	}
	out := cloneRefresh(rec)
	out.ID = id
	return out, nil
}

func (s *refreshStore) Consume(_ context.Context, id string) (*store.RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hashKey(id)
	rec, ok := s.m[key]
	if !ok {
		return nil, store.ErrNotFound
	}
	if !constantTimeKeyMatch(rec.ID, key) {
		return nil, store.ErrNotFound
	}
	if isExpired(rec.ExpiresAt, s.clock) {
		return nil, store.ErrNotFound
	}
	if rec.ConsumedAt != nil {
		out := cloneRefresh(rec)
		out.ID = id
		return out, store.ErrAlreadyConsumed
	}
	now := s.clock.Now()
	rec.ConsumedAt = &now
	out := cloneRefresh(rec)
	out.ID = id
	return out, nil
}

func (s *refreshStore) RevokeChain(_ context.Context, rootID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rootKey := hashKey(rootID)
	if _, ok := s.m[rootKey]; !ok {
		return store.ErrNotFound
	}
	now := s.clock.Now()
	s.revokeChainLocked(rootKey, now)
	return nil
}

// storeRefresh produces the in-memory representation of token: a clone
// with the raw ID replaced by its hash key. Storing the digest as the
// map key means a snapshot of the underlying map (heap dump, debugger
// inspection) cannot reconstruct the bearer secret the OP issued.
// ParentID is left as the raw parent identifier so callers reading the
// record back via Find / Consume see the same value they passed in;
// [refreshStore.indexRefreshLocked] hashes it into the parent index.
func storeRefresh(token *store.RefreshToken, key string) *store.RefreshToken {
	stored := cloneRefresh(token)
	stored.ID = key
	return stored
}

func (s *refreshStore) RevokeByGrant(_ context.Context, grantID string) error {
	if grantID == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock.Now()
	s.revokeByGrantLocked(grantID, now)
	return nil
}

// RevokeByClient implements [store.RevokeByClient]. Used by the
// dynamic registration cascade so a deleted client takes its
// outstanding refresh tokens with it.
func (s *refreshStore) RevokeByClient(_ context.Context, clientID string) error {
	if clientID == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock.Now()
	s.revokeByClientLocked(clientID, now)
	return nil
}

// refreshIndex maps one stable record attribute (client, grant, or hashed
// parent key) to the hashed primary keys carrying that value. Refresh-token rows are retained after revocation for
// replay detection and audit, so their immutable ClientID, GrantID and ParentID entries
// have the same lifetime as the primary map entry.
type refreshIndex map[string]map[string]struct{}

func (i refreshIndex) add(value, id string) {
	if value == "" {
		return
	}
	ids := i[value]
	if ids == nil {
		ids = make(map[string]struct{})
		i[value] = ids
	}
	ids[id] = struct{}{}
}

// indexRefreshLocked adds rec to every applicable secondary index. The caller
// must hold refreshStore.mu for writing, either directly or through a
// transaction that owns the full atomic-cluster lock set.
func (s *refreshStore) indexRefreshLocked(id string, rec *store.RefreshToken) {
	s.byClient.add(rec.ClientID, id)
	s.byGrant.add(rec.GrantID, id)
	if rec.ParentID != nil {
		s.byParent.add(hashKey(*rec.ParentID), id)
	}
}

func (s *refreshStore) revokeByGrantLocked(grantID string, now time.Time) int {
	return s.revokeByIndexLocked(s.byGrant, grantID, now)
}

func (s *refreshStore) revokeByClientLocked(clientID string, now time.Time) int {
	return s.revokeByIndexLocked(s.byClient, clientID, now)
}

// revokeByIndexLocked marks exactly the primary rows named by index[value].
// Returning the visited-row count gives deterministic complexity tests a
// timing-independent way to prove that unrelated rows are never traversed.
// The caller must hold refreshStore.mu for writing.
func (s *refreshStore) revokeByIndexLocked(index refreshIndex, value string, now time.Time) int {
	visited := 0
	for id := range index[value] {
		rec, ok := s.m[id]
		if !ok {
			continue
		}
		markRevoked(rec, now)
		visited++
	}
	return visited
}

// revokeChainLocked stamps rootKey and every descendant consumed and
// revoked, following the parent index breadth-first so the cost is
// proportional to the chain rather than to the whole map. A descendant is
// reached through its parent's key whether or not the parent row is still
// present. The caller must hold refreshStore.mu for writing.
func (s *refreshStore) revokeChainLocked(rootKey string, now time.Time) {
	markRevoked(s.m[rootKey], now)
	seen := map[string]struct{}{rootKey: {}}
	queue := []string{rootKey}
	for len(queue) > 0 {
		parentKey := queue[0]
		queue = queue[1:]
		for childKey := range s.byParent[parentKey] {
			if _, done := seen[childKey]; done {
				continue
			}
			seen[childKey] = struct{}{}
			markRevoked(s.m[childKey], now)
			queue = append(queue, childKey)
		}
	}
}

// markRevoked stamps rec as both consumed and revoked. The Revoked
// flag distinguishes "consumed via legitimate rotation" (eligible for
// the RFC 9700 §2.2.2 grace window) from "retired by chain
// revocation" (never grace-eligible). rec may be nil; in that case
// the call is a no-op.
func markRevoked(rec *store.RefreshToken, now time.Time) {
	if rec == nil {
		return
	}
	if rec.ConsumedAt == nil {
		t := now
		rec.ConsumedAt = &t
	}
	rec.Revoked = true
}

func cloneRefresh(t *store.RefreshToken) *store.RefreshToken {
	if t == nil {
		return nil
	}
	out := *t
	out.Scope = slices.Clone(t.Scope)
	out.Resource = t.Resource
	out.AMR = slices.Clone(t.AMR)
	out.AuthorizationDetails = cloneObjectArray(t.AuthorizationDetails)
	out.Claims = cloneMap(t.Claims)
	out.AccessTokenExtra = cloneMap(t.AccessTokenExtra)
	if t.ParentID != nil {
		p := *t.ParentID
		out.ParentID = &p
	}
	if t.ConsumedAt != nil {
		c := *t.ConsumedAt
		out.ConsumedAt = &c
	}
	return &out
}
