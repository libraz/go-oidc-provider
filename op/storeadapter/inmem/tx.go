package inmem

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"sync/atomic"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// errTxClosed is returned by tx substores once the transaction has committed
// or rolled back. The library treats this as a programming error: a handler
// path that holds onto a Tx after Commit/Rollback is buggy. It wraps
// [store.ErrTxRequired] so embedders can match the closed-handle case with
// [errors.Is] uniformly across backends, as [store.Tx] requires.
var errTxClosed = fmt.Errorf("inmem: transaction already closed: %w", store.ErrTxRequired)

// tx is the in-memory implementation of [store.Tx]. It buffers writes against
// staging maps while owning every atomic-cluster substore mutex. Commit applies
// all staged writes before releasing any mutex; Rollback discards them before
// releasing the same lock set. The owning Store's txMu is also held for the
// lifetime of the tx so two transactions never acquire the cluster together.
type tx struct {
	owner *Store
	clock Clock

	closed atomic.Bool

	acStaging  *authCodeStaging
	rtStaging  *refreshStaging
	grStaging  *grantStaging
	parStaging *parStaging
	atStaging  *overlay[*store.AccessTokenRecord]
	oatStaging *overlay[*store.OpaqueAccessToken]
	grvStaging *grantRevocationStaging
}

// guard reports the error a substore call must return before touching
// staging: the closed-handle sentinel, or the context's own error.
func (t *tx) guard(ctx context.Context) error {
	if t.closed.Load() {
		return errTxClosed
	}
	return ctx.Err()
}

// AuthorizationCodes returns the transactional authorization-code substore.
func (t *tx) AuthorizationCodes() store.AuthorizationCodeStore {
	return &txAuthCodes{tx: t}
}

// RefreshTokens returns the transactional refresh-token substore.
func (t *tx) RefreshTokens() store.RefreshTokenStore {
	return &txRefreshes{tx: t}
}

// Grants returns the transactional grant substore.
func (t *tx) Grants() store.GrantStore {
	return &txGrants{tx: t}
}

// PushedAuthRequests returns the transactional PAR substore.
func (t *tx) PushedAuthRequests() store.PushedAuthRequestStore {
	return &txPARs{tx: t}
}

func (t *tx) AccessTokens() store.AccessTokenRegistry {
	return txAccessTokens{tx: t}
}

func (t *tx) OpaqueAccessTokens() store.OpaqueAccessTokenStore {
	return txOpaqueAccessTokens{tx: t}
}

func (t *tx) GrantRevocations() store.GrantRevocationStore {
	return txGrantRevocations{tx: t}
}

// Commit flushes every staged write to the owning Store and releases the tx
// mutex. After Commit the tx is closed; further substore calls return an
// error.
func (t *tx) Commit() error {
	if !t.closed.CompareAndSwap(false, true) {
		return errTxClosed
	}
	defer t.releaseLocks()
	t.acStaging.flushLocked()
	t.rtStaging.flushLocked()
	t.grStaging.flushLocked()
	t.parStaging.flushLocked()
	t.atStaging.flushLocked()
	t.oatStaging.flushLocked()
	t.grvStaging.flushLocked()
	return nil
}

// Rollback discards every staged write and releases the tx mutex. Rollback is
// safe to call after Commit; subsequent calls are no-ops.
//
// The staging maps are cleared before the mutex is released so any
// pointer the caller retained into a staged record is severed: a buggy
// caller that holds onto a [store.AuthorizationCode] pointer obtained
// inside the tx and mutates it after Rollback can no longer corrupt
// future transactions, and the freed slots are eligible for GC
// immediately rather than on the next BeginTx.
func (t *tx) Rollback() error {
	if !t.closed.CompareAndSwap(false, true) {
		// Per godoc, Rollback after Commit is a deliberate no-op.
		return nil
	}
	t.clearStaging()
	t.releaseLocks()
	return nil
}

func (t *tx) releaseLocks() {
	t.owner.unlockTxCluster()
	t.owner.txMu.Unlock()
}

// clearStaging drops every staged add / update / delete map entry so a
// rolled-back tx surrenders its temporary pointers eagerly. The
// helper runs both on Rollback (where staging would otherwise be
// reachable through the tx struct itself until GC sweeps the closed
// transaction) and from the race tests that pin the same property
// under concurrent commits.
func (t *tx) clearStaging() {
	if t.acStaging != nil {
		clear(t.acStaging.added)
		clear(t.acStaging.updated)
	}
	if t.rtStaging != nil {
		clear(t.rtStaging.added)
		clear(t.rtStaging.updated)
		clear(t.rtStaging.byParent)
		clear(t.rtStaging.byGrant)
		clear(t.rtStaging.revoked)
		clear(t.rtStaging.retries)
	}
	if t.grStaging != nil {
		clear(t.grStaging.added)
		clear(t.grStaging.deleted)
	}
	if t.parStaging != nil {
		clear(t.parStaging.added)
		clear(t.parStaging.updated)
	}
	if t.atStaging != nil {
		t.atStaging.clear()
	}
	if t.oatStaging != nil {
		t.oatStaging.clear()
	}
	if t.grvStaging != nil {
		t.grvStaging.clear()
	}
}

// --- staging: authorization codes -------------------------------------------

type authCodeStaging struct {
	parent  *authCodeStore
	added   map[string]*store.AuthorizationCode
	updated map[string]*store.AuthorizationCode
}

func (s *authCodeStaging) flushLocked() {
	maps.Copy(s.parent.m, s.added)
	maps.Copy(s.parent.m, s.updated)
	// The browser authorization-code flow persists every code inside a
	// transaction, so the amortised sweep has to be driven from here as
	// well: counting only the direct Save path would leave the map
	// unreclaimed on the one route an unauthenticated request can grow
	// without limit. The sweep runs after the staged writes land so it
	// judges the map the transaction actually committed.
	s.parent.maybeGCLocked(s.parent.clock.Now())
}

type txAuthCodes struct{ tx *tx }

func (a *txAuthCodes) Save(ctx context.Context, code *store.AuthorizationCode) error {
	if err := a.tx.guard(ctx); err != nil {
		return err
	}
	if code == nil {
		return errors.New("inmem: nil authorization code")
	}
	st := a.tx.acStaging
	key := hashKey(code.ID)
	if _, exists := st.added[key]; exists {
		return store.ErrAlreadyExists
	}
	_, parentExists := st.parent.m[key]
	if parentExists {
		return store.ErrAlreadyExists
	}
	stored := cloneAuthCode(code)
	stored.ID = key
	st.added[key] = stored
	return nil
}

func (a *txAuthCodes) Find(ctx context.Context, id string) (*store.AuthorizationCode, error) {
	if err := a.tx.guard(ctx); err != nil {
		return nil, err
	}
	rec := a.tx.acStaging.lookup(hashKey(id))
	if rec == nil {
		return nil, store.ErrNotFound
	}
	if isExpired(rec.ExpiresAt, a.tx.clock) {
		return nil, store.ErrNotFound
	}
	out := cloneAuthCode(rec)
	out.ID = id
	return out, nil
}

func (a *txAuthCodes) Consume(ctx context.Context, id string) (*store.AuthorizationCode, error) {
	if err := a.tx.guard(ctx); err != nil {
		return nil, err
	}
	st := a.tx.acStaging
	key := hashKey(id)
	rec := st.lookup(key)
	if rec == nil {
		return nil, store.ErrNotFound
	}
	if isExpired(rec.ExpiresAt, a.tx.clock) {
		return nil, store.ErrNotFound
	}
	if rec.ConsumedAt != nil {
		out := cloneAuthCode(rec)
		out.ID = id
		return out, store.ErrAlreadyConsumed
	}
	updated := cloneAuthCode(rec)
	now := a.tx.clock.Now()
	updated.ConsumedAt = &now
	updated.ID = key
	st.updated[key] = updated
	out := cloneAuthCode(updated)
	out.ID = id
	return out, nil
}

// lookup returns a snapshot, so a later mutation via Consume is confined
// to staging.
func (s *authCodeStaging) lookup(key string) *store.AuthorizationCode {
	return stagedLookup(key, s.updated, s.added, s.parent.m, cloneAuthCode)
}

// stagedLookup resolves key against the updated overlay, then the added
// one, then a clone of the committed record; it returns nil when none
// holds it.
func stagedLookup[V *T, T any](key string, updated, added, base map[string]V, clone func(V) V) V {
	if rec, ok := updated[key]; ok {
		return rec
	}
	if rec, ok := added[key]; ok {
		return rec
	}
	if rec, ok := base[key]; ok {
		return clone(rec)
	}
	return nil
}

// --- staging: refresh tokens -------------------------------------------------

type refreshStaging struct {
	parent   *refreshStore
	added    map[string]*store.RefreshToken
	updated  map[string]*store.RefreshToken
	byGrant  refreshIndex
	byParent refreshIndex             // hashed parent key -> staged child keys
	revoked  map[string]struct{}      // chain roots whose descendants must be revoked at flush
	retries  map[string]retryResponse // hashed predecessor -> sealed response
}

func (s *refreshStaging) flushLocked() {
	for id, rec := range s.added {
		s.parent.m[id] = rec
		s.parent.indexRefreshLocked(id, rec)
	}
	for id, rec := range s.updated {
		s.parent.m[id] = rec
	}
	for parent, rec := range s.retries {
		s.parent.retries[parent] = retryResponse{
			sealed:    bytes.Clone(rec.sealed),
			expiresAt: rec.expiresAt,
		}
	}
	// Rotation runs inside a transaction in production, so the amortised
	// sweep of the retry map has to be driven from here as well: counting
	// only the direct SaveRotationWithRetry path would leave the map
	// unreclaimed on the one route the token endpoint actually takes. The
	// sweep runs after the staged entries land so it judges the map the
	// transaction committed.
	if len(s.retries) > 0 {
		s.parent.maybeGCRetriesLocked(s.parent.clock.Now())
	}
	if len(s.revoked) > 0 {
		now := s.parent.clock.Now()
		for root := range s.revoked {
			// At flush time, traverse the now-merged map to revoke
			// descendants. The chain root itself is already marked via
			// updated; revokeChainLocked is idempotent.
			s.parent.revokeChainLocked(root, now)
		}
	}
}

type txRefreshes struct{ tx *tx }

func (r *txRefreshes) Save(ctx context.Context, token *store.RefreshToken) error {
	if err := r.tx.guard(ctx); err != nil {
		return err
	}
	if token == nil {
		return errors.New("inmem: nil refresh token")
	}
	st := r.tx.rtStaging
	key := hashKey(token.ID)
	if _, exists := st.added[key]; exists {
		return store.ErrAlreadyExists
	}
	_, parentExists := st.parent.m[key]
	if parentExists {
		return store.ErrAlreadyExists
	}
	// Mirror the non-transactional guard (RFC 9700 §2.2.2): a rotation
	// whose parent link has already been tombstoned descends from a
	// revoked chain and must never become redeemable. The transaction
	// owns the whole atomic cluster, so the staged view is the
	// authoritative one and the check cannot be raced.
	if token.ParentID != nil {
		if parent := st.lookup(hashKey(*token.ParentID)); parent != nil && parent.Revoked {
			return store.ErrAlreadyConsumed
		}
	}
	stored := storeRefresh(token, key)
	st.added[key] = stored
	st.byGrant.add(stored.GrantID, key)
	if stored.ParentID != nil {
		st.byParent.add(hashKey(*stored.ParentID), key)
	}
	return nil
}

func (r *txRefreshes) SaveRotationWithRetry(ctx context.Context, token *store.RefreshToken, sealed []byte) error {
	if r.tx.closed.Load() {
		return errTxClosed
	}
	if token == nil || token.ParentID == nil || len(sealed) == 0 {
		return errors.New("inmem: retryable refresh rotation requires successor, parent, and sealed response")
	}
	if err := r.Save(ctx, token); err != nil {
		return err
	}
	st := r.tx.rtStaging
	parentKey := hashKey(*token.ParentID)
	st.retries[parentKey] = retryResponse{
		sealed:    bytes.Clone(sealed),
		expiresAt: retryRetention(st.lookup(parentKey), token),
	}
	return nil
}

// LoadRetryResponse reads the staged view first so a rotation sees the
// response it just sealed, then the committed map. Both answers are held
// to the same retention bound as the non-transactional read: past the
// predecessor's own expiry the entry reads as absent.
func (r *txRefreshes) LoadRetryResponse(ctx context.Context, predecessorID string) ([]byte, error) {
	if err := r.tx.guard(ctx); err != nil {
		return nil, err
	}
	key := hashKey(predecessorID)
	rec, ok := r.tx.rtStaging.retries[key]
	if !ok {
		rec, ok = r.tx.rtStaging.parent.retries[key]
	}
	if !ok || retryReclaimable(rec, r.tx.clock.Now()) {
		return nil, store.ErrNotFound
	}
	return bytes.Clone(rec.sealed), nil
}

func (r *txRefreshes) Find(ctx context.Context, id string) (*store.RefreshToken, error) {
	if err := r.tx.guard(ctx); err != nil {
		return nil, err
	}
	rec := r.tx.rtStaging.lookup(hashKey(id))
	if rec == nil {
		return nil, store.ErrNotFound
	}
	if isExpired(rec.ExpiresAt, r.tx.clock) {
		return nil, store.ErrNotFound
	}
	out := cloneRefresh(rec)
	out.ID = id
	return out, nil
}

func (r *txRefreshes) Consume(ctx context.Context, id string) (*store.RefreshToken, error) {
	if err := r.tx.guard(ctx); err != nil {
		return nil, err
	}
	st := r.tx.rtStaging
	key := hashKey(id)
	rec := st.lookup(key)
	if rec == nil {
		return nil, store.ErrNotFound
	}
	if isExpired(rec.ExpiresAt, r.tx.clock) {
		return nil, store.ErrNotFound
	}
	if rec.ConsumedAt != nil {
		// Return the consumed record alongside the sentinel so the
		// replay path can recover the chain root, matching
		// [store.RefreshTokenStore.Consume] and refreshStore.Consume.
		out := cloneRefresh(rec)
		out.ID = id
		return out, store.ErrAlreadyConsumed
	}
	updated := cloneRefresh(rec)
	now := r.tx.clock.Now()
	updated.ConsumedAt = &now
	updated.ID = key
	st.updated[key] = updated
	out := cloneRefresh(updated)
	out.ID = id
	return out, nil
}

func (r *txRefreshes) RevokeChain(ctx context.Context, rootID string) error {
	if err := r.tx.guard(ctx); err != nil {
		return err
	}
	st := r.tx.rtStaging
	rootKey := hashKey(rootID)
	rec := st.lookup(rootKey)
	if rec == nil {
		return store.ErrNotFound
	}
	// Stamp the root immediately and queue chain traversal for flush time
	// so we can see records added later in the same tx. The stamp sets
	// Revoked as well as ConsumedAt: a read issued through this same Tx
	// must observe the tombstone the transaction just wrote, and the
	// flag is what separates "retired by cascade" from "consumed by
	// legitimate rotation" on the grace path.
	now := r.tx.clock.Now()
	updated := cloneRefresh(rec)
	markRevoked(updated, now)
	updated.ID = rootKey
	st.updated[rootKey] = updated
	st.revoked[rootKey] = struct{}{}
	// Apply chain marking against the staging view so callers within the
	// same tx see revoked descendants.
	st.markChainStaged(rootKey, now)
	return nil
}

func (r *txRefreshes) RevokeByGrant(ctx context.Context, grantID string) error {
	if err := r.tx.guard(ctx); err != nil {
		return err
	}
	if grantID == "" {
		return nil
	}
	st := r.tx.rtStaging
	now := r.tx.clock.Now()
	st.revokeIDs(st.parent.byGrant[grantID], now)
	st.revokeIDs(st.byGrant[grantID], now)
	return nil
}

func (s *refreshStaging) revokeIDs(ids map[string]struct{}, now time.Time) {
	for id := range ids {
		rec := s.lookup(id)
		if rec == nil {
			continue
		}
		updated := cloneRefresh(rec)
		if updated.ConsumedAt == nil {
			t := now
			updated.ConsumedAt = &t
		}
		updated.Revoked = true
		updated.ID = id // id here is the hashed key (matches the map key contract).
		s.updated[id] = updated
	}
}

// markChainStaged walks the in-memory view (parent + staging) breadth-first
// from rootID and stamps every descendant consumed + revoked. It is called at
// RevokeChain time so that reads inside the same tx see the revocations in
// full. Children come from the committed parent index plus the staged one, so
// the cost follows the chain rather than the whole map.
func (s *refreshStaging) markChainStaged(rootID string, now time.Time) {
	seen := map[string]struct{}{rootID: {}}
	queue := []string{rootID}
	for len(queue) > 0 {
		parentKey := queue[0]
		queue = queue[1:]
		for _, children := range []map[string]struct{}{s.parent.byParent[parentKey], s.byParent[parentKey]} {
			for id := range children {
				if _, done := seen[id]; done {
					continue
				}
				seen[id] = struct{}{}
				queue = append(queue, id)
				rec := s.lookup(id)
				if rec == nil {
					continue
				}
				updated := cloneRefresh(rec)
				markRevoked(updated, now)
				updated.ID = id
				s.updated[id] = updated
			}
		}
	}
}

func (s *refreshStaging) lookup(id string) *store.RefreshToken {
	return stagedLookup(id, s.updated, s.added, s.parent.m, cloneRefresh)
}

// --- staging: grants ---------------------------------------------------------

type grantStaging struct {
	parent  *grantStore
	added   map[string]*store.Grant
	deleted map[string]struct{}
}

func (s *grantStaging) flushLocked() {
	for id := range s.deleted {
		delete(s.parent.m, id)
	}
	for id, rec := range s.added {
		s.parent.m[id] = rec
	}
}

type txGrants struct{ tx *tx }

func (g *txGrants) Save(ctx context.Context, gr *store.Grant) error {
	if err := g.tx.guard(ctx); err != nil {
		return err
	}
	if gr == nil {
		return errors.New("inmem: nil grant")
	}
	st := g.tx.grStaging
	delete(st.deleted, gr.ID)
	st.added[gr.ID] = cloneGrant(gr)
	return nil
}

func (g *txGrants) Find(ctx context.Context, id string) (*store.Grant, error) {
	if err := g.tx.guard(ctx); err != nil {
		return nil, err
	}
	st := g.tx.grStaging
	if _, deleted := st.deleted[id]; deleted {
		return nil, store.ErrNotFound
	}
	if rec, ok := st.added[id]; ok {
		return cloneGrant(rec), nil
	}
	if rec, ok := st.parent.m[id]; ok {
		return cloneGrant(rec), nil
	}
	return nil, store.ErrNotFound
}

func (g *txGrants) FindBySubjectClient(ctx context.Context, subject, clientID string) (*store.Grant, error) {
	if err := g.tx.guard(ctx); err != nil {
		return nil, err
	}
	best := g.tx.grStaging.findLatestMatching(subject, clientID)
	if best == nil {
		return nil, store.ErrNotFound
	}
	return cloneGrant(best), nil
}

// findLatestMatching scans the staged view (parent + added - deleted) and
// returns the grant with the most recent UpdatedAt that matches (subject,
// clientID), or nil if none matches. It is the staging-aware counterpart to
// [grantStore.FindBySubjectClient].
func (s *grantStaging) findLatestMatching(subject, clientID string) *store.Grant {
	var best *store.Grant
	s.each(func(rec *store.Grant) bool {
		if rec.Subject != subject || rec.ClientID != clientID {
			return true
		}
		if best == nil || rec.UpdatedAt.After(best.UpdatedAt) {
			best = rec
		}
		return true
	})
	return best
}

// each calls fn for every grant visible in the staged view: the staged adds
// plus the parent rows that are neither deleted nor overridden by an add.
// fn returns false to stop the walk.
func (s *grantStaging) each(fn func(*store.Grant) bool) {
	for id, rec := range s.added {
		if _, deleted := s.deleted[id]; deleted {
			continue
		}
		if !fn(rec) {
			return
		}
	}
	for id, rec := range s.parent.m {
		if _, deleted := s.deleted[id]; deleted {
			continue
		}
		if _, override := s.added[id]; override {
			continue
		}
		if !fn(rec) {
			return
		}
	}
}

// ListBySubject mirrors [grantStore.ListBySubject] over the staged
// view: it walks the parent map plus the per-tx added / deleted
// overlay and returns every active grant for the subject.
func (g *txGrants) ListBySubject(ctx context.Context, subject string) ([]*store.Grant, error) {
	if err := g.tx.guard(ctx); err != nil {
		return nil, err
	}
	grants := g.tx.grStaging.collectBySubject(subject)
	out := make([]*store.Grant, 0, len(grants))
	for _, rec := range grants {
		out = append(out, cloneGrant(rec))
	}
	return out, nil
}

func (g *txGrants) ListClientIDsBySubject(
	ctx context.Context,
	subject, cursor string,
	limit int,
) (store.GrantClientPage, error) {
	if err := g.tx.guard(ctx); err != nil {
		return store.GrantClientPage{}, err
	}
	if limit <= 0 {
		return store.GrantClientPage{}, errors.New("inmem: grant client page limit must be positive")
	}
	builder := newSortedPageBuilder(cursor, limit)
	g.tx.grStaging.addClientIDsBySubject(subject, builder)
	return builder.clientPage(), nil
}

func (g *txGrants) ListSubjectsByClient(
	ctx context.Context,
	clientID, cursor string,
	limit int,
) (store.GrantSubjectPage, error) {
	if err := g.tx.guard(ctx); err != nil {
		return store.GrantSubjectPage{}, err
	}
	if limit <= 0 {
		return store.GrantSubjectPage{}, errors.New("inmem: grant subject page limit must be positive")
	}
	builder := newSortedPageBuilder(cursor, limit)
	g.tx.grStaging.addSubjectsByClient(clientID, builder)
	return builder.subjectPage(), nil
}

// collectBySubject is the staging-aware companion to
// [grantStore.ListBySubject]: it walks the staged-add map and the
// parent map (already transaction-locked), filtering out deletes and per-tx
// overrides, and returns every active grant for the subject.
// The helper is split out so [txGrants.ListBySubject] stays under
// the project's gocognit cap.
func (s *grantStaging) collectBySubject(subject string) []*store.Grant {
	out := make([]*store.Grant, 0)
	s.each(func(rec *store.Grant) bool {
		if rec.Subject == subject {
			out = append(out, rec)
		}
		return true
	})
	return out
}

func (s *grantStaging) addClientIDsBySubject(
	subject string,
	builder *sortedPageBuilder,
) {
	s.each(func(rec *store.Grant) bool {
		if rec.Subject == subject {
			builder.add(rec.ClientID)
		}
		return true
	})
}

func (s *grantStaging) addSubjectsByClient(
	clientID string,
	builder *sortedPageBuilder,
) {
	s.each(func(rec *store.Grant) bool {
		if rec.ClientID == clientID {
			builder.add(rec.Subject)
		}
		return true
	})
}

func (g *txGrants) Delete(ctx context.Context, id string) error {
	if err := g.tx.guard(ctx); err != nil {
		return err
	}
	st := g.tx.grStaging
	_, inAdded := st.added[id]
	_, inParent := st.parent.m[id]
	if !inAdded && !inParent {
		return store.ErrNotFound
	}
	delete(st.added, id)
	st.deleted[id] = struct{}{}
	return nil
}

// HasAny mirrors [grantStore.HasAny] in the transactional view: a
// staged add counts even before commit, and a staged delete is
// honoured for parent rows that have not yet been flushed.
func (g *txGrants) HasAny(ctx context.Context) (bool, error) {
	if err := g.tx.guard(ctx); err != nil {
		return false, err
	}
	found := false
	g.tx.grStaging.each(func(*store.Grant) bool {
		found = true
		return false
	})
	return found, nil
}

// --- staging: PAR ------------------------------------------------------------

type parStaging struct {
	parent  *parStore
	added   map[string]*store.PushedAuthRequest
	updated map[string]*store.PushedAuthRequest
}

func (s *parStaging) flushLocked() {
	maps.Copy(s.parent.m, s.added)
	maps.Copy(s.parent.m, s.updated)
}

type txPARs struct{ tx *tx }

func (p *txPARs) Save(ctx context.Context, par *store.PushedAuthRequest) error {
	if err := p.tx.guard(ctx); err != nil {
		return err
	}
	if par == nil {
		return errors.New("inmem: nil pushed authorization request")
	}
	st := p.tx.parStaging
	key := hashKey(par.URI)
	if _, exists := st.added[key]; exists {
		return store.ErrAlreadyExists
	}
	parent, parentExists := st.parent.m[key]
	// A staged insert replaces the committed row under the same key, so
	// it is a reclamation path and answers to the same predicate as the
	// sweep: only a record past retention may be displaced.
	if parentExists && parReclaimable(parent, p.tx.clock.Now()) {
		parentExists = false
	}
	if parentExists {
		return store.ErrAlreadyExists
	}
	stored := clonePAR(par)
	stored.URI = key
	st.added[key] = stored
	return nil
}

func (p *txPARs) Find(ctx context.Context, uri string) (*store.PushedAuthRequest, error) {
	if err := p.tx.guard(ctx); err != nil {
		return nil, err
	}
	rec := p.tx.parStaging.lookup(hashKey(uri))
	if rec == nil {
		return nil, store.ErrNotFound
	}
	if isExpired(rec.ExpiresAt, p.tx.clock) {
		return nil, store.ErrNotFound
	}
	out := clonePAR(rec)
	out.URI = uri
	return out, nil
}

func (p *txPARs) Consume(ctx context.Context, uri string) (*store.PushedAuthRequest, error) {
	if err := p.tx.guard(ctx); err != nil {
		return nil, err
	}
	st := p.tx.parStaging
	key := hashKey(uri)
	rec := st.lookup(key)
	if rec == nil {
		return nil, store.ErrNotFound
	}
	// Consume enforces single-use only; expiry is gated at presentation
	// by Find (see store.PushedAuthRequestStore.Consume). An interactive
	// login that outlives the request_uri lifetime still redeems here,
	// matching the non-transactional parStore.Consume and the SQL adapter.
	if rec.ConsumedAt != nil {
		return nil, store.ErrAlreadyConsumed
	}
	updated := clonePAR(rec)
	now := p.tx.clock.Now()
	updated.ConsumedAt = &now
	updated.URI = key
	st.updated[key] = updated
	out := clonePAR(updated)
	out.URI = uri
	return out, nil
}

func (s *parStaging) lookup(key string) *store.PushedAuthRequest {
	return stagedLookup(key, s.updated, s.added, s.parent.m, clonePAR)
}
