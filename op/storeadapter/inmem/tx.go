package inmem

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// errTxClosed is returned by tx substores once the transaction has committed
// or rolled back. The library treats this as a programming error: a handler
// path that holds onto a Tx after Commit/Rollback is buggy.
var errTxClosed = errors.New("inmem: transaction already closed")

// tx is the in-memory implementation of [store.Tx]. It buffers writes against
// staging maps and flushes them under the owning Store's substore mutexes on
// Commit. Rollback discards the staged writes. The owning Store's txMu is
// held for the entire lifetime of the tx so that two transactions never run
// concurrently against the same backend.
type tx struct {
	owner *Store
	clock Clock

	closed atomic.Bool

	acStaging  *authCodeStaging
	rtStaging  *refreshStaging
	grStaging  *grantStaging
	parStaging *parStaging
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

// Commit flushes every staged write to the owning Store and releases the tx
// mutex. After Commit the tx is closed; further substore calls return an
// error.
func (t *tx) Commit() error {
	if !t.closed.CompareAndSwap(false, true) {
		return errTxClosed
	}
	defer t.owner.txMu.Unlock()
	t.acStaging.flush()
	t.rtStaging.flush()
	t.grStaging.flush()
	t.parStaging.flush()
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
	t.owner.txMu.Unlock()
	return nil
}

// clearStaging drops every staged add / update / delete map entry so a
// rolled-back tx surrenders its temporary pointers eagerly. The
// helper runs both on Rollback (where staging would otherwise be
// reachable through the tx struct itself until GC sweeps the closed
// transaction) and as part of the race-test surface for F-11.
func (t *tx) clearStaging() {
	if t.acStaging != nil {
		clear(t.acStaging.added)
		clear(t.acStaging.updated)
	}
	if t.rtStaging != nil {
		clear(t.rtStaging.added)
		clear(t.rtStaging.updated)
		clear(t.rtStaging.revoked)
	}
	if t.grStaging != nil {
		clear(t.grStaging.added)
		clear(t.grStaging.deleted)
	}
	if t.parStaging != nil {
		clear(t.parStaging.added)
		clear(t.parStaging.updated)
	}
}

// --- staging: authorization codes -------------------------------------------

type authCodeStaging struct {
	parent  *authCodeStore
	added   map[string]*store.AuthorizationCode
	updated map[string]*store.AuthorizationCode
}

func (s *authCodeStaging) flush() {
	s.parent.mu.Lock()
	defer s.parent.mu.Unlock()
	for id, rec := range s.added {
		s.parent.m[id] = rec
	}
	for id, rec := range s.updated {
		s.parent.m[id] = rec
	}
}

type txAuthCodes struct{ tx *tx }

func (a *txAuthCodes) Save(ctx context.Context, code *store.AuthorizationCode) error {
	if a.tx.closed.Load() {
		return errTxClosed
	}
	if err := ctx.Err(); err != nil {
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
	st.parent.mu.RLock()
	_, parentExists := st.parent.m[key]
	st.parent.mu.RUnlock()
	if parentExists {
		return store.ErrAlreadyExists
	}
	stored := cloneAuthCode(code)
	stored.ID = key
	st.added[key] = stored
	return nil
}

func (a *txAuthCodes) Find(ctx context.Context, id string) (*store.AuthorizationCode, error) {
	if a.tx.closed.Load() {
		return nil, errTxClosed
	}
	if err := ctx.Err(); err != nil {
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
	if a.tx.closed.Load() {
		return nil, errTxClosed
	}
	if err := ctx.Err(); err != nil {
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

func (s *authCodeStaging) lookup(key string) *store.AuthorizationCode {
	if rec, ok := s.updated[key]; ok {
		return rec
	}
	if rec, ok := s.added[key]; ok {
		return rec
	}
	s.parent.mu.RLock()
	defer s.parent.mu.RUnlock()
	if rec, ok := s.parent.m[key]; ok {
		// Return a snapshot so subsequent mutations via Consume are
		// confined to staging.
		return cloneAuthCode(rec)
	}
	return nil
}

// --- staging: refresh tokens -------------------------------------------------

type refreshStaging struct {
	parent  *refreshStore
	added   map[string]*store.RefreshToken
	updated map[string]*store.RefreshToken
	revoked map[string]struct{} // chain roots whose descendants must be revoked at flush
}

func (s *refreshStaging) flush() {
	s.parent.mu.Lock()
	defer s.parent.mu.Unlock()
	for id, rec := range s.added {
		s.parent.m[id] = rec
	}
	for id, rec := range s.updated {
		s.parent.m[id] = rec
	}
	for root := range s.revoked {
		// At flush time, traverse the now-merged map to revoke
		// descendants. The chain root itself is already marked via
		// updated; revokeChainLocked is idempotent.
		now := s.parent.clock.Now()
		revokeChainLocked(s.parent.m, root, now)
	}
}

type txRefreshes struct{ tx *tx }

func (r *txRefreshes) Save(ctx context.Context, token *store.RefreshToken) error {
	if r.tx.closed.Load() {
		return errTxClosed
	}
	if err := ctx.Err(); err != nil {
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
	st.parent.mu.RLock()
	_, parentExists := st.parent.m[key]
	st.parent.mu.RUnlock()
	if parentExists {
		return store.ErrAlreadyExists
	}
	st.added[key] = storeRefresh(token, key)
	return nil
}

func (r *txRefreshes) Find(ctx context.Context, id string) (*store.RefreshToken, error) {
	if r.tx.closed.Load() {
		return nil, errTxClosed
	}
	if err := ctx.Err(); err != nil {
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
	if r.tx.closed.Load() {
		return nil, errTxClosed
	}
	if err := ctx.Err(); err != nil {
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
		return nil, store.ErrAlreadyConsumed
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
	if r.tx.closed.Load() {
		return errTxClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	st := r.tx.rtStaging
	rootKey := hashKey(rootID)
	rec := st.lookup(rootKey)
	if rec == nil {
		return store.ErrNotFound
	}
	// Stamp the root immediately and queue chain traversal for flush time
	// so we can see records added later in the same tx.
	now := r.tx.clock.Now()
	if rec.ConsumedAt == nil {
		updated := cloneRefresh(rec)
		updated.ConsumedAt = &now
		updated.ID = rootKey
		st.updated[rootKey] = updated
	}
	st.revoked[rootKey] = struct{}{}
	// Apply chain marking against the staging view so callers within the
	// same tx see revoked descendants.
	st.markChainStaged(rootKey, now)
	return nil
}

func (r *txRefreshes) RevokeByGrant(ctx context.Context, grantID string) error {
	if r.tx.closed.Load() {
		return errTxClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if grantID == "" {
		return nil
	}
	st := r.tx.rtStaging
	now := r.tx.clock.Now()
	st.iter(func(id string, rec *store.RefreshToken) {
		if rec.GrantID != grantID {
			return
		}
		updated := cloneRefresh(rec)
		if updated.ConsumedAt == nil {
			t := now
			updated.ConsumedAt = &t
		}
		updated.Revoked = true
		updated.ID = id // id here is the hashed key (matches the map key contract).
		st.updated[id] = updated
	})
	return nil
}

// markChainStaged walks the in-memory view (parent + staging) and stamps
// every descendant with ConsumedAt. It is called at RevokeChain time so that
// reads inside the same tx see the revocations.
func (s *refreshStaging) markChainStaged(rootID string, now time.Time) {
	revoked := map[string]struct{}{rootID: {}}
	for s.markOneGenerationStaged(revoked, now) {
	}
}

// markOneGenerationStaged is the inner pass of markChainStaged. It returns
// true when at least one new descendant was stamped so the outer loop
// continues until no more descendants are reachable.
//
// id is the hashed staging-map key. rec.ParentID is stored as the raw
// parent identifier (see [storeRefresh]) so the walk hashes it on the
// fly to compare against the revoked set, which is keyed on digests.
func (s *refreshStaging) markOneGenerationStaged(revoked map[string]struct{}, now time.Time) bool {
	grew := false
	s.iter(func(id string, rec *store.RefreshToken) {
		if _, already := revoked[id]; already {
			return
		}
		if rec.ParentID == nil {
			return
		}
		parentKey := hashKey(*rec.ParentID)
		if _, parentRevoked := revoked[parentKey]; !parentRevoked {
			return
		}
		updated := cloneRefresh(rec)
		if updated.ConsumedAt == nil {
			t := now
			updated.ConsumedAt = &t
		}
		updated.ID = id
		s.updated[id] = updated
		revoked[id] = struct{}{}
		grew = true
	})
	return grew
}

// iter calls fn for every (id, record) visible to this staging area, with
// the staged view taking precedence over the parent map.
func (s *refreshStaging) iter(fn func(string, *store.RefreshToken)) {
	seen := make(map[string]struct{})
	for id, rec := range s.updated {
		fn(id, rec)
		seen[id] = struct{}{}
	}
	for id, rec := range s.added {
		if _, ok := seen[id]; ok {
			continue
		}
		fn(id, rec)
		seen[id] = struct{}{}
	}
	s.parent.mu.RLock()
	defer s.parent.mu.RUnlock()
	for id, rec := range s.parent.m {
		if _, ok := seen[id]; ok {
			continue
		}
		fn(id, rec)
	}
}

func (s *refreshStaging) lookup(id string) *store.RefreshToken {
	if rec, ok := s.updated[id]; ok {
		return rec
	}
	if rec, ok := s.added[id]; ok {
		return rec
	}
	s.parent.mu.RLock()
	defer s.parent.mu.RUnlock()
	if rec, ok := s.parent.m[id]; ok {
		return cloneRefresh(rec)
	}
	return nil
}

// --- staging: grants ---------------------------------------------------------

type grantStaging struct {
	parent  *grantStore
	added   map[string]*store.Grant
	deleted map[string]struct{}
}

func (s *grantStaging) flush() {
	s.parent.mu.Lock()
	defer s.parent.mu.Unlock()
	for id := range s.deleted {
		delete(s.parent.m, id)
	}
	for id, rec := range s.added {
		s.parent.m[id] = rec
	}
}

type txGrants struct{ tx *tx }

func (g *txGrants) Save(ctx context.Context, gr *store.Grant) error {
	if g.tx.closed.Load() {
		return errTxClosed
	}
	if err := ctx.Err(); err != nil {
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
	if g.tx.closed.Load() {
		return nil, errTxClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	st := g.tx.grStaging
	if _, deleted := st.deleted[id]; deleted {
		return nil, store.ErrNotFound
	}
	if rec, ok := st.added[id]; ok {
		return cloneGrant(rec), nil
	}
	st.parent.mu.RLock()
	defer st.parent.mu.RUnlock()
	if rec, ok := st.parent.m[id]; ok {
		return cloneGrant(rec), nil
	}
	return nil, store.ErrNotFound
}

func (g *txGrants) FindBySubjectClient(ctx context.Context, subject, clientID string) (*store.Grant, error) {
	if g.tx.closed.Load() {
		return nil, errTxClosed
	}
	if err := ctx.Err(); err != nil {
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
	consider := func(rec *store.Grant) {
		if rec.Subject != subject || rec.ClientID != clientID {
			return
		}
		if best == nil || rec.UpdatedAt.After(best.UpdatedAt) {
			best = rec
		}
	}
	for id, rec := range s.added {
		if _, deleted := s.deleted[id]; deleted {
			continue
		}
		consider(rec)
	}
	s.parent.mu.RLock()
	defer s.parent.mu.RUnlock()
	for id, rec := range s.parent.m {
		if _, deleted := s.deleted[id]; deleted {
			continue
		}
		if _, override := s.added[id]; override {
			continue
		}
		consider(rec)
	}
	return best
}

// ListBySubject mirrors [grantStore.ListBySubject] over the staged
// view: it walks the parent map plus the per-tx added / deleted
// overlay and returns one entry per consented client (latest
// UpdatedAt wins when historical rows exist).
func (g *txGrants) ListBySubject(ctx context.Context, subject string) ([]*store.Grant, error) {
	if g.tx.closed.Load() {
		return nil, errTxClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	latest := g.tx.grStaging.collectBySubject(subject)
	out := make([]*store.Grant, 0, len(latest))
	for _, rec := range latest {
		out = append(out, cloneGrant(rec))
	}
	return out, nil
}

// collectBySubject is the staging-aware companion to
// [grantStore.ListBySubject]: it walks the staged-add map and the
// parent map (under read-lock), filtering out deletes and per-tx
// overrides, and returns the latest grant per (subject, clientID).
// The helper is split out so [txGrants.ListBySubject] stays under
// the project's gocognit cap.
func (s *grantStaging) collectBySubject(subject string) map[string]*store.Grant {
	latest := make(map[string]*store.Grant)
	consider := func(rec *store.Grant) {
		if rec.Subject != subject {
			return
		}
		current, ok := latest[rec.ClientID]
		if !ok || rec.UpdatedAt.After(current.UpdatedAt) {
			latest[rec.ClientID] = rec
		}
	}
	for id, rec := range s.added {
		if _, deleted := s.deleted[id]; deleted {
			continue
		}
		consider(rec)
	}
	s.parent.mu.RLock()
	defer s.parent.mu.RUnlock()
	for id, rec := range s.parent.m {
		if _, deleted := s.deleted[id]; deleted {
			continue
		}
		if _, override := s.added[id]; override {
			continue
		}
		consider(rec)
	}
	return latest
}

func (g *txGrants) Delete(ctx context.Context, id string) error {
	if g.tx.closed.Load() {
		return errTxClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	st := g.tx.grStaging
	_, inAdded := st.added[id]
	st.parent.mu.RLock()
	_, inParent := st.parent.m[id]
	st.parent.mu.RUnlock()
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
	if g.tx.closed.Load() {
		return false, errTxClosed
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	st := g.tx.grStaging
	if len(st.added) > 0 {
		return true, nil
	}
	st.parent.mu.RLock()
	defer st.parent.mu.RUnlock()
	for id := range st.parent.m {
		if _, deleted := st.deleted[id]; deleted {
			continue
		}
		return true, nil
	}
	return false, nil
}

// --- staging: PAR ------------------------------------------------------------

type parStaging struct {
	parent  *parStore
	added   map[string]*store.PushedAuthRequest
	updated map[string]*store.PushedAuthRequest
}

func (s *parStaging) flush() {
	s.parent.mu.Lock()
	defer s.parent.mu.Unlock()
	for uri, rec := range s.added {
		s.parent.m[uri] = rec
	}
	for uri, rec := range s.updated {
		s.parent.m[uri] = rec
	}
}

type txPARs struct{ tx *tx }

func (p *txPARs) Save(ctx context.Context, par *store.PushedAuthRequest) error {
	if p.tx.closed.Load() {
		return errTxClosed
	}
	if err := ctx.Err(); err != nil {
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
	st.parent.mu.Lock()
	now := p.tx.clock.Now()
	st.parent.deleteExpiredKeyLocked(key, now)
	st.parent.maybeGCLocked(now)
	_, parentExists := st.parent.m[key]
	st.parent.mu.Unlock()
	if parentExists {
		return store.ErrAlreadyExists
	}
	stored := clonePAR(par)
	stored.URI = key
	st.added[key] = stored
	return nil
}

func (p *txPARs) Find(ctx context.Context, uri string) (*store.PushedAuthRequest, error) {
	if p.tx.closed.Load() {
		return nil, errTxClosed
	}
	if err := ctx.Err(); err != nil {
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
	if p.tx.closed.Load() {
		return nil, errTxClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	st := p.tx.parStaging
	key := hashKey(uri)
	rec := st.lookup(key)
	if rec == nil {
		return nil, store.ErrNotFound
	}
	if isExpired(rec.ExpiresAt, p.tx.clock) {
		return nil, store.ErrNotFound
	}
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
	if rec, ok := s.updated[key]; ok {
		return rec
	}
	if rec, ok := s.added[key]; ok {
		return rec
	}
	s.parent.mu.RLock()
	defer s.parent.mu.RUnlock()
	if rec, ok := s.parent.m[key]; ok {
		return clonePAR(rec)
	}
	return nil
}
