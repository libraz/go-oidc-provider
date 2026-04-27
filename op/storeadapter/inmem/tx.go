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
	ssStaging  *sessionStaging
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

// Sessions returns the transactional session substore.
func (t *tx) Sessions() store.SessionStore {
	return &txSessions{tx: t}
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
	t.ssStaging.flush()
	t.parStaging.flush()
	return nil
}

// Rollback discards every staged write and releases the tx mutex. Rollback is
// safe to call after Commit; subsequent calls are no-ops.
func (t *tx) Rollback() error {
	if !t.closed.CompareAndSwap(false, true) {
		// Per godoc, Rollback after Commit is a deliberate no-op.
		return nil
	}
	t.owner.txMu.Unlock()
	return nil
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
	if _, exists := st.added[code.ID]; exists {
		return store.ErrAlreadyExists
	}
	st.parent.mu.RLock()
	_, parentExists := st.parent.m[code.ID]
	st.parent.mu.RUnlock()
	if parentExists {
		return store.ErrAlreadyExists
	}
	st.added[code.ID] = cloneAuthCode(code)
	return nil
}

func (a *txAuthCodes) Find(ctx context.Context, id string) (*store.AuthorizationCode, error) {
	if a.tx.closed.Load() {
		return nil, errTxClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rec := a.tx.acStaging.lookup(id)
	if rec == nil {
		return nil, store.ErrNotFound
	}
	if isExpired(rec.ExpiresAt, a.tx.clock) {
		return nil, store.ErrNotFound
	}
	return cloneAuthCode(rec), nil
}

func (a *txAuthCodes) Consume(ctx context.Context, id string) (*store.AuthorizationCode, error) {
	if a.tx.closed.Load() {
		return nil, errTxClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	st := a.tx.acStaging
	rec := st.lookup(id)
	if rec == nil {
		return nil, store.ErrNotFound
	}
	if isExpired(rec.ExpiresAt, a.tx.clock) {
		return nil, store.ErrNotFound
	}
	if rec.ConsumedAt != nil {
		return nil, store.ErrAlreadyConsumed
	}
	updated := cloneAuthCode(rec)
	now := a.tx.clock.Now()
	updated.ConsumedAt = &now
	st.updated[id] = updated
	return cloneAuthCode(updated), nil
}

func (s *authCodeStaging) lookup(id string) *store.AuthorizationCode {
	if rec, ok := s.updated[id]; ok {
		return rec
	}
	if rec, ok := s.added[id]; ok {
		return rec
	}
	s.parent.mu.RLock()
	defer s.parent.mu.RUnlock()
	if rec, ok := s.parent.m[id]; ok {
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
	if _, exists := st.added[token.ID]; exists {
		return store.ErrAlreadyExists
	}
	st.parent.mu.RLock()
	_, parentExists := st.parent.m[token.ID]
	st.parent.mu.RUnlock()
	if parentExists {
		return store.ErrAlreadyExists
	}
	st.added[token.ID] = cloneRefresh(token)
	return nil
}

func (r *txRefreshes) Find(ctx context.Context, id string) (*store.RefreshToken, error) {
	if r.tx.closed.Load() {
		return nil, errTxClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rec := r.tx.rtStaging.lookup(id)
	if rec == nil {
		return nil, store.ErrNotFound
	}
	if isExpired(rec.ExpiresAt, r.tx.clock) {
		return nil, store.ErrNotFound
	}
	return cloneRefresh(rec), nil
}

func (r *txRefreshes) Consume(ctx context.Context, id string) (*store.RefreshToken, error) {
	if r.tx.closed.Load() {
		return nil, errTxClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	st := r.tx.rtStaging
	rec := st.lookup(id)
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
	st.updated[id] = updated
	return cloneRefresh(updated), nil
}

func (r *txRefreshes) RevokeChain(ctx context.Context, rootID string) error {
	if r.tx.closed.Load() {
		return errTxClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	st := r.tx.rtStaging
	rec := st.lookup(rootID)
	if rec == nil {
		return store.ErrNotFound
	}
	// Stamp the root immediately and queue chain traversal for flush time
	// so we can see records added later in the same tx.
	now := r.tx.clock.Now()
	if rec.ConsumedAt == nil {
		updated := cloneRefresh(rec)
		updated.ConsumedAt = &now
		st.updated[rootID] = updated
	}
	st.revoked[rootID] = struct{}{}
	// Apply chain marking against the staging view so callers within the
	// same tx see revoked descendants.
	st.markChainStaged(rootID, now)
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
func (s *refreshStaging) markOneGenerationStaged(revoked map[string]struct{}, now time.Time) bool {
	grew := false
	s.iter(func(id string, rec *store.RefreshToken) {
		if _, already := revoked[id]; already {
			return
		}
		if rec.ParentID == nil {
			return
		}
		if _, parentRevoked := revoked[*rec.ParentID]; !parentRevoked {
			return
		}
		updated := cloneRefresh(rec)
		if updated.ConsumedAt == nil {
			t := now
			updated.ConsumedAt = &t
		}
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

// --- staging: sessions -------------------------------------------------------

type sessionTouch struct {
	expiresAt time.Time
	updatedAt time.Time
}

type sessionStaging struct {
	parent  *sessionStore
	added   map[string]*store.Session
	touched map[string]sessionTouch
	deleted map[string]struct{}
}

func (s *sessionStaging) flush() {
	s.parent.mu.Lock()
	defer s.parent.mu.Unlock()
	for id := range s.deleted {
		delete(s.parent.m, id)
	}
	for id, rec := range s.added {
		s.parent.m[id] = rec
	}
	for id, t := range s.touched {
		if rec, ok := s.parent.m[id]; ok {
			rec.ExpiresAt = t.expiresAt
			rec.UpdatedAt = t.updatedAt
		}
	}
}

type txSessions struct{ tx *tx }

func (s *txSessions) Save(ctx context.Context, sess *store.Session) error {
	if s.tx.closed.Load() {
		return errTxClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if sess == nil {
		return errors.New("inmem: nil session")
	}
	st := s.tx.ssStaging
	delete(st.deleted, sess.ID)
	st.added[sess.ID] = cloneSession(sess)
	return nil
}

func (s *txSessions) Find(ctx context.Context, id string) (*store.Session, error) {
	if s.tx.closed.Load() {
		return nil, errTxClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rec := s.tx.ssStaging.lookup(id)
	if rec == nil {
		return nil, store.ErrNotFound
	}
	if isExpired(rec.ExpiresAt, s.tx.clock) {
		return nil, store.ErrNotFound
	}
	return cloneSession(rec), nil
}

func (s *txSessions) Touch(ctx context.Context, id string, expiresAt, updatedAt time.Time) error {
	if s.tx.closed.Load() {
		return errTxClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	st := s.tx.ssStaging
	rec := st.lookup(id)
	if rec == nil {
		return store.ErrNotFound
	}
	if isExpired(rec.ExpiresAt, s.tx.clock) {
		return store.ErrNotFound
	}
	if added, ok := st.added[id]; ok {
		added.ExpiresAt = expiresAt
		added.UpdatedAt = updatedAt
		return nil
	}
	st.touched[id] = sessionTouch{expiresAt: expiresAt, updatedAt: updatedAt}
	return nil
}

func (s *txSessions) Delete(ctx context.Context, id string) error {
	if s.tx.closed.Load() {
		return errTxClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	st := s.tx.ssStaging
	_, inAdded := st.added[id]
	st.parent.mu.RLock()
	_, inParent := st.parent.m[id]
	st.parent.mu.RUnlock()
	if !inAdded && !inParent {
		return store.ErrNotFound
	}
	delete(st.added, id)
	delete(st.touched, id)
	st.deleted[id] = struct{}{}
	return nil
}

func (s *txSessions) ListByChooserGroup(ctx context.Context, groupID string) ([]*store.Session, error) {
	if s.tx.closed.Load() {
		return nil, errTxClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	st := s.tx.ssStaging
	out, seen := stagedSessionsByGroup(st, groupID, s.tx.clock)
	st.parent.mu.RLock()
	defer st.parent.mu.RUnlock()
	for id, rec := range st.parent.m {
		if _, dup := seen[id]; dup {
			continue
		}
		if _, deleted := st.deleted[id]; deleted {
			continue
		}
		if rec.ChooserGroupID != groupID {
			continue
		}
		clone := cloneSession(rec)
		if t, ok := st.touched[id]; ok {
			clone.ExpiresAt = t.expiresAt
			clone.UpdatedAt = t.updatedAt
		}
		if isExpired(clone.ExpiresAt, s.tx.clock) {
			continue
		}
		out = append(out, clone)
	}
	return out, nil
}

// stagedSessionsByGroup collects sessions added in this transaction that
// match the chooser group, returning them alongside the set of IDs already
// observed so the parent walk can skip duplicates.
func stagedSessionsByGroup(
	st *sessionStaging,
	groupID string,
	clock Clock,
) ([]*store.Session, map[string]struct{}) {
	out := make([]*store.Session, 0)
	seen := make(map[string]struct{})
	for id, rec := range st.added {
		if rec.ChooserGroupID != groupID {
			continue
		}
		if isExpired(rec.ExpiresAt, clock) {
			continue
		}
		out = append(out, cloneSession(rec))
		seen[id] = struct{}{}
	}
	return out, seen
}

func (s *sessionStaging) lookup(id string) *store.Session {
	if _, deleted := s.deleted[id]; deleted {
		return nil
	}
	if rec, ok := s.added[id]; ok {
		return rec
	}
	s.parent.mu.RLock()
	defer s.parent.mu.RUnlock()
	rec, ok := s.parent.m[id]
	if !ok {
		return nil
	}
	out := cloneSession(rec)
	if t, ok := s.touched[id]; ok {
		out.ExpiresAt = t.expiresAt
		out.UpdatedAt = t.updatedAt
	}
	return out
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
	if _, exists := st.added[par.URI]; exists {
		return store.ErrAlreadyExists
	}
	st.parent.mu.RLock()
	_, parentExists := st.parent.m[par.URI]
	st.parent.mu.RUnlock()
	if parentExists {
		return store.ErrAlreadyExists
	}
	st.added[par.URI] = clonePAR(par)
	return nil
}

func (p *txPARs) Find(ctx context.Context, uri string) (*store.PushedAuthRequest, error) {
	if p.tx.closed.Load() {
		return nil, errTxClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rec := p.tx.parStaging.lookup(uri)
	if rec == nil {
		return nil, store.ErrNotFound
	}
	if isExpired(rec.ExpiresAt, p.tx.clock) {
		return nil, store.ErrNotFound
	}
	return clonePAR(rec), nil
}

func (p *txPARs) Consume(ctx context.Context, uri string) (*store.PushedAuthRequest, error) {
	if p.tx.closed.Load() {
		return nil, errTxClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	st := p.tx.parStaging
	rec := st.lookup(uri)
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
	st.updated[uri] = updated
	return clonePAR(updated), nil
}

func (s *parStaging) lookup(uri string) *store.PushedAuthRequest {
	if rec, ok := s.updated[uri]; ok {
		return rec
	}
	if rec, ok := s.added[uri]; ok {
		return rec
	}
	s.parent.mu.RLock()
	defer s.parent.mu.RUnlock()
	if rec, ok := s.parent.m[uri]; ok {
		return clonePAR(rec)
	}
	return nil
}
