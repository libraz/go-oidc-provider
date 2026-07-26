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
// staging maps while owning every atomic-cluster substore mutex. Commit applies
// all staged writes before releasing any mutex; Rollback discards them before
// releasing the same lock set. The owning Store's txMu is also held for the
// lifetime of the tx so two transactions never acquire the cluster together.
type tx struct {
	owner *Store
	clock Clock

	closed atomic.Bool

	acStaging          *authCodeStaging
	rtStaging          *refreshStaging
	grStaging          *grantStaging
	parStaging         *parStaging
	accessTokens       *accessTokenStore
	opaqueAccessTokens *opaqueAccessTokenStore
	grantRevocations   *grantRevocationStore
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
	flushAccessTokenSnapshotLocked(t.owner.accessTokens, t.accessTokens)
	flushOpaqueAccessTokenSnapshotLocked(t.owner.opaqueAccessTokens, t.opaqueAccessTokens)
	flushGrantRevocationSnapshotLocked(t.owner.grantRevocations, t.grantRevocations)
	return nil
}

func accessTokenSnapshotLocked(parent *accessTokenStore) *accessTokenStore {
	out := newAccessTokenStore()
	for id, rec := range parent.m {
		out.m[id] = cloneAccessToken(rec)
	}
	return out
}

func flushAccessTokenSnapshotLocked(parent, snapshot *accessTokenStore) {
	parent.m = snapshot.m
}

func opaqueAccessTokenSnapshotLocked(parent *opaqueAccessTokenStore) *opaqueAccessTokenStore {
	out := newOpaqueAccessTokenStore()
	for id, rec := range parent.m {
		out.m[id] = cloneOpaqueAccessToken(rec)
	}
	return out
}

func flushOpaqueAccessTokenSnapshotLocked(parent, snapshot *opaqueAccessTokenStore) {
	parent.m = snapshot.m
}

func grantRevocationSnapshotLocked(parent *grantRevocationStore) *grantRevocationStore {
	out := newGrantRevocationStore()
	for id, rec := range parent.tombstones {
		v := *rec
		out.tombstones[id] = &v
	}
	for id, rec := range parent.denylist {
		v := *rec
		out.denylist[id] = &v
	}
	return out
}

func flushGrantRevocationSnapshotLocked(parent, snapshot *grantRevocationStore) {
	parent.tombstones, parent.denylist = snapshot.tombstones, snapshot.denylist
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
		clear(t.rtStaging.byClient)
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
}

// The auxiliary atomic-cluster stores use private snapshots rather than the
// delta staging used by the older stores above. Keep their handles bound to
// the transaction as well: returning a raw snapshot would allow writes after
// Commit or Rollback, violating Tx's closed-handle contract.
type txAccessTokens struct{ tx *tx }

func (s txAccessTokens) Register(ctx context.Context, rec store.AccessTokenRecord) error {
	if s.tx.closed.Load() {
		return errTxClosed
	}
	return s.tx.accessTokens.Register(ctx, rec)
}

func (s txAccessTokens) Find(ctx context.Context, jti string) (*store.AccessTokenRecord, error) {
	if s.tx.closed.Load() {
		return nil, errTxClosed
	}
	return s.tx.accessTokens.Find(ctx, jti)
}

func (s txAccessTokens) RevokeByJTI(ctx context.Context, jti string) error {
	if s.tx.closed.Load() {
		return errTxClosed
	}
	return s.tx.accessTokens.RevokeByJTI(ctx, jti)
}

func (s txAccessTokens) RevokeByGrant(ctx context.Context, grantID string) (int, error) {
	if s.tx.closed.Load() {
		return 0, errTxClosed
	}
	return s.tx.accessTokens.RevokeByGrant(ctx, grantID)
}

func (s txAccessTokens) GC(ctx context.Context, cutoff time.Time) (int, error) {
	if s.tx.closed.Load() {
		return 0, errTxClosed
	}
	return s.tx.accessTokens.GC(ctx, cutoff)
}

type txOpaqueAccessTokens struct{ tx *tx }

func (s txOpaqueAccessTokens) Save(ctx context.Context, tok *store.OpaqueAccessToken) error {
	if s.tx.closed.Load() {
		return errTxClosed
	}
	return s.tx.opaqueAccessTokens.Save(ctx, tok)
}

func (s txOpaqueAccessTokens) Find(ctx context.Context, id string) (*store.OpaqueAccessToken, error) {
	if s.tx.closed.Load() {
		return nil, errTxClosed
	}
	return s.tx.opaqueAccessTokens.Find(ctx, id)
}

func (s txOpaqueAccessTokens) RevokeByID(ctx context.Context, id string) error {
	if s.tx.closed.Load() {
		return errTxClosed
	}
	return s.tx.opaqueAccessTokens.RevokeByID(ctx, id)
}

func (s txOpaqueAccessTokens) RevokeByGrant(ctx context.Context, grantID string) (int, error) {
	if s.tx.closed.Load() {
		return 0, errTxClosed
	}
	return s.tx.opaqueAccessTokens.RevokeByGrant(ctx, grantID)
}

func (s txOpaqueAccessTokens) GC(ctx context.Context, cutoff time.Time) (int, error) {
	if s.tx.closed.Load() {
		return 0, errTxClosed
	}
	return s.tx.opaqueAccessTokens.GC(ctx, cutoff)
}

type txGrantRevocations struct{ tx *tx }

func (s txGrantRevocations) RevokeGrant(ctx context.Context, tombstone store.GrantTombstone) error {
	if s.tx.closed.Load() {
		return errTxClosed
	}
	return s.tx.grantRevocations.RevokeGrant(ctx, tombstone)
}

func (s txGrantRevocations) RevokeJTI(ctx context.Context, revoked store.RevokedJTI) error {
	if s.tx.closed.Load() {
		return errTxClosed
	}
	return s.tx.grantRevocations.RevokeJTI(ctx, revoked)
}

func (s txGrantRevocations) IsRevoked(ctx context.Context, grantID, jti string, iat time.Time) (bool, error) {
	if s.tx.closed.Load() {
		return false, errTxClosed
	}
	return s.tx.grantRevocations.IsRevoked(ctx, grantID, jti, iat)
}

func (s txGrantRevocations) GC(ctx context.Context, cutoff time.Time) (int, error) {
	if s.tx.closed.Load() {
		return 0, errTxClosed
	}
	return s.tx.grantRevocations.GC(ctx, cutoff)
}

// --- staging: authorization codes -------------------------------------------

type authCodeStaging struct {
	parent  *authCodeStore
	added   map[string]*store.AuthorizationCode
	updated map[string]*store.AuthorizationCode
}

func (s *authCodeStaging) flushLocked() {
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
	if rec, ok := s.parent.m[key]; ok {
		// Return a snapshot so subsequent mutations via Consume are
		// confined to staging.
		return cloneAuthCode(rec)
	}
	return nil
}

// --- staging: refresh tokens -------------------------------------------------

type refreshStaging struct {
	parent   *refreshStore
	added    map[string]*store.RefreshToken
	updated  map[string]*store.RefreshToken
	byClient refreshIndex
	byGrant  refreshIndex
	revoked  map[string]struct{} // chain roots whose descendants must be revoked at flush
	retries  map[string][]byte   // hashed predecessor -> sealed response
}

func (s *refreshStaging) flushLocked() {
	for id, rec := range s.added {
		s.parent.m[id] = rec
		s.parent.indexRefreshLocked(id, rec)
	}
	for id, rec := range s.updated {
		s.parent.m[id] = rec
	}
	for parent, sealed := range s.retries {
		s.parent.retries[parent] = append([]byte(nil), sealed...)
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
	_, parentExists := st.parent.m[key]
	if parentExists {
		return store.ErrAlreadyExists
	}
	stored := storeRefresh(token, key)
	st.added[key] = stored
	st.byClient.add(stored.ClientID, key)
	st.byGrant.add(stored.GrantID, key)
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
	r.tx.rtStaging.retries[hashKey(*token.ParentID)] = append([]byte(nil), sealed...)
	return nil
}

func (r *txRefreshes) LoadRetryResponse(ctx context.Context, predecessorID string) ([]byte, error) {
	if r.tx.closed.Load() {
		return nil, errTxClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key := hashKey(predecessorID)
	if sealed, ok := r.tx.rtStaging.retries[key]; ok {
		return append([]byte(nil), sealed...), nil
	}
	sealed, ok := r.tx.rtStaging.parent.retries[key]
	if !ok {
		return nil, store.ErrNotFound
	}
	return append([]byte(nil), sealed...), nil
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
// overlay and returns every active grant for the subject.
func (g *txGrants) ListBySubject(ctx context.Context, subject string) ([]*store.Grant, error) {
	if g.tx.closed.Load() {
		return nil, errTxClosed
	}
	if err := ctx.Err(); err != nil {
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
	if g.tx.closed.Load() {
		return store.GrantClientPage{}, errTxClosed
	}
	if err := ctx.Err(); err != nil {
		return store.GrantClientPage{}, err
	}
	if limit <= 0 {
		return store.GrantClientPage{}, errors.New("inmem: grant client page limit must be positive")
	}
	builder := newGrantClientPageBuilder(cursor, limit)
	g.tx.grStaging.addClientIDsBySubject(subject, builder)
	return builder.page(), nil
}

// collectBySubject is the staging-aware companion to
// [grantStore.ListBySubject]: it walks the staged-add map and the
// parent map (already transaction-locked), filtering out deletes and per-tx
// overrides, and returns every active grant for the subject.
// The helper is split out so [txGrants.ListBySubject] stays under
// the project's gocognit cap.
func (s *grantStaging) collectBySubject(subject string) []*store.Grant {
	out := make([]*store.Grant, 0)
	consider := func(rec *store.Grant) {
		if rec.Subject != subject {
			return
		}
		out = append(out, rec)
	}
	for id, rec := range s.added {
		if _, deleted := s.deleted[id]; deleted {
			continue
		}
		consider(rec)
	}
	for id, rec := range s.parent.m {
		if _, deleted := s.deleted[id]; deleted {
			continue
		}
		if _, override := s.added[id]; override {
			continue
		}
		consider(rec)
	}
	return out
}

func (s *grantStaging) addClientIDsBySubject(
	subject string,
	builder *grantClientPageBuilder,
) {
	consider := func(rec *store.Grant) {
		if rec.Subject == subject {
			builder.add(rec.ClientID)
		}
	}
	for id, rec := range s.added {
		if _, deleted := s.deleted[id]; !deleted {
			consider(rec)
		}
	}
	for id, rec := range s.parent.m {
		if _, deleted := s.deleted[id]; deleted {
			continue
		}
		if _, override := s.added[id]; override {
			continue
		}
		consider(rec)
	}
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

func (s *parStaging) flushLocked() {
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
	parent, parentExists := st.parent.m[key]
	if parentExists && isExpired(parent.ExpiresAt, p.tx.clock) {
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
	if rec, ok := s.updated[key]; ok {
		return rec
	}
	if rec, ok := s.added[key]; ok {
		return rec
	}
	if rec, ok := s.parent.m[key]; ok {
		return clonePAR(rec)
	}
	return nil
}
