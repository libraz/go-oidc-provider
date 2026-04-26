// Package inmem provides an in-memory reference implementation of every
// substore declared in [github.com/libraz/go-oidc-provider/op/store]. It is
// the backend the library tests run against, the seed for the testkit, and
// the smallest possible illustration of the storage contract for embedders
// who want a working example before plugging in a real database.
//
// # Scope
//
// The package implements a single concrete type, [Store], that satisfies
// [store.Store], [store.ClientRegistry], and [store.Transactional]. Every
// substore lives behind its own [sync.RWMutex] for read/write isolation;
// transactions are serialised through a process-wide mutex held by the
// returned [store.Tx]. The implementation is deliberately simple -- it is a
// reference, not a production engine -- and trades throughput for clarity.
//
// # Concurrency model
//
// Each substore guards its map with a [sync.RWMutex]. A [store.Tx] obtained
// from [Store.BeginTx] takes a process-wide [sync.Mutex] that is released by
// either [store.Tx.Commit] or [store.Tx.Rollback]. While a transaction is in
// flight, non-transactional writes still proceed -- the global mutex
// serialises BeginTx callers, not direct substore calls. Tests that mix the
// two paths SHOULD prefer to drive every write through BeginTx so that the
// orderings remain deterministic.
//
// # Defensive copying
//
// Save and Find return fresh pointers and clone every slice and map field
// before handing the value over. Callers may mutate the returned record
// freely without affecting subsequent reads, and the storage map is
// immune to mutations performed on previously returned records.
//
// # Expiry
//
// Records carrying an ExpiresAt field (sessions, interactions, PAR records,
// authorization codes, refresh tokens, JTIs) are filtered through the
// configured [Clock] on every Find/Consume. A record whose ExpiresAt is
// strictly before [Clock.Now] is treated as absent: the lookup returns
// [store.ErrNotFound] and Consume returns the same. The records remain in
// the map for diagnostic purposes; production backends typically run a
// sweeper, but the reference implementation deliberately omits one to keep
// the surface tiny.
package inmem

import (
	"context"
	"errors"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Clock returns the wall-clock time used to evaluate record expiry. It is
// declared here rather than imported from [github.com/libraz/go-oidc-provider/op]
// so that the inmem package can be used by the op package itself without a
// circular dependency. Any [github.com/libraz/go-oidc-provider/internal/timex.Clock]
// or [op.Clock] value satisfies the interface structurally.
type Clock interface {
	Now() time.Time
}

// Option configures a [Store] at construction time.
type Option func(*Store)

// WithClock injects the wall-clock implementation used to evaluate record
// expiry. The default is [timex.SystemClock].
func WithClock(c Clock) Option {
	return func(s *Store) {
		if c != nil {
			s.clock = c
		}
	}
}

// Store is the in-memory backend. The zero value is not usable; callers MUST
// obtain a Store through [New].
type Store struct {
	clock Clock

	// txMu serialises [Store.BeginTx] callers so that the in-flight
	// transaction has exclusive access to the substore data while it is
	// staging writes. The mutex is held for the lifetime of the returned
	// [store.Tx] and released by Commit or Rollback.
	txMu sync.Mutex

	clients      *clientStore
	authCodes    *authCodeStore
	refreshes    *refreshStore
	grants       *grantStore
	sessions     *sessionStore
	pars         *parStore
	interactions *interactionStore
	jtis         *jtiStore
}

// New constructs a fresh in-memory [Store] populated with empty substores.
func New(opts ...Option) *Store {
	s := &Store{
		clock: timex.SystemClock,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	s.clients = newClientStore()
	s.authCodes = newAuthCodeStore(s.clock)
	s.refreshes = newRefreshStore(s.clock)
	s.grants = newGrantStore()
	s.sessions = newSessionStore(s.clock)
	s.pars = newPARStore(s.clock)
	s.interactions = newInteractionStore(s.clock)
	s.jtis = newJTIStore(s.clock)
	return s
}

// Clients implements [store.Store].
func (s *Store) Clients() store.ClientStore { return s.clients }

// AuthorizationCodes implements [store.Store].
func (s *Store) AuthorizationCodes() store.AuthorizationCodeStore { return s.authCodes }

// RefreshTokens implements [store.Store].
func (s *Store) RefreshTokens() store.RefreshTokenStore { return s.refreshes }

// Grants implements [store.Store].
func (s *Store) Grants() store.GrantStore { return s.grants }

// Sessions implements [store.Store].
func (s *Store) Sessions() store.SessionStore { return s.sessions }

// PushedAuthRequests implements [store.Store].
func (s *Store) PushedAuthRequests() store.PushedAuthRequestStore { return s.pars }

// Interactions implements [store.Store].
func (s *Store) Interactions() store.InteractionStore { return s.interactions }

// ConsumedJTIs implements [store.Store].
func (s *Store) ConsumedJTIs() store.ConsumedJTIStore { return s.jtis }

// RegisterClient implements [store.ClientRegistry].
func (s *Store) RegisterClient(ctx context.Context, c *store.Client) error {
	return s.clients.Register(ctx, c)
}

// UpdateClient implements [store.ClientRegistry].
func (s *Store) UpdateClient(ctx context.Context, c *store.Client) error {
	return s.clients.Update(ctx, c)
}

// DeleteClient implements [store.ClientRegistry].
func (s *Store) DeleteClient(ctx context.Context, id string) error {
	return s.clients.Delete(ctx, id)
}

// GetClient implements [store.ClientStore].
func (s *Store) GetClient(ctx context.Context, id string) (*store.Client, error) {
	return s.clients.GetClient(ctx, id)
}

// BeginTx implements [store.Transactional]. The returned [store.Tx] holds the
// process-wide tx mutex and stages writes that are flushed atomically on
// [store.Tx.Commit] and discarded on [store.Tx.Rollback].
func (s *Store) BeginTx(ctx context.Context) (store.Tx, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.txMu.Lock()
	t := &tx{
		owner: s,
		clock: s.clock,
		acStaging: &authCodeStaging{
			parent:  s.authCodes,
			added:   make(map[string]*store.AuthorizationCode),
			updated: make(map[string]*store.AuthorizationCode),
		},
		rtStaging: &refreshStaging{
			parent:  s.refreshes,
			added:   make(map[string]*store.RefreshToken),
			updated: make(map[string]*store.RefreshToken),
			revoked: make(map[string]struct{}),
		},
		grStaging: &grantStaging{
			parent:  s.grants,
			added:   make(map[string]*store.Grant),
			deleted: make(map[string]struct{}),
		},
		ssStaging: &sessionStaging{
			parent:  s.sessions,
			added:   make(map[string]*store.Session),
			touched: make(map[string]sessionTouch),
			deleted: make(map[string]struct{}),
		},
		parStaging: &parStaging{
			parent:  s.pars,
			added:   make(map[string]*store.PushedAuthRequest),
			updated: make(map[string]*store.PushedAuthRequest),
		},
	}
	return t, nil
}

// --- ClientStore -------------------------------------------------------------

type clientStore struct {
	mu sync.RWMutex
	m  map[string]*store.Client
}

func newClientStore() *clientStore {
	return &clientStore{m: make(map[string]*store.Client)}
}

func (s *clientStore) GetClient(_ context.Context, id string) (*store.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.m[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneClient(c), nil
}

func (s *clientStore) Register(_ context.Context, c *store.Client) error {
	if c == nil {
		return errors.New("inmem: nil client")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.m[c.ID]; exists {
		return store.ErrAlreadyExists
	}
	s.m[c.ID] = cloneClient(c)
	return nil
}

func (s *clientStore) Update(_ context.Context, c *store.Client) error {
	if c == nil {
		return errors.New("inmem: nil client")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.m[c.ID]; !exists {
		return store.ErrNotFound
	}
	s.m[c.ID] = cloneClient(c)
	return nil
}

func (s *clientStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.m[id]; !exists {
		return store.ErrNotFound
	}
	delete(s.m, id)
	return nil
}

func cloneClient(c *store.Client) *store.Client {
	if c == nil {
		return nil
	}
	out := *c
	out.RedirectURIs = slices.Clone(c.RedirectURIs)
	out.GrantTypes = slices.Clone(c.GrantTypes)
	out.ResponseTypes = slices.Clone(c.ResponseTypes)
	out.Scopes = slices.Clone(c.Scopes)
	return &out
}

// --- AuthorizationCodeStore --------------------------------------------------

type authCodeStore struct {
	mu    sync.RWMutex
	clock Clock
	m     map[string]*store.AuthorizationCode
}

func newAuthCodeStore(c Clock) *authCodeStore {
	return &authCodeStore{clock: c, m: make(map[string]*store.AuthorizationCode)}
}

func (s *authCodeStore) Save(_ context.Context, code *store.AuthorizationCode) error {
	if code == nil {
		return errors.New("inmem: nil authorization code")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.m[code.ID]; exists {
		return store.ErrAlreadyExists
	}
	s.m[code.ID] = cloneAuthCode(code)
	return nil
}

func (s *authCodeStore) Find(_ context.Context, id string) (*store.AuthorizationCode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.m[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	if isExpired(rec.ExpiresAt, s.clock) {
		return nil, store.ErrNotFound
	}
	return cloneAuthCode(rec), nil
}

func (s *authCodeStore) Consume(_ context.Context, id string) (*store.AuthorizationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.m[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	if isExpired(rec.ExpiresAt, s.clock) {
		return nil, store.ErrNotFound
	}
	if rec.ConsumedAt != nil {
		return nil, store.ErrAlreadyConsumed
	}
	now := s.clock.Now()
	rec.ConsumedAt = &now
	return cloneAuthCode(rec), nil
}

func cloneAuthCode(c *store.AuthorizationCode) *store.AuthorizationCode {
	if c == nil {
		return nil
	}
	out := *c
	out.Scope = slices.Clone(c.Scope)
	if c.ConsumedAt != nil {
		t := *c.ConsumedAt
		out.ConsumedAt = &t
	}
	return &out
}

// --- RefreshTokenStore -------------------------------------------------------

type refreshStore struct {
	mu    sync.RWMutex
	clock Clock
	m     map[string]*store.RefreshToken
}

func newRefreshStore(c Clock) *refreshStore {
	return &refreshStore{clock: c, m: make(map[string]*store.RefreshToken)}
}

func (s *refreshStore) Save(_ context.Context, token *store.RefreshToken) error {
	if token == nil {
		return errors.New("inmem: nil refresh token")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.m[token.ID]; exists {
		return store.ErrAlreadyExists
	}
	s.m[token.ID] = cloneRefresh(token)
	return nil
}

func (s *refreshStore) Find(_ context.Context, id string) (*store.RefreshToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.m[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	if isExpired(rec.ExpiresAt, s.clock) {
		return nil, store.ErrNotFound
	}
	return cloneRefresh(rec), nil
}

func (s *refreshStore) Consume(_ context.Context, id string) (*store.RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.m[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	if isExpired(rec.ExpiresAt, s.clock) {
		return nil, store.ErrNotFound
	}
	if rec.ConsumedAt != nil {
		return nil, store.ErrAlreadyConsumed
	}
	now := s.clock.Now()
	rec.ConsumedAt = &now
	return cloneRefresh(rec), nil
}

func (s *refreshStore) RevokeChain(_ context.Context, rootID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[rootID]; !ok {
		return store.ErrNotFound
	}
	now := s.clock.Now()
	revokeChainLocked(s.m, rootID, now)
	return nil
}

// revokeChainLocked walks the parent pointers in m starting at rootID and
// stamps ConsumedAt on rootID and every descendant. The traversal repeatedly
// scans m until a full pass adds no new revocations; this keeps the helper
// O(n^2) but tolerates parents that appear after their children in the map.
func revokeChainLocked(m map[string]*store.RefreshToken, rootID string, now time.Time) {
	stampConsumed(m[rootID], now)
	revoked := map[string]struct{}{rootID: {}}
	for revokeOneGeneration(m, revoked, now) {
	}
}

// revokeOneGeneration scans m and stamps every record whose parent is already
// in revoked. Returns true if any new record was added so the caller can loop
// until a fixed point.
func revokeOneGeneration(m map[string]*store.RefreshToken, revoked map[string]struct{}, now time.Time) bool {
	grew := false
	for id, rec := range m {
		if _, already := revoked[id]; already {
			continue
		}
		if rec.ParentID == nil {
			continue
		}
		if _, parentRevoked := revoked[*rec.ParentID]; !parentRevoked {
			continue
		}
		stampConsumed(rec, now)
		revoked[id] = struct{}{}
		grew = true
	}
	return grew
}

// stampConsumed sets rec.ConsumedAt to now when the field is currently nil.
// rec may be nil; in that case the call is a no-op.
func stampConsumed(rec *store.RefreshToken, now time.Time) {
	if rec == nil || rec.ConsumedAt != nil {
		return
	}
	t := now
	rec.ConsumedAt = &t
}

func cloneRefresh(t *store.RefreshToken) *store.RefreshToken {
	if t == nil {
		return nil
	}
	out := *t
	out.Scope = slices.Clone(t.Scope)
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

// --- GrantStore --------------------------------------------------------------

type grantStore struct {
	mu sync.RWMutex
	m  map[string]*store.Grant
}

func newGrantStore() *grantStore {
	return &grantStore{m: make(map[string]*store.Grant)}
}

func (s *grantStore) Save(_ context.Context, g *store.Grant) error {
	if g == nil {
		return errors.New("inmem: nil grant")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[g.ID] = cloneGrant(g)
	return nil
}

func (s *grantStore) Find(_ context.Context, id string) (*store.Grant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.m[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneGrant(rec), nil
}

func (s *grantStore) FindBySubjectClient(_ context.Context, subject, clientID string) (*store.Grant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var best *store.Grant
	for _, rec := range s.m {
		if rec.Subject != subject || rec.ClientID != clientID {
			continue
		}
		if best == nil || rec.UpdatedAt.After(best.UpdatedAt) {
			best = rec
		}
	}
	if best == nil {
		return nil, store.ErrNotFound
	}
	return cloneGrant(best), nil
}

func (s *grantStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[id]; !ok {
		return store.ErrNotFound
	}
	delete(s.m, id)
	return nil
}

func cloneGrant(g *store.Grant) *store.Grant {
	if g == nil {
		return nil
	}
	out := *g
	out.Scope = slices.Clone(g.Scope)
	out.Claims = maps.Clone(g.Claims)
	return &out
}

// --- SessionStore ------------------------------------------------------------

type sessionStore struct {
	mu    sync.RWMutex
	clock Clock
	m     map[string]*store.Session
}

func newSessionStore(c Clock) *sessionStore {
	return &sessionStore{clock: c, m: make(map[string]*store.Session)}
}

func (s *sessionStore) Save(_ context.Context, sess *store.Session) error {
	if sess == nil {
		return errors.New("inmem: nil session")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[sess.ID] = cloneSession(sess)
	return nil
}

func (s *sessionStore) Find(_ context.Context, id string) (*store.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.m[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	if isExpired(rec.ExpiresAt, s.clock) {
		return nil, store.ErrNotFound
	}
	return cloneSession(rec), nil
}

func (s *sessionStore) Touch(_ context.Context, id string, expiresAt, updatedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.m[id]
	if !ok {
		return store.ErrNotFound
	}
	if isExpired(rec.ExpiresAt, s.clock) {
		return store.ErrNotFound
	}
	rec.ExpiresAt = expiresAt
	rec.UpdatedAt = updatedAt
	return nil
}

func (s *sessionStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[id]; !ok {
		return store.ErrNotFound
	}
	delete(s.m, id)
	return nil
}

func (s *sessionStore) ListByChooserGroup(_ context.Context, groupID string) ([]*store.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*store.Session, 0)
	for _, rec := range s.m {
		if rec.ChooserGroupID != groupID {
			continue
		}
		if isExpired(rec.ExpiresAt, s.clock) {
			continue
		}
		out = append(out, cloneSession(rec))
	}
	return out, nil
}

func cloneSession(s *store.Session) *store.Session {
	if s == nil {
		return nil
	}
	out := *s
	out.AMR = slices.Clone(s.AMR)
	return &out
}

// --- PushedAuthRequestStore --------------------------------------------------

type parStore struct {
	mu    sync.RWMutex
	clock Clock
	m     map[string]*store.PushedAuthRequest
}

func newPARStore(c Clock) *parStore {
	return &parStore{clock: c, m: make(map[string]*store.PushedAuthRequest)}
}

func (s *parStore) Save(_ context.Context, par *store.PushedAuthRequest) error {
	if par == nil {
		return errors.New("inmem: nil pushed authorization request")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.m[par.URI]; exists {
		return store.ErrAlreadyExists
	}
	s.m[par.URI] = clonePAR(par)
	return nil
}

func (s *parStore) Find(_ context.Context, uri string) (*store.PushedAuthRequest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.m[uri]
	if !ok {
		return nil, store.ErrNotFound
	}
	if isExpired(rec.ExpiresAt, s.clock) {
		return nil, store.ErrNotFound
	}
	return clonePAR(rec), nil
}

func (s *parStore) Consume(_ context.Context, uri string) (*store.PushedAuthRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.m[uri]
	if !ok {
		return nil, store.ErrNotFound
	}
	if isExpired(rec.ExpiresAt, s.clock) {
		return nil, store.ErrNotFound
	}
	if rec.ConsumedAt != nil {
		return nil, store.ErrAlreadyConsumed
	}
	now := s.clock.Now()
	rec.ConsumedAt = &now
	return clonePAR(rec), nil
}

func clonePAR(p *store.PushedAuthRequest) *store.PushedAuthRequest {
	if p == nil {
		return nil
	}
	out := *p
	out.RawParams = slices.Clone(p.RawParams)
	if p.ConsumedAt != nil {
		t := *p.ConsumedAt
		out.ConsumedAt = &t
	}
	return &out
}

// --- InteractionStore --------------------------------------------------------

type interactionStore struct {
	mu    sync.RWMutex
	clock Clock
	m     map[string]*store.Interaction
}

func newInteractionStore(c Clock) *interactionStore {
	return &interactionStore{clock: c, m: make(map[string]*store.Interaction)}
}

func (s *interactionStore) Save(_ context.Context, i *store.Interaction) error {
	if i == nil {
		return errors.New("inmem: nil interaction")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[i.ID] = cloneInteraction(i)
	return nil
}

func (s *interactionStore) Find(_ context.Context, id string) (*store.Interaction, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.m[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	if isExpired(rec.ExpiresAt, s.clock) {
		return nil, store.ErrNotFound
	}
	return cloneInteraction(rec), nil
}

func (s *interactionStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[id]; !ok {
		return store.ErrNotFound
	}
	delete(s.m, id)
	return nil
}

func cloneInteraction(i *store.Interaction) *store.Interaction {
	if i == nil {
		return nil
	}
	out := *i
	out.RawState = slices.Clone(i.RawState)
	return &out
}

// --- ConsumedJTIStore --------------------------------------------------------

type jtiStore struct {
	mu    sync.RWMutex
	clock Clock
	m     map[string]time.Time
}

func newJTIStore(c Clock) *jtiStore {
	return &jtiStore{clock: c, m: make(map[string]time.Time)}
}

func (s *jtiStore) Mark(_ context.Context, jti string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.m[jti]; ok {
		// Treat expired entries as absent so a fresh mark may succeed.
		if !isExpired(existing, s.clock) {
			return store.ErrAlreadyConsumed
		}
	}
	s.m[jti] = expiresAt
	return nil
}

func (s *jtiStore) Has(_ context.Context, jti string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	expiresAt, ok := s.m[jti]
	if !ok {
		return false, nil
	}
	if isExpired(expiresAt, s.clock) {
		return false, nil
	}
	return true, nil
}

// --- helpers -----------------------------------------------------------------

// isExpired reports whether t is strictly before clock.Now. The zero time is
// treated as "no expiry" so records may opt out of expiry by leaving the
// field unset.
func isExpired(t time.Time, clock Clock) bool {
	if t.IsZero() {
		return false
	}
	return t.Before(clock.Now())
}
