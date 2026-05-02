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
// strictly before [Clock.Now()] is treated as absent: the lookup returns
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

	clients            *clientStore
	authCodes          *authCodeStore
	refreshes          *refreshStore
	grants             *grantStore
	sessions           *sessionStore
	pars               *parStore
	interactions       *interactionStore
	jtis               *jtiStore
	users              *userStore
	iats               *iatStore
	rats               *ratStore
	totps              *totpStore
	recoveries         *recoveryStore
	passkeys           *passkeyStore
	emailotps          *emailOTPStore
	accessTokens       *accessTokenStore
	opaqueAccessTokens *opaqueAccessTokenStore
	grantRevocations   *grantRevocationStore
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
	s.users = newUserStore()
	s.iats = newIATStore()
	s.rats = newRATStore()
	s.totps = newTOTPStore()
	s.recoveries = newRecoveryStore()
	s.passkeys = newPasskeyStore()
	s.emailotps = newEmailOTPStore(s.clock)
	s.accessTokens = newAccessTokenStore()
	s.opaqueAccessTokens = newOpaqueAccessTokenStore()
	s.grantRevocations = newGrantRevocationStore()
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

// Users implements [store.Store].
func (s *Store) Users() store.UserStore { return s.users }

// InitialAccessTokens implements [store.Store].
func (s *Store) InitialAccessTokens() store.InitialAccessTokenStore { return s.iats }

// RegistrationAccessTokens implements [store.Store].
func (s *Store) RegistrationAccessTokens() store.RegistrationAccessTokenStore { return s.rats }

// AccessTokens implements [store.Store]. The reference implementation
// keeps one row per issued JWT access token and marks rows revoked
// rather than deleting them so the token endpoint can distinguish
// "expired and dropped" from "revoked but still inside its TTL".
func (s *Store) AccessTokens() store.AccessTokenRegistry { return s.accessTokens }

// OpaqueAccessTokens implements [store.Store]. The reference
// implementation keys rows by the SHA-256 digest of the raw bearer id
// (ADR 0024 §S.2) so a heap dump cannot reconstruct an issued
// credential. Revocation flips a flag rather than deleting the row so
// audit metadata remains recoverable.
func (s *Store) OpaqueAccessTokens() store.OpaqueAccessTokenStore { return s.opaqueAccessTokens }

// GrantRevocations implements [store.Store] (ADR 0025). The reference
// implementation keeps two maps under one mutex: tombstones keyed by
// GrantID and a JTI denylist; the lookup order honours the contract's
// "denylist first, tombstone second" precedence. Both row shapes are
// plain strings -- GrantID is internal and JTI is a non-secret claim,
// so no hash-on-store contract applies.
func (s *Store) GrantRevocations() store.GrantRevocationStore { return s.grantRevocations }

// TOTPs returns the [store.TOTPStore] backed by this Store. The
// substore is not part of the aggregate [store.Store] interface (the
// MFA wiring lives behind a future op option) but the accessor is
// exposed here so the authn package and its tests can reach the
// reference implementation without forking the in-memory backend.
func (s *Store) TOTPs() store.TOTPStore { return s.totps }

// RecoveryCodes returns the [store.RecoveryStore] backed by this Store.
// The substore is not part of the aggregate [store.Store] interface
// (the recovery-code wiring lives behind a future op option) but the
// accessor is exposed here so the authn package and its tests can
// reach the reference implementation without forking the in-memory
// backend.
func (s *Store) RecoveryCodes() store.RecoveryStore { return s.recoveries }

// Passkeys returns the [store.PasskeyStore] backed by this Store. The
// substore is not part of the aggregate [store.Store] interface (the
// passkey wiring lives behind a future op option) but the accessor is
// exposed here so the authn package and its tests can reach the
// reference implementation without forking the in-memory backend.
func (s *Store) Passkeys() store.PasskeyStore { return s.passkeys }

// EmailOTPs returns the [store.EmailOTPStore] backed by this Store.
// Like [Store.TOTPs] / [Store.Passkeys] the substore is not part of
// the aggregate [store.Store] interface — the email-OTP wiring lives
// behind [op.NewEmailOTPAuthenticator] — but the accessor is exposed
// here so the authn package and its tests can reach the reference
// implementation without forking the in-memory backend.
func (s *Store) EmailOTPs() store.EmailOTPStore { return s.emailotps }

// PutUser seeds the in-memory user store with u so tests can drive
// /userinfo and id_token claim assembly without standing up a real
// backend. Calling PutUser with a Subject that already exists overwrites
// the prior record; the helper is intentionally lenient because the
// reference implementation targets tests, not production.
func (s *Store) PutUser(_ context.Context, u *store.User) {
	s.users.put(u)
}

// PutUserWithPassword seeds u together with a username→subject mapping
// and the supplied PHC-encoded password hash so tests can drive the
// PrimaryPassword Step end-to-end. The password hash is stored verbatim;
// callers are responsible for encoding (typically via
// [internal/authn/password.NewHasher]). The helper overwrites any prior
// record for the same Subject.
func (s *Store) PutUserWithPassword(_ context.Context, u *store.User, username string, passwordHash []byte) {
	s.users.putWithPassword(u, username, passwordHash)
}

// UserPasswords returns the in-memory implementation of
// [store.UserPasswordStore], the substore the built-in PrimaryPassword
// Step requires. The returned value is the same underlying state as
// [Store.Users]; the split lets callers wire the password-only API
// where the LoginFlow compiler expects [store.UserPasswordStore].
func (s *Store) UserPasswords() store.UserPasswordStore { return s.users }

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
		parStaging: &parStaging{
			parent:  s.pars,
			added:   make(map[string]*store.PushedAuthRequest),
			updated: make(map[string]*store.PushedAuthRequest),
		},
	}
	return t, nil
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
	key := hashKey(token.ID)
	if _, exists := s.m[key]; exists {
		return store.ErrAlreadyExists
	}
	s.m[key] = storeRefresh(token, key)
	return nil
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
		return nil, store.ErrAlreadyConsumed
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
	revokeChainLocked(s.m, rootKey, now)
	return nil
}

// storeRefresh produces the in-memory representation of token: a clone
// with the raw ID replaced by its hash key. Storing the digest as the
// map key means a snapshot of the underlying map (heap dump, debugger
// inspection) cannot reconstruct the bearer secret the OP issued.
// ParentID is left as the raw parent identifier so callers reading the
// record back via Find / Consume see the same value they passed in;
// [revokeOneGeneration] hashes ParentID on the fly to walk into the
// hash-keyed map.
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
	for _, rec := range s.m {
		if rec.GrantID == grantID {
			markRevoked(rec, now)
		}
	}
	return nil
}

// revokeChainLocked walks the parent pointers in m starting at rootID and
// stamps ConsumedAt on rootID and every descendant. The traversal repeatedly
// scans m until a full pass adds no new revocations; this keeps the helper
// O(n^2) but tolerates parents that appear after their children in the map.
func revokeChainLocked(m map[string]*store.RefreshToken, rootID string, now time.Time) {
	markRevoked(m[rootID], now)
	revoked := map[string]struct{}{rootID: {}}
	for revokeOneGeneration(m, revoked, now) {
	}
}

// revokeOneGeneration scans m and stamps every record whose parent is already
// in revoked. Returns true if any new record was added so the caller can loop
// until a fixed point.
//
// The map keys are SHA-256 hashes of the raw bearer secret (see
// [storeRefresh]); [store.RefreshToken.ParentID] is stored as the raw
// parent identifier. The walk hashes ParentID on the fly so the
// parent-revoked check is a single map lookup keyed on the digest.
func revokeOneGeneration(m map[string]*store.RefreshToken, revoked map[string]struct{}, now time.Time) bool {
	grew := false
	for id, rec := range m {
		if _, already := revoked[id]; already {
			continue
		}
		if rec.ParentID == nil {
			continue
		}
		parentKey := hashKey(*rec.ParentID)
		if _, parentRevoked := revoked[parentKey]; !parentRevoked {
			continue
		}
		markRevoked(rec, now)
		revoked[id] = struct{}{}
		grew = true
	}
	return grew
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

// ListBySubject mirrors [FindBySubjectClient] but enumerates every
// grant the subject currently holds. The implementation walks the
// in-memory map and returns clones so the caller can mutate the slice
// without racing the store. When historical (per-update) records exist
// for the same (subject, clientID) pair, the latest UpdatedAt wins —
// the same precedence rule [FindBySubjectClient] applies — so the
// caller observes one entry per consented client even if the embedder
// has not pruned superseded rows.
func (s *grantStore) ListBySubject(_ context.Context, subject string) ([]*store.Grant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	latest := make(map[string]*store.Grant)
	for _, rec := range s.m {
		if rec.Subject != subject {
			continue
		}
		current, ok := latest[rec.ClientID]
		if !ok || rec.UpdatedAt.After(current.UpdatedAt) {
			latest[rec.ClientID] = rec
		}
	}
	out := make([]*store.Grant, 0, len(latest))
	for _, rec := range latest {
		out = append(out, cloneGrant(rec))
	}
	return out, nil
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
	out.AMR = slices.Clone(g.AMR)
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
	key := hashKey(par.URI)
	if _, exists := s.m[key]; exists {
		return store.ErrAlreadyExists
	}
	stored := clonePAR(par)
	stored.URI = key
	s.m[key] = stored
	return nil
}

func (s *parStore) Find(_ context.Context, uri string) (*store.PushedAuthRequest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := hashKey(uri)
	rec, ok := s.m[key]
	if !ok {
		return nil, store.ErrNotFound
	}
	if !constantTimeKeyMatch(rec.URI, key) {
		return nil, store.ErrNotFound
	}
	if isExpired(rec.ExpiresAt, s.clock) {
		return nil, store.ErrNotFound
	}
	out := clonePAR(rec)
	out.URI = uri
	return out, nil
}

func (s *parStore) Consume(_ context.Context, uri string) (*store.PushedAuthRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hashKey(uri)
	rec, ok := s.m[key]
	if !ok {
		return nil, store.ErrNotFound
	}
	if !constantTimeKeyMatch(rec.URI, key) {
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
	out := clonePAR(rec)
	out.URI = uri
	return out, nil
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

// --- UserStore ---------------------------------------------------------------

type userStore struct {
	mu        sync.RWMutex
	m         map[string]*store.User
	usernames map[string]string // username → subject
	hashes    map[string][]byte // subject → PHC-encoded password hash
}

func newUserStore() *userStore {
	return &userStore{
		m:         make(map[string]*store.User),
		usernames: make(map[string]string),
		hashes:    make(map[string][]byte),
	}
}

func (s *userStore) FindBySubject(_ context.Context, sub string) (*store.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.m[sub]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneUser(u), nil
}

func (s *userStore) FindByUsername(_ context.Context, username string) (*store.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sub, ok := s.usernames[username]
	if !ok {
		return nil, store.ErrNotFound
	}
	u, ok := s.m[sub]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneUser(u), nil
}

func (s *userStore) ReadPasswordHash(_ context.Context, subject string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	hash, ok := s.hashes[subject]
	if !ok || len(hash) == 0 {
		return nil, store.ErrNotFound
	}
	out := make([]byte, len(hash))
	copy(out, hash)
	return out, nil
}

func (s *userStore) put(u *store.User) {
	if u == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[u.Subject] = cloneUser(u)
}

func (s *userStore) putWithPassword(u *store.User, username string, hash []byte) {
	if u == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[u.Subject] = cloneUser(u)
	if username != "" {
		s.usernames[username] = u.Subject
	}
	if len(hash) > 0 {
		stored := make([]byte, len(hash))
		copy(stored, hash)
		s.hashes[u.Subject] = stored
	}
}

func cloneUser(u *store.User) *store.User {
	if u == nil {
		return nil
	}
	out := *u
	if u.Claims != nil {
		out.Claims = maps.Clone(u.Claims)
	}
	return &out
}

// --- InitialAccessTokenStore -------------------------------------------------

type iatStore struct {
	mu sync.Mutex
	m  map[string]*store.InitialAccessToken
	// byHash indexes records by [store.InitialAccessToken.HashedValue]
	// so [GetByHash] is a single map lookup rather than a linear scan
	// over m. The two maps share the same record pointer; mutations
	// through Put / IncrementUses are visible through both views.
	byHash map[string]*store.InitialAccessToken
}

func newIATStore() *iatStore {
	return &iatStore{
		m:      make(map[string]*store.InitialAccessToken),
		byHash: make(map[string]*store.InitialAccessToken),
	}
}

func (s *iatStore) Put(_ context.Context, t *store.InitialAccessToken) error {
	if t == nil {
		return errors.New("inmem: nil initial access token")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.m[t.ID]; exists {
		return store.ErrAlreadyExists
	}
	rec := cloneIAT(t)
	s.m[t.ID] = rec
	if rec.HashedValue != "" {
		s.byHash[rec.HashedValue] = rec
	}
	return nil
}

// GetByHash looks the IAT up by its [InitialAccessToken.HashedValue]
// in O(1) via the byHash index. The caller hashes the presented bearer
// secret (SHA-256, hex-encoded) and passes the digest verbatim; the
// constant-time compare against the stored digest is a structural
// belt-and-braces guard that guarantees safety even if a future
// refactor switches the index to a slice scan.
func (s *iatStore) GetByHash(_ context.Context, hash string) (*store.InitialAccessToken, error) {
	if hash == "" {
		return nil, store.ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.byHash[hash]
	if !ok {
		return nil, store.ErrNotFound
	}
	if !constantTimeKeyMatch(rec.HashedValue, hash) {
		return nil, store.ErrNotFound
	}
	return cloneIAT(rec), nil
}

// IncrementUses atomically increments the Uses counter and reports the new
// value. The contract test relies on this being read-modify-write under a
// single mutex; the reference implementation is single-process by design.
// IncrementUses returns [store.ErrConflict] when the new value would exceed
// MaxUses (with MaxUses==0 treated as a single-use ceiling of 1) so the
// caller can treat the attempt as a replay race rather than an absent IAT.
func (s *iatStore) IncrementUses(_ context.Context, id string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.m[id]
	if !ok {
		return 0, store.ErrNotFound
	}
	newUses := rec.Uses + 1
	ceiling := rec.MaxUses
	if ceiling == 0 {
		ceiling = 1
	}
	if newUses > ceiling {
		return rec.Uses, store.ErrConflict
	}
	rec.Uses = newUses
	return newUses, nil
}

func (s *iatStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.m[id]
	if !ok {
		return store.ErrNotFound
	}
	delete(s.m, id)
	if rec != nil && rec.HashedValue != "" {
		// Only drop the byHash entry when it still points at this
		// record; a colliding HashedValue rotation could otherwise
		// orphan the surviving entry.
		if cur, present := s.byHash[rec.HashedValue]; present && cur == rec {
			delete(s.byHash, rec.HashedValue)
		}
	}
	return nil
}

func cloneIAT(t *store.InitialAccessToken) *store.InitialAccessToken {
	if t == nil {
		return nil
	}
	out := *t
	out.AllowedScopes = slices.Clone(t.AllowedScopes)
	return &out
}

// --- RegistrationAccessTokenStore --------------------------------------------

type ratStore struct {
	mu sync.Mutex
	m  map[string]*store.RegistrationAccessToken
}

func newRATStore() *ratStore {
	return &ratStore{m: make(map[string]*store.RegistrationAccessToken)}
}

func (s *ratStore) Put(_ context.Context, t *store.RegistrationAccessToken) error {
	if t == nil {
		return errors.New("inmem: nil registration access token")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[t.ClientID] = cloneRAT(t)
	return nil
}

func (s *ratStore) GetByClientID(_ context.Context, clientID string) (*store.RegistrationAccessToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.m[clientID]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneRAT(rec), nil
}

func (s *ratStore) Delete(_ context.Context, clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[clientID]; !ok {
		return store.ErrNotFound
	}
	delete(s.m, clientID)
	return nil
}

func cloneRAT(t *store.RegistrationAccessToken) *store.RegistrationAccessToken {
	if t == nil {
		return nil
	}
	out := *t
	return &out
}
