// Package inmem provides an in-memory reference implementation of every
// substore declared in [github.com/libraz/go-oidc-provider/op/store]. It is
// the backend the library tests run against, the seed for the testkit, and
// the smallest possible illustration of the storage contract for embedders
// who want a working example before plugging in a real database.
//
// # Scope
//
// The package implements a single concrete type, [Store], that satisfies
// [store.Store], [store.ClientRegistry], [store.StaticClientReconciler], and
// [store.Transactional]. Every substore lives behind its own [sync.RWMutex]
// for read/write isolation;
// transactions are serialised through a process-wide mutex and hold the seven
// atomic-cluster locks until completion. The implementation is deliberately
// simple -- it is a reference, not a production engine -- and trades
// throughput for clarity.
//
// # Concurrency model
//
// Each substore guards its map with a [sync.RWMutex]. A [store.Tx] obtained
// from [Store.BeginTx] takes the process-wide transaction mutex followed by
// every atomic-cluster substore lock in a fixed order. Direct reads and writes
// to those substores block until Commit or Rollback releases the locks. Commit
// applies every staged change before releasing any lock, so readers cannot
// observe a partially committed cluster and a concurrent direct write cannot
// be overwritten by snapshot replacement. The refresh-token substore maintains
// client-ID and grant-ID secondary indexes under that same lock and commit
// boundary, keeping administrative revocation proportional to its target set.
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
// [store.ErrNotFound] and Consume returns the same.
//
// # Reclamation
//
// Expired records are not merely hidden, they are reclaimed. Every
// substore whose map can be grown by an unauthenticated request sweeps
// itself: authorization codes, sessions, interactions, PAR records,
// consumed JTIs, device codes, CIBA requests, and the cross-factor
// lockout counters each run a full sweep once a fixed number of writes
// has accumulated since the last one, so a write costs O(1) amortised
// rather than O(total records). Records that collide with the exact key
// an insert is claiming are evicted immediately, without waiting for the
// sweep, so a reused request_uri, device_code, user_code, or
// auth_req_id is never rejected as a duplicate of a dead row.
//
// Refresh tokens are deliberately not on that list. Growing the map
// takes an authenticated token exchange, so it is not a vector an
// unauthenticated caller can drive, and the records outlive their own
// expiry on purpose: replay revocation walks a rotation chain from the
// deepest record it can resolve, and a chain's oldest record is the
// first to expire. Reclaiming rows on their own expiry alone would
// shorten the chain a cascade can reach — see the same reasoning behind
// the SQL adapter's per-grant retention. A long-running process holds
// the full rotation history of every grant it has issued.
//
// A sweep only removes records the lookup paths already treat as
// absent, so it cannot change what a caller observes. The lockout
// counters carry no ExpiresAt and are instead retired once their lock
// has lapsed and their window anchor has aged out, which is the point
// at which the library's own rolling-window rollover would reset them.
//
// Substores whose rows have no expiry (clients, users, grants,
// metadata, enrolled authentication factors) are owned by the embedder
// and are never swept.
package inmem

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/patterns"
)

// Clock returns the wall-clock time used to evaluate record expiry. It is
// declared here rather than imported from [github.com/libraz/go-oidc-provider/op]
// so that the inmem package can be used by the op package itself without a
// circular dependency. Every clock the library passes around has the same
// single-method shape, so an [op.Clock] — or anything else with a
// Now() time.Time method — satisfies this one structurally.
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

	// txMu serialises [Store.BeginTx] callers. Each transaction also owns
	// all seven atomic-cluster substore locks for its lifetime; txMu keeps
	// transaction acquisition itself single-file and documents that nested
	// transactions are unsupported.
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
	authnLockouts      *authnLockoutStore
	accessTokens       *accessTokenStore
	opaqueAccessTokens *opaqueAccessTokenStore
	grantRevocations   *grantRevocationStore
	metadata           *metadataStore
	deviceCodes        *deviceCodeStore
	cibaRequests       *cibaRequestStore
}

var _ store.StaticClientReconciler = (*Store)(nil)

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
	s.authnLockouts = newAuthnLockoutStore(s.clock)
	s.accessTokens = newAccessTokenStore()
	s.opaqueAccessTokens = newOpaqueAccessTokenStore()
	s.grantRevocations = newGrantRevocationStore()
	s.metadata = newMetadataStore()
	s.deviceCodes = newDeviceCodeStore(s.clock)
	s.cibaRequests = newCIBARequestStore(s.clock)
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
// so a heap dump cannot reconstruct an issued credential. Revocation
// flips a flag rather than deleting the row so audit metadata remains
// recoverable.
func (s *Store) OpaqueAccessTokens() store.OpaqueAccessTokenStore { return s.opaqueAccessTokens }

// GrantRevocations implements [store.Store]. The reference
// implementation keeps two maps under one mutex: tombstones keyed by
// GrantID and a JTI denylist; the lookup order honours the contract's
// "denylist first, tombstone second" precedence. Both row shapes are
// plain strings -- GrantID is internal and JTI is a non-secret claim,
// so no hash-on-store contract applies.
func (s *Store) GrantRevocations() store.GrantRevocationStore { return s.grantRevocations }

// Metadata implements [store.Store]. The reference implementation
// keeps a single map under one mutex; the substore is consulted by
// the pairwise immutability gate at op.New and by no other code path
// in v0.9.1, so a simple key/value map satisfies every documented
// access pattern.
func (s *Store) Metadata() store.MetadataStore { return s.metadata }

// DeviceCodes implements [store.Store]. The reference implementation
// keys the primary map on the SHA-256 digest of the wire device_code
// and maintains a secondary user_code → digest index so the
// verification page's FindByUserCode lookup runs without scanning the
// primary map. Outside the transactional cluster: the approve→consume
// CAS in [DeviceCodeStore.Consume] supplies the single-use guarantee
// on its own.
func (s *Store) DeviceCodes() store.DeviceCodeStore { return s.deviceCodes }

// CIBARequests implements [store.Store].
func (s *Store) CIBARequests() store.CIBARequestStore { return s.cibaRequests }

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

// AuthnLockouts returns the [store.AuthnLockoutStore] backed by this
// Store. The cross-factor brute-force counter is not part of the
// aggregate [store.Store] interface — the wiring lives behind the
// lockout helper consumed by the per-factor authenticators — but the
// accessor is exposed here so the authn package and its tests can
// reach the reference implementation without forking the in-memory
// backend.
func (s *Store) AuthnLockouts() store.AuthnLockoutStore { return s.authnLockouts }

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
// PrimaryPassword Step end-to-end. The password hash is stored verbatim
// and the caller owns the encoding, typically through
// [github.com/libraz/go-oidc-provider/op.HashPassword]: nothing here
// hashes on the caller's behalf, so seeding a plaintext value produces
// a record no login can ever match. The helper overwrites any prior
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

// ReconcileStaticClients implements [store.StaticClientReconciler]. The
// client store stages the complete batch under one lock and publishes the
// snapshot only after every record has been checked.
func (s *Store) ReconcileStaticClients(ctx context.Context, clients []*store.Client) error {
	return s.clients.ReconcileStatic(ctx, clients)
}

// GetClient implements [store.ClientStore].
func (s *Store) GetClient(ctx context.Context, id string) (*store.Client, error) {
	return s.clients.GetClient(ctx, id)
}

// BeginTx implements [store.Transactional]. The returned [store.Tx] holds the
// process-wide tx mutex and stages writes that are flushed atomically on
// [store.Tx.Commit] and discarded on [store.Tx.Rollback].
//
// Every substore in the cluster stages through an overlay onto the
// committed map rather than a copy of it, so the cost of starting a
// transaction is a fixed set of empty maps and does not grow with the
// number of records the store holds.
func (s *Store) BeginTx(ctx context.Context) (store.Tx, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.txMu.Lock()
	s.lockTxCluster()
	if err := ctx.Err(); err != nil {
		s.unlockTxCluster()
		s.txMu.Unlock()
		return nil, err
	}
	t := &tx{
		owner: s,
		clock: s.clock,
		acStaging: &authCodeStaging{
			parent:  s.authCodes,
			added:   make(map[string]*store.AuthorizationCode),
			updated: make(map[string]*store.AuthorizationCode),
		},
		rtStaging: &refreshStaging{
			parent:   s.refreshes,
			added:    make(map[string]*store.RefreshToken),
			updated:  make(map[string]*store.RefreshToken),
			byClient: make(refreshIndex),
			byGrant:  make(refreshIndex),
			revoked:  make(map[string]struct{}),
			retries:  make(map[string][]byte),
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
		atStaging:  newAccessTokenStaging(s.accessTokens),
		oatStaging: newOpaqueAccessTokenStaging(s.opaqueAccessTokens),
		grvStaging: newGrantRevocationStaging(s.grantRevocations),
	}
	return t, nil
}

// lockTxCluster acquires every atomic-cluster substore lock in declaration
// order. No direct operation holds more than one of these locks, and every
// transaction uses this exact order, preventing lock-order inversion.
func (s *Store) lockTxCluster() {
	s.authCodes.mu.Lock()
	s.refreshes.mu.Lock()
	s.grants.mu.Lock()
	s.pars.mu.Lock()
	s.accessTokens.mu.Lock()
	s.opaqueAccessTokens.mu.Lock()
	s.grantRevocations.mu.Lock()
}

// unlockTxCluster releases the atomic-cluster locks in reverse acquisition
// order. Commit calls this only after all seven parent maps have their final
// state, preserving all-or-nothing visibility across direct readers.
func (s *Store) unlockTxCluster() {
	s.grantRevocations.mu.Unlock()
	s.opaqueAccessTokens.mu.Unlock()
	s.accessTokens.mu.Unlock()
	s.pars.mu.Unlock()
	s.grants.mu.Unlock()
	s.refreshes.mu.Unlock()
	s.authCodes.mu.Unlock()
}

// --- RefreshTokenStore -------------------------------------------------------

type refreshStore struct {
	mu       sync.RWMutex
	clock    Clock
	m        map[string]*store.RefreshToken
	byClient refreshIndex
	byGrant  refreshIndex
	retries  map[string][]byte
}

func newRefreshStore(c Clock) *refreshStore {
	return &refreshStore{
		clock:    c,
		m:        make(map[string]*store.RefreshToken),
		byClient: make(refreshIndex),
		byGrant:  make(refreshIndex),
		retries:  make(map[string][]byte),
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
	stored := storeRefresh(token, key)
	s.m[key] = stored
	s.indexRefreshLocked(key, stored)
	s.retries[hashKey(*token.ParentID)] = append([]byte(nil), sealed...)
	return nil
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

func (s *refreshStore) LoadRetryResponse(_ context.Context, predecessorID string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sealed, ok := s.retries[hashKey(predecessorID)]
	if !ok {
		return nil, store.ErrNotFound
	}
	return append([]byte(nil), sealed...), nil
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

// refreshIndex maps one stable record attribute to the hashed primary keys
// carrying that value. Refresh-token rows are retained after revocation for
// replay detection and audit, so their immutable ClientID and GrantID entries
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
	out.AMR = slices.Clone(t.AMR)
	out.AuthorizationDetails = cloneObjectArray(t.AuthorizationDetails)
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

// ListBySubject enumerates every grant the subject currently holds.
// The implementation walks the in-memory map and returns clones so the
// caller can mutate the slice without racing the store. Unlike
// FindBySubjectClient, it intentionally does not collapse duplicate
// (subject, clientID) rows: callers that revoke by listing must see
// every active grant so no orphaned token chain survives.
func (s *grantStore) ListBySubject(_ context.Context, subject string) ([]*store.Grant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*store.Grant, 0)
	for _, rec := range s.m {
		if rec.Subject != subject {
			continue
		}
		out = append(out, cloneGrant(rec))
	}
	return out, nil
}

func (s *grantStore) ListClientIDsBySubject(
	ctx context.Context,
	subject, cursor string,
	limit int,
) (store.GrantClientPage, error) {
	if err := ctx.Err(); err != nil {
		return store.GrantClientPage{}, err
	}
	if limit <= 0 {
		return store.GrantClientPage{}, errors.New("inmem: grant client page limit must be positive")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	builder := newGrantClientPageBuilder(cursor, limit)
	for _, rec := range s.m {
		if rec.Subject == subject {
			builder.add(rec.ClientID)
		}
	}
	return builder.page(), nil
}

// grantClientPageBuilder retains only the lexicographically-smallest limit
// distinct IDs after cursor. Scanning an in-memory map is unavoidable, but
// candidate storage remains O(limit) even when every grant has a unique client.
type grantClientPageBuilder struct {
	cursor    string
	limit     int
	clientIDs []string
	more      bool
	peak      int
}

func newGrantClientPageBuilder(cursor string, limit int) *grantClientPageBuilder {
	return &grantClientPageBuilder{cursor: cursor, limit: limit}
}

func (b *grantClientPageBuilder) add(clientID string) {
	if clientID == "" || clientID <= b.cursor {
		return
	}
	index := sort.SearchStrings(b.clientIDs, clientID)
	if index < len(b.clientIDs) && b.clientIDs[index] == clientID {
		return
	}
	if len(b.clientIDs) < b.limit {
		b.clientIDs = append(b.clientIDs, "")
		copy(b.clientIDs[index+1:], b.clientIDs[index:])
		b.clientIDs[index] = clientID
		b.peak = max(b.peak, len(b.clientIDs))
		return
	}
	b.more = true
	if index == len(b.clientIDs) {
		return
	}
	copy(b.clientIDs[index+1:], b.clientIDs[index:len(b.clientIDs)-1])
	b.clientIDs[index] = clientID
}

func (b *grantClientPageBuilder) page() store.GrantClientPage {
	page := store.GrantClientPage{ClientIDs: b.clientIDs}
	if b.more {
		page.NextCursor = b.clientIDs[len(b.clientIDs)-1]
	}
	return page
}

func (s *grantStore) HasAny(_ context.Context) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.m) > 0, nil
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

// RevokeByClient implements [store.RevokeByClient]. The dynamic
// registration cascade calls it so a deleted client takes its
// outstanding grants with it. A non-existent client is a no-op.
func (s *grantStore) RevokeByClient(_ context.Context, clientID string) error {
	if clientID == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, rec := range s.m {
		if rec.ClientID == clientID {
			delete(s.m, id)
		}
	}
	return nil
}

func cloneGrant(g *store.Grant) *store.Grant {
	if g == nil {
		return nil
	}
	out := *g
	out.Scope = slices.Clone(g.Scope)
	out.Claims = cloneMap(g.Claims)
	out.AMR = slices.Clone(g.AMR)
	out.AuthorizationDetails = cloneObjectArray(g.AuthorizationDetails)
	return &out
}

// cloneObjectArray deep-copies a []map[string]any (the RFC 9396
// authorization_details), including nested JSON maps and arrays, so a stored
// grant cannot be mutated through a caller-held reference.
func cloneObjectArray(in []map[string]any) []map[string]any {
	if in == nil {
		return nil
	}
	out := make([]map[string]any, len(in))
	for i, m := range in {
		out[i] = cloneMap(m)
	}
	return out
}

func cloneMap(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = cloneJSONValue(v)
	}
	return out
}

// cloneJSONValue recursively copies maps and slices while preserving their Go
// type. Claims and authorization details accept arbitrary JSON-compatible
// values, so cloning only map[string]any / []any would still alias legitimate
// typed values such as []string or map[string][]any.
func cloneJSONValue(v any) any {
	rv := reflect.ValueOf(v)
	if !rv.IsValid() {
		return nil
	}
	return cloneJSONReflect(rv).Interface()
}

func cloneJSONReflect(v reflect.Value) reflect.Value {
	switch v.Kind() {
	case reflect.Interface:
		if v.IsNil() {
			return reflect.Zero(v.Type())
		}
		out := reflect.New(v.Type()).Elem()
		out.Set(cloneJSONReflect(v.Elem()))
		return out
	case reflect.Map:
		if v.IsNil() {
			return reflect.Zero(v.Type())
		}
		out := reflect.MakeMapWithSize(v.Type(), v.Len())
		iter := v.MapRange()
		for iter.Next() {
			out.SetMapIndex(iter.Key(), cloneJSONReflect(iter.Value()))
		}
		return out
	case reflect.Slice:
		if v.IsNil() {
			return reflect.Zero(v.Type())
		}
		out := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		length := v.Len()
		for i := range length {
			out.Index(i).Set(cloneJSONReflect(v.Index(i)))
		}
		return out
	default:
		return v
	}
}

// --- SessionStore ------------------------------------------------------------

type sessionStore struct {
	mu           sync.RWMutex
	clock        Clock
	m            map[string]*store.Session
	savesSinceGC uint32
}

// sessionFullGCSaveInterval is how many Save calls pass between full
// sweeps of the session map. Every unauthenticated login attempt that
// reaches the session step can create a row, so the map needs
// reclamation; sweeping on each Save would make every login cost
// O(total sessions).
const sessionFullGCSaveInterval uint32 = 64

func newSessionStore(c Clock) *sessionStore {
	return &sessionStore{clock: c, m: make(map[string]*store.Session)}
}

func (s *sessionStore) Save(_ context.Context, sess *store.Session) error {
	if sess == nil {
		return errors.New("inmem: nil session")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maybeGCLocked(s.clock.Now())
	s.m[sess.ID] = cloneSession(sess)
	return nil
}

// gcLocked drops every session whose ExpiresAt has passed. Find, Touch,
// ListByChooserGroup, and Delete all treat an expired session as
// absent, so removing it cannot change what a caller observes on any
// path.
func (s *sessionStore) gcLocked(now time.Time) {
	for id, rec := range s.m {
		if isExpiredAtStrict(rec.ExpiresAt, now) {
			delete(s.m, id)
		}
	}
	s.savesSinceGC = 0
}

func (s *sessionStore) maybeGCLocked(now time.Time) {
	s.savesSinceGC++
	if s.savesSinceGC < sessionFullGCSaveInterval {
		return
	}
	s.gcLocked(now)
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
	rec, ok := s.m[id]
	if !ok {
		return store.ErrNotFound
	}
	// Reclaim the entry either way, but report an expired record as
	// absent: the contract makes the answer turn on ExpiresAt, not on
	// whether the sweep has reached this key yet.
	delete(s.m, id)
	if isExpired(rec.ExpiresAt, s.clock) {
		return store.ErrNotFound
	}
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
	mu           sync.RWMutex
	clock        Clock
	m            map[string]*store.PushedAuthRequest
	savesSinceGC uint32
}

const parFullGCSaveInterval uint32 = 64

func newPARStore(c Clock) *parStore {
	return &parStore{clock: c, m: make(map[string]*store.PushedAuthRequest)}
}

func (s *parStore) Save(_ context.Context, par *store.PushedAuthRequest) error {
	if par == nil {
		return errors.New("inmem: nil pushed authorization request")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock.Now()
	key := hashKey(par.URI)
	s.deleteExpiredKeyLocked(key, now)
	s.maybeGCLocked(now)
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
	// Consume enforces single-use only; expiry is gated at presentation
	// by Find (see store.PushedAuthRequestStore.Consume). An interactive
	// login that outlives the request_uri lifetime still redeems here.
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

func (s *parStore) gcLocked(now time.Time) {
	for key, rec := range s.m {
		if !rec.ExpiresAt.IsZero() && now.UTC().After(rec.ExpiresAt.UTC()) {
			delete(s.m, key)
		}
	}
	s.savesSinceGC = 0
}

func (s *parStore) maybeGCLocked(now time.Time) {
	s.savesSinceGC++
	if s.savesSinceGC < parFullGCSaveInterval {
		return
	}
	s.gcLocked(now)
}

func (s *parStore) deleteExpiredKeyLocked(key string, now time.Time) {
	rec, ok := s.m[key]
	if !ok {
		return
	}
	if !rec.ExpiresAt.IsZero() && now.UTC().After(rec.ExpiresAt.UTC()) {
		delete(s.m, key)
	}
}

// --- InteractionStore --------------------------------------------------------

type interactionStore struct {
	mu           sync.RWMutex
	clock        Clock
	m            map[string]*store.Interaction
	savesSinceGC uint32
}

// interactionFullGCSaveInterval is how many Save calls pass between
// full sweeps of the interaction map. An interaction is created by an
// unauthenticated /authorize request and abandoned whenever the user
// walks away, so abandoned rows are the common case rather than the
// exception.
const interactionFullGCSaveInterval uint32 = 64

func newInteractionStore(c Clock) *interactionStore {
	return &interactionStore{clock: c, m: make(map[string]*store.Interaction)}
}

func (s *interactionStore) Save(_ context.Context, i *store.Interaction) error {
	if i == nil {
		return errors.New("inmem: nil interaction")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maybeGCLocked(s.clock.Now())
	s.m[i.ID] = cloneInteraction(i)
	return nil
}

// gcLocked drops every interaction whose ExpiresAt has passed. Find,
// CompareAndSwap, DeleteIfUnchanged, and the unconditional Delete all
// treat an expired interaction as absent and report ErrNotFound, so a
// swept row is indistinguishable from one that was left in place.
func (s *interactionStore) gcLocked(now time.Time) {
	for id, rec := range s.m {
		if isExpiredAtStrict(rec.ExpiresAt, now) {
			delete(s.m, id)
		}
	}
	s.savesSinceGC = 0
}

func (s *interactionStore) maybeGCLocked(now time.Time) {
	s.savesSinceGC++
	if s.savesSinceGC < interactionFullGCSaveInterval {
		return
	}
	s.gcLocked(now)
}

func (s *interactionStore) CompareAndSwap(
	_ context.Context,
	previous, next *store.Interaction,
) error {
	if previous == nil || next == nil || previous.ID == "" || previous.ID != next.ID {
		return errors.New("inmem: invalid interaction compare-and-swap")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.m[previous.ID]
	if !ok || isExpired(current.ExpiresAt, s.clock) {
		return store.ErrNotFound
	}
	if !store.InteractionStateEqual(previous, current) {
		return store.ErrConflict
	}
	s.m[next.ID] = cloneInteraction(next)
	return nil
}

func (s *interactionStore) DeleteIfUnchanged(
	_ context.Context,
	previous *store.Interaction,
) error {
	if previous == nil || previous.ID == "" {
		return errors.New("inmem: invalid conditional interaction delete")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.m[previous.ID]
	if !ok || isExpired(current.ExpiresAt, s.clock) {
		return store.ErrNotFound
	}
	if !store.InteractionStateEqual(previous, current) {
		return store.ErrConflict
	}
	delete(s.m, previous.ID)
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
	rec, ok := s.m[id]
	if !ok {
		return store.ErrNotFound
	}
	// Reclaim the entry either way, but report an expired record as
	// absent: the contract makes the answer turn on ExpiresAt, not on
	// whether the sweep has reached this key yet.
	delete(s.m, id)
	if isExpired(rec.ExpiresAt, s.clock) {
		return store.ErrNotFound
	}
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
	mu           sync.RWMutex
	clock        Clock
	m            map[string]time.Time
	marksSinceGC uint32
}

const jtiFullGCMarkInterval uint32 = 64

func newJTIStore(c Clock) *jtiStore {
	return &jtiStore{clock: c, m: make(map[string]time.Time)}
}

// Mark hashes the supplied jti via [patterns.Digest] before keying
// the map so the raw bearer is never retained in process memory. JWT
// IDs are caller-supplied strings (RFC 7519 sets no upper bound) and a
// heap dump that contains the raw values would let an attacker replay
// proofs against another OP that signed the same key. The digest is
// not a secret; its only purpose is bounded length and one-way derivation.
func (s *jtiStore) Mark(_ context.Context, jti string, expiresAt time.Time) error {
	digest := patterns.Digest(jti)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock.Now()
	if existing, ok := s.m[digest]; ok {
		// Treat expired entries as absent so a fresh mark may succeed.
		if !isExpiredAt(existing, now) {
			return store.ErrAlreadyConsumed
		}
		delete(s.m, digest)
	}
	s.maybeGCJTILocked(now)
	s.m[digest] = expiresAt
	return nil
}

// Has reports whether jti is still marked. The expiry bound is the
// inclusive one [jtiStore.Mark] applies (a marker is expired from its
// expiresAt onwards), so the two methods cannot disagree at the boundary
// instant about whether a jti is consumed; see [store.ConsumedJTIStore].
func (s *jtiStore) Has(_ context.Context, jti string) (bool, error) {
	digest := patterns.Digest(jti)
	s.mu.RLock()
	defer s.mu.RUnlock()
	expiresAt, ok := s.m[digest]
	if !ok {
		return false, nil
	}
	if isExpiredAt(expiresAt, s.clock.Now()) {
		return false, nil
	}
	return true, nil
}

func (s *jtiStore) maybeGCJTILocked(now time.Time) {
	s.marksSinceGC++
	if s.marksSinceGC < jtiFullGCMarkInterval {
		return
	}
	for digest, expiresAt := range s.m {
		if isExpiredAt(expiresAt, now) {
			delete(s.m, digest)
		}
	}
	s.marksSinceGC = 0
}

// isExpiredAt is the inclusive expiry bound the consumed-JTI substore
// uses: a marker is expired from expiresAt onwards, and a zero expiresAt
// never expires. It is deliberately stricter than [isExpired], which
// keeps a record alive at its own expiry instant, because
// [store.ConsumedJTIStore] pins the inclusive boundary for both Mark and
// Has.
func isExpiredAt(expiresAt, now time.Time) bool {
	return patterns.IsExpiredInclusive(expiresAt, now)
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
		out.Claims = cloneMap(u.Claims)
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

// --- MetadataStore -----------------------------------------------------------

type metadataStore struct {
	mu sync.RWMutex
	m  map[string]string
}

func newMetadataStore() *metadataStore {
	return &metadataStore{m: make(map[string]string)}
}

func (s *metadataStore) Get(_ context.Context, key string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.m[key]
	if !ok {
		return "", store.ErrNotFound
	}
	return v, nil
}

func (s *metadataStore) Set(_ context.Context, key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[key] = value
	return nil
}
