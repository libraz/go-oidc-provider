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
// lockout counters each run a full sweep once the writes since the
// last one reach half the map size (at least a fixed minimum), so a write
// costs O(1) amortised rather than O(total records). Records that collide with the exact key
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
// The sealed retry responses attached to those records are swept, on
// their predecessor's own expiry. Nothing about a chain walk needs
// them, the store is forbidden from serving one past that instant, and
// each entry is an encrypted token response rather than a handful of
// fields, so retaining them for the life of the process would grow the
// heap by one response per rotation forever.
//
// PAR records are swept on a retention window measured from their own
// expiry rather than on the expiry itself. Their Consume enforces
// single-use only — expiry is gated at presentation by Find, so a
// request_uri whose short lifetime elapsed during an interactive login
// still redeems at code emission — and a sweep keyed on expiry alone
// would make that redemption depend on how many unrelated pushes
// happened while the user was authenticating.
//
// A sweep only removes records the substore's own read and consume
// paths already reject, so it cannot change what a caller observes.
// The lockout counters carry no ExpiresAt and are instead retired once
// their lock has lapsed and their window anchor has aged out, which is
// the point at which the library's own rolling-window rollover would
// reset them.
//
// Three substores are reclaimed on a cutoff the embedder passes in
// rather than by a sweep of their own: the access-token registry, the
// opaque access tokens, and the grant revocations, whose grant
// tombstones and JTI denylist are collected together. Each implements
// the GC method its interface declares, so an embedder running a
// janitor reclaims them on the schedule it already runs for a SQL
// backend, and a deployment that skips the janitor keeps them. Only an
// authenticated exchange or an administrative revocation adds a row to
// any of the three, so the growth an embedder is choosing to accept is
// bounded by its own clients rather than by an anonymous caller.
//
// Two substores carry an expiry and are reclaimed by neither route,
// because their key space is what bounds them. The email-OTP
// challenges hold one record per subject — a fresh send replaces the
// subject's previous challenge instead of adding to it — so the map is
// bounded by the directory the embedder owns; the stale record is left
// behind deliberately, so its rate-limit and brute-force counters stay
// readable while their windows are live. The initial access tokens exist
// only because an operator minted them, so nothing an unauthenticated
// caller does grows that map either. The email-OTP challenges filter
// expired rows on read, like every other substore here; the initial
// access tokens deliberately do not — [InitialAccessTokenStore.GetByHash]
// MUST return a matching row past its ExpiresAt so the registration
// endpoint can distinguish an expired credential from a forged one.
//
// Registration access tokens appear on none of those lists and belong
// on none: [store.RegistrationAccessToken] carries no expiry or
// retention field at all, so there is nothing for a sweep to key on.
//
// Substores whose rows have no expiry (clients, users, grants,
// metadata, enrolled authentication factors) are owned by the embedder
// and are never swept.
package inmem

import (
	"context"
	"sync"
	"time"

	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
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
	ssfStreams         *ssfStreamStore
	ssfEvents          *ssfEventStore
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
	mfaVersions := newMFAVersionAllocator()
	s.totps = newTOTPStore(mfaVersions)
	s.recoveries = newRecoveryStore(s.clock)
	s.passkeys = newPasskeyStore()
	s.emailotps = newEmailOTPStore(s.clock, mfaVersions)
	s.authnLockouts = newAuthnLockoutStore(s.clock)
	s.accessTokens = newAccessTokenStore()
	s.opaqueAccessTokens = newOpaqueAccessTokenStore()
	s.grantRevocations = newGrantRevocationStore()
	s.metadata = newMetadataStore()
	s.deviceCodes = newDeviceCodeStore(s.clock)
	s.cibaRequests = newCIBARequestStore(s.clock)
	ssf := newSSFState()
	s.ssfStreams = &ssfStreamStore{st: ssf}
	s.ssfEvents = &ssfEventStore{st: ssf}
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
// the pairwise immutability gate at op.New and by no other code path,
// so a simple key/value map satisfies every documented
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
			retries:  make(map[string]retryResponse),
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

// sweepDue reports whether a substore has accumulated enough writes for a
// full sweep. The threshold grows with half the current map size so the sweep
// stays O(1) amortised per write instead of O(live/interval).
func sweepDue(writes, minInterval uint32, live int) bool {
	threshold := uint64(minInterval)
	if l := uint64(max(live, 0)) / 2; l > threshold {
		threshold = l
	}
	return uint64(writes) >= threshold
}
