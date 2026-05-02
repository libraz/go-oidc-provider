// Package composite provides a [github.com/libraz/go-oidc-provider/op/store.Store]
// adapter that routes individual substore [Kind] values to different backends
// while enforcing the cross-backend safety invariants the library relies on.
//
// # Why composite exists
//
// Real deployments commonly want a hot/cold split: persistent records (clients,
// authorization codes, refresh tokens, grants, sessions, PAR) live in a
// durable store such as MySQL or Postgres, while ephemeral records
// (interactions, DPoP/private_key_jwt JTIs) live in a fast volatile store
// such as Redis. The library takes a single [store.Store] value, so the
// composite adapter weaves several backends behind one [Store] facade.
//
// # The transactional cluster invariant
//
// Authorization-code exchange, refresh-token rotation, and PAR consumption
// each touch several substores in the same handler path. If any of those
// substores commit independently, a partial failure leaves a still-redeemable
// record next to a freshly issued one and opens a replay window. To make the
// hazard impossible to misconfigure, the composite adapter validates at
// construction time that every Kind in the [TxClusterKinds] set resolves to
// the SAME backend (the "tx anchor") and that the anchor implements
// [store.Transactional]. Configurations that violate either rule cause [New]
// to return one of the sentinel errors declared in this package; the embedder
// finds out at startup, not at production traffic time.
//
// # Routing
//
// Every Kind MUST be reachable. Callers either route Kinds individually with
// [With] or supply a fallback with [WithDefault]; mixing both is supported
// (per-Kind overrides win over the default). [New] returns
// [ErrKindNotRouted] if any Kind is left unrouted.
//
// # Client registry capability
//
// The composite adapter conditionally exposes [store.ClientRegistry]. When
// the backend routed for [Clients] implements ClientRegistry, the registry is
// available through [Store.ClientRegistry]; otherwise the same call reports
// that the capability is unavailable. This mirrors how the library probes
// other backends for the extension and avoids silently coercing a read-only
// ClientStore into a ClientRegistry.
//
// # Stability
//
// composite is part of the public API of go-oidc-provider and follows the
// same SemVer policy as the root [github.com/libraz/go-oidc-provider/op]
// package.
package composite

import (
	"context"
	"errors"
	"fmt"

	"github.com/libraz/go-oidc-provider/op/store"
)

// Kind enumerates every substore the [store.Store] aggregate exposes. The
// composite adapter routes each Kind to a single backend; the [TxClusterKinds]
// subset additionally requires that all members share one anchor.
type Kind int

// Kind values. The integer values are not part of the API: callers use the
// names. The set is closed; adding new substores to [store.Store] requires
// adding a new Kind here and updating [TxClusterKinds] when the new kind
// participates in atomic commits.
const (
	// Clients routes [store.ClientStore] (and optionally
	// [store.ClientRegistry]) calls. Outside the transactional cluster.
	Clients Kind = iota + 1

	// AuthorizationCodes routes [store.AuthorizationCodeStore] calls.
	// Member of the transactional cluster.
	AuthorizationCodes

	// RefreshTokens routes [store.RefreshTokenStore] calls. Member of the
	// transactional cluster.
	RefreshTokens

	// Grants routes [store.GrantStore] calls. Member of the transactional
	// cluster.
	Grants

	// Sessions routes [store.SessionStore] calls. Outside the transactional
	// cluster: the OP tolerates session loss as a re-login event and does
	// not coordinate Session writes with token-endpoint commits.
	// Embedders MAY route Sessions to a volatile cache (Redis, Memcached)
	// without violating any invariant.
	Sessions

	// PushedAuthRequests routes [store.PushedAuthRequestStore] calls.
	// Member of the transactional cluster.
	PushedAuthRequests

	// Interactions routes [store.InteractionStore] calls. Outside the
	// transactional cluster.
	Interactions

	// ConsumedJTIs routes [store.ConsumedJTIStore] calls. Outside the
	// transactional cluster.
	ConsumedJTIs

	// Users routes [store.UserStore] calls. Outside the transactional
	// cluster.
	Users

	// InitialAccessTokens routes [store.InitialAccessTokenStore] calls.
	// Used by the RFC 7591 dynamic-client-registration endpoint. Outside
	// the transactional cluster.
	InitialAccessTokens

	// RegistrationAccessTokens routes [store.RegistrationAccessTokenStore]
	// calls. Used by the RFC 7592 management endpoints. Outside the
	// transactional cluster.
	RegistrationAccessTokens

	// AccessTokens routes [store.AccessTokenRegistry] calls. Used by
	// the userinfo, introspection, revocation endpoints, and by the
	// code-replay cascade. Part of the transactional cluster: the
	// register-on-issue path commits alongside the matching grant
	// write.
	AccessTokens

	// OpaqueAccessTokens routes [store.OpaqueAccessTokenStore] calls
	// (ADR 0024). Used by the userinfo, introspection, revocation
	// endpoints, and by the code-replay cascade when opt-in opaque
	// access tokens are enabled. Part of the transactional cluster:
	// the save-on-issue path commits alongside the matching grant
	// write.
	OpaqueAccessTokens

	// GrantRevocations routes [store.GrantRevocationStore] calls
	// (ADR 0025). Used by the userinfo, introspection, and revocation
	// endpoints to enforce JWT access-token revocation under the
	// grant-tombstone strategy, and written by the code-replay /
	// logout cascades. Part of the transactional cluster: a tombstone
	// or denylist write commits alongside the matching grant /
	// refresh-token write so a partially-committed cascade cannot
	// leave a still-redeemable grant next to its tombstone.
	GrantRevocations

	// Metadata routes [store.MetadataStore] calls. Outside the
	// transactional cluster: the substore is consulted only by the
	// op.New construction-time pairwise immutability gate.
	Metadata
)

// kindNames maps each [Kind] to its unqualified name. Indexed by Kind value
// so [Kind.String] is a constant-time lookup; the table MUST stay aligned
// with the iota block above.
//
//nolint:gochecknoglobals // closed enumeration; declared once and treated as a constant lookup table.
var kindNames = map[Kind]string{
	Clients:                  "Clients",
	AuthorizationCodes:       "AuthorizationCodes",
	RefreshTokens:            "RefreshTokens",
	Grants:                   "Grants",
	Sessions:                 "Sessions",
	PushedAuthRequests:       "PushedAuthRequests",
	Interactions:             "Interactions",
	ConsumedJTIs:             "ConsumedJTIs",
	Users:                    "Users",
	InitialAccessTokens:      "InitialAccessTokens",
	RegistrationAccessTokens: "RegistrationAccessTokens",
	AccessTokens:             "AccessTokens",
	OpaqueAccessTokens:       "OpaqueAccessTokens",
	GrantRevocations:         "GrantRevocations",
	Metadata:                 "Metadata",
}

// String returns the unqualified name of the Kind, suitable for error
// messages. Unknown values are formatted with their integer for diagnostic
// purposes.
func (k Kind) String() string {
	if name, ok := kindNames[k]; ok {
		return name
	}
	return fmt.Sprintf("Kind(%d)", int(k))
}

// allKinds enumerates every Kind in declaration order. It is the source of
// truth for "is this routed?" checks performed by [New].
//
//nolint:gochecknoglobals // closed enumeration; declared once and treated as a constant lookup table.
var allKinds = []Kind{
	Clients,
	AuthorizationCodes,
	RefreshTokens,
	Grants,
	Sessions,
	PushedAuthRequests,
	Interactions,
	ConsumedJTIs,
	Users,
	InitialAccessTokens,
	RegistrationAccessTokens,
	AccessTokens,
	OpaqueAccessTokens,
	GrantRevocations,
	Metadata,
}

// TxClusterKinds is the closed set of [Kind] values that must share a single
// backend. The library coordinates updates that span these substores under
// one [store.Transactional] handle, so routing two of them to different
// backends would split the atomic commit and open a replay window.
//
// [Sessions] is intentionally absent: the OP does not coordinate Session
// writes with token-endpoint commits, and embedders are expected to route
// Sessions to a volatile cache.
//
//nolint:gochecknoglobals // closed enumeration mirroring 002 §D.1.1.
var TxClusterKinds = []Kind{
	AuthorizationCodes,
	RefreshTokens,
	Grants,
	PushedAuthRequests,
	AccessTokens,
	OpaqueAccessTokens,
	GrantRevocations,
}

// Sentinel errors. Each one is wrapped with [fmt.Errorf] %w by the helpers in
// this package so that callers can match with [errors.Is] without depending
// on string contents.
var (
	// ErrTxClusterSplit signals that two members of [TxClusterKinds]
	// resolved to different backends. The wrapped error message names the
	// kinds and the backend types so operators can identify the
	// misconfiguration from logs alone.
	ErrTxClusterSplit = errors.New("composite: transactional-cluster Kinds split across backends")

	// ErrTxAnchorNotTx signals that the backend chosen as the
	// transactional-cluster anchor does not implement
	// [store.Transactional]. Backends in the cluster must support atomic
	// commits; a Store value that lacks BeginTx cannot host them.
	ErrTxAnchorNotTx = errors.New("composite: transactional-cluster anchor does not implement store.Transactional")

	// ErrKindNotRouted signals that a [Kind] has no backend and no
	// [WithDefault] fallback was supplied. Every Kind must be reachable
	// before [New] returns successfully.
	ErrKindNotRouted = errors.New("composite: kind has no backend and no default")

	// ErrInvalidKind signals that an unknown [Kind] was passed to [With].
	// The condition is normally caught by the type system; the error
	// exists as a defensive guard against future Kind additions that
	// forget to update lookup tables.
	ErrInvalidKind = errors.New("composite: invalid kind")
)

// Option configures a composite [Store] at construction time. Options are
// applied in the order supplied; later [With] calls overwrite earlier ones for
// the same [Kind].
type Option func(*config)

// WithDefault registers s as the fallback backend used for any [Kind] that
// is not explicitly routed via [With]. Passing a nil store is a no-op so
// callers can compose Option slices conditionally.
func WithDefault(s store.Store) Option {
	return func(c *config) {
		if s == nil {
			return
		}
		c.def = s
	}
}

// With routes calls for kind to s. Calling With twice for the same kind keeps
// the last registration. Passing a nil store is a no-op.
func With(kind Kind, s store.Store) Option {
	return func(c *config) {
		if s == nil {
			return
		}
		if c.routes == nil {
			c.routes = make(map[Kind]store.Store)
		}
		c.routes[kind] = s
	}
}

// config accumulates the routing decisions while [Option] callbacks run.
// It is not exported: the validated [*Store] is the surface callers see.
type config struct {
	def    store.Store
	routes map[Kind]store.Store
}

// Store is the composite [store.Store]. The zero value is unusable; callers
// MUST construct one through [New]. Store also implements
// [store.Transactional] by delegating to the transactional anchor; the
// optional [store.ClientRegistry] capability is reachable through
// [Store.ClientRegistry].
type Store struct {
	// routes maps every [Kind] to the backend it resolves to. The map is
	// fully populated by [New] -- accessor methods rely on every Kind
	// being present and panic-free lookup.
	routes map[Kind]store.Store

	// anchor is the backend that owns the entire transactional cluster.
	// It is guaranteed to implement [store.Transactional] (otherwise
	// [New] would have returned an error).
	anchor store.Transactional

	// registry is the [store.ClientRegistry] view of the Clients backend
	// when that backend supports the extension. nil otherwise.
	registry store.ClientRegistry
}

// New builds a composite [Store] from the supplied options. The validation
// order is fixed:
//
//  1. Every [Kind] is routed (either via [With] or [WithDefault]); otherwise
//     [ErrKindNotRouted] is returned with the offending Kind named.
//  2. Every member of [TxClusterKinds] resolves to the same backend (the
//     "tx anchor"); otherwise [ErrTxClusterSplit] is returned with the
//     conflicting Kinds and backend types named.
//  3. The tx anchor implements [store.Transactional]; otherwise
//     [ErrTxAnchorNotTx] is returned with the anchor's concrete type named.
//
// The order is deliberate: missing routing is the most common configuration
// bug, so callers see that error first; cluster splits are the next-most
// common; anchor capability is checked last because it requires that the
// other two checks already pass.
func New(opts ...Option) (*Store, error) {
	cfg := &config{}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(cfg)
	}
	routes, err := buildRoutes(cfg)
	if err != nil {
		return nil, err
	}
	anchor, err := resolveAnchor(routes)
	if err != nil {
		return nil, err
	}
	registry, _ := routes[Clients].(store.ClientRegistry)
	return &Store{
		routes:   routes,
		anchor:   anchor,
		registry: registry,
	}, nil
}

// buildRoutes resolves every [Kind] against the per-Kind overrides and the
// default, returning [ErrKindNotRouted] when a Kind has no backend.
func buildRoutes(cfg *config) (map[Kind]store.Store, error) {
	out := make(map[Kind]store.Store, len(allKinds))
	for _, k := range allKinds {
		s, err := resolveKind(cfg, k)
		if err != nil {
			return nil, err
		}
		out[k] = s
	}
	return out, nil
}

// resolveKind returns the backend that should serve k, or [ErrKindNotRouted]
// when no With/WithDefault entry covers it.
func resolveKind(cfg *config, k Kind) (store.Store, error) {
	if s, ok := cfg.routes[k]; ok {
		return s, nil
	}
	if cfg.def != nil {
		return cfg.def, nil
	}
	return nil, fmt.Errorf("%w: kind %s has no With(...) override and no WithDefault(...) fallback", ErrKindNotRouted, k)
}

// resolveAnchor verifies that every [TxClusterKinds] member maps to the same
// backend and that the backend implements [store.Transactional]. The first
// kind in the cluster is the canonical anchor; subsequent kinds that resolve
// to a different backend produce [ErrTxClusterSplit].
func resolveAnchor(routes map[Kind]store.Store) (store.Transactional, error) {
	anchorKind := TxClusterKinds[0]
	anchor := routes[anchorKind]
	for _, k := range TxClusterKinds[1:] {
		if routes[k] != anchor {
			return nil, fmt.Errorf(
				"%w: %s routed to %T but %s routed to %T",
				ErrTxClusterSplit, anchorKind, anchor, k, routes[k],
			)
		}
	}
	tx, ok := anchor.(store.Transactional)
	if !ok {
		return nil, fmt.Errorf(
			"%w: anchor backend %T does not satisfy store.Transactional",
			ErrTxAnchorNotTx, anchor,
		)
	}
	return tx, nil
}

// Clients implements [store.Store]. The returned [store.ClientStore] is the
// substore exposed by the backend routed for [Clients].
func (s *Store) Clients() store.ClientStore {
	return s.routes[Clients].Clients()
}

// AuthorizationCodes implements [store.Store]. Outside a transaction the
// returned substore writes directly to the anchor backend. Within a
// transaction obtained from [Store.BeginTx], use the [store.Tx] handle's
// AuthorizationCodes() method instead.
func (s *Store) AuthorizationCodes() store.AuthorizationCodeStore {
	return s.routes[AuthorizationCodes].AuthorizationCodes()
}

// RefreshTokens implements [store.Store].
func (s *Store) RefreshTokens() store.RefreshTokenStore {
	return s.routes[RefreshTokens].RefreshTokens()
}

// Grants implements [store.Store].
func (s *Store) Grants() store.GrantStore {
	return s.routes[Grants].Grants()
}

// Sessions implements [store.Store].
func (s *Store) Sessions() store.SessionStore {
	return s.routes[Sessions].Sessions()
}

// PushedAuthRequests implements [store.Store].
func (s *Store) PushedAuthRequests() store.PushedAuthRequestStore {
	return s.routes[PushedAuthRequests].PushedAuthRequests()
}

// Interactions implements [store.Store].
func (s *Store) Interactions() store.InteractionStore {
	return s.routes[Interactions].Interactions()
}

// ConsumedJTIs implements [store.Store].
func (s *Store) ConsumedJTIs() store.ConsumedJTIStore {
	return s.routes[ConsumedJTIs].ConsumedJTIs()
}

// Users implements [store.Store].
func (s *Store) Users() store.UserStore {
	return s.routes[Users].Users()
}

// InitialAccessTokens implements [store.Store]. The returned substore is
// nil-passthrough: backends that lack RFC 7591 support return nil from
// their own [store.Store.InitialAccessTokens] accessor and the composite
// surfaces the same nil. Callers that require dynamic registration MUST
// treat the nil return as a configuration error.
func (s *Store) InitialAccessTokens() store.InitialAccessTokenStore {
	return s.routes[InitialAccessTokens].InitialAccessTokens()
}

// RegistrationAccessTokens implements [store.Store]. Same nil-passthrough
// semantics as [Store.InitialAccessTokens].
func (s *Store) RegistrationAccessTokens() store.RegistrationAccessTokenStore {
	return s.routes[RegistrationAccessTokens].RegistrationAccessTokens()
}

// AccessTokens implements [store.Store] by routing the call through the
// transactional-cluster anchor. Splitting the AT registry away from the
// other transactional substores would re-introduce a code-replay
// cascade that revokes refresh tokens in one backend and access
// tokens in another, so the composite
// rejects such configurations at construction time via
// [TxClusterKinds].
func (s *Store) AccessTokens() store.AccessTokenRegistry {
	return s.routes[AccessTokens].AccessTokens()
}

// OpaqueAccessTokens implements [store.Store] (ADR 0024) by routing the
// call through the transactional-cluster anchor. The substore belongs
// to the same atomic-commit cluster as [AccessTokens] for the same
// reason: rotating an opaque AT inside a refresh-rotation tx must
// commit alongside the new AT and grant updates so a stolen-but-still-
// valid token cannot outlive its issuing chain. The routed backend MAY
// return nil from its own [store.Store.OpaqueAccessTokens] accessor
// when opaque format is not enabled; the library checks the resulting
// nil at op.New time and rejects opaque-format options that have no
// place to persist.
func (s *Store) OpaqueAccessTokens() store.OpaqueAccessTokenStore {
	return s.routes[OpaqueAccessTokens].OpaqueAccessTokens()
}

// GrantRevocations implements [store.Store] (ADR 0025) by routing the
// call through the transactional-cluster anchor. The substore belongs
// to the same atomic-commit cluster as [Grants] and [RefreshTokens]:
// cascade revocations write a tombstone alongside the underlying
// refresh-token chain revocation so a partial failure cannot leave a
// still-redeemable grant next to its tombstone. The routed backend MAY
// return nil from its own [store.Store.GrantRevocations] accessor when
// the grant-tombstone strategy is not enabled; the library checks the
// resulting nil at op.New time and rejects the strategy when its
// substore is missing.
func (s *Store) GrantRevocations() store.GrantRevocationStore {
	return s.routes[GrantRevocations].GrantRevocations()
}

// Metadata implements [store.Store]. The composite passes the call
// through to the routed backend; nil from the backend surfaces as
// nil here so the op.New pairwise-immutability gate can fall back
// to its skip-with-warning posture without further plumbing.
func (s *Store) Metadata() store.MetadataStore {
	return s.routes[Metadata].Metadata()
}

// BeginTx implements [store.Transactional] by delegating to the
// transactional anchor. The returned [store.Tx] vends substores from the
// anchor's transaction; ConsumedJTIs and Interactions are deliberately not
// exposed on [store.Tx] (see the godoc on [store.Tx]) and continue to flow
// through the per-Kind routing for both transactional and non-transactional
// callers.
//
// If the anchor's BeginTx fails, the error is propagated verbatim; the
// composite adapter does not wrap it because callers commonly need to match
// transport-level sentinels (for example [context.Canceled]).
func (s *Store) BeginTx(ctx context.Context) (store.Tx, error) {
	inner, err := s.anchor.BeginTx(ctx)
	if err != nil {
		return nil, err
	}
	return &compositeTx{inner: inner}, nil
}

// ClientRegistry returns the [store.ClientRegistry] view of the backend
// routed for [Clients] when that backend implements the extension. The
// boolean is false when the backend is read-only; callers that require
// dynamic registration MUST treat the false return as a configuration error.
//
// Type assertion of *Store to [store.ClientRegistry] is intentionally NOT
// supported: that would silently treat every composite as registry-capable
// and only fail at the moment a write call hits an unsupported backend. The
// explicit accessor surfaces the capability gap at wiring time instead.
//
// op.WithStaticClients consumes this accessor automatically: when the
// configured Store is a *Store, op probes ClientRegistry() and uses the
// returned registry for seeding. Embedders therefore do not need to register
// static clients against the underlying durable backend before wrapping it
// in a composite — op.WithStaticClients(op.PublicClient{...}) flows through
// the composite directly. If the routed Clients backend is read-only, the
// probe returns (nil, false) and op.New rejects the configuration with the
// same "ClientRegistry required" error a directly-supplied read-only store
// would produce.
func (s *Store) ClientRegistry() (store.ClientRegistry, bool) {
	if s.registry == nil {
		return nil, false
	}
	return s.registry, true
}
