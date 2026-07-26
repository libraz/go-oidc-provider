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
// # Atomic-routing cluster invariant
//
// Authorization-code exchange, refresh-token rotation, and PAR consumption
// each touch several substores in the same handler path. The OP core relies
// on the compare-and-set / single-operation guarantees documented on those
// substores and opens [store.Transactional] transactions on paths that require
// cross-substore atomicity. The composite adapter validates at construction
// time that every Kind in [TxClusterKinds] resolves to the SAME backend and
// that the backend implements Transactional. [New] returns [ErrTxAnchorNotTx]
// rather than exposing a Store whose BeginTx method cannot honour the
// capability advertised by its method set.
//
// # Routing
//
// Every Kind MUST be reachable. Callers either route Kinds individually with
// [With] or supply a fallback with [WithDefault]; mixing both is supported
// (per-Kind overrides win over the default). [New] returns
// [ErrKindNotRouted] if any Kind is left unrouted.
//
// # Client write capabilities
//
// The composite adapter conditionally exposes [store.ClientRegistry] and
// [store.StaticClientReconciler]. When the backend routed for [Clients]
// implements an extension, it is available through the corresponding Store
// accessor; otherwise the call reports that the capability is unavailable.
// This avoids silently coercing a read-only or non-atomic ClientStore into a
// stronger write contract.
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
// subset additionally requires that all members share one consistency-domain
// anchor.
type Kind int

// Kind values. The integer values are not part of the API: callers use the
// names. The set is closed; adding new substores to [store.Store] requires
// adding a new Kind here and updating [TxClusterKinds] when the new kind
// participates in atomic commits.
const (
	// Clients routes [store.ClientStore] (and optionally
	// [store.ClientRegistry]) calls. Outside the atomic-routing cluster.
	Clients Kind = iota + 1

	// AuthorizationCodes routes [store.AuthorizationCodeStore] calls.
	// Member of the atomic-routing cluster.
	AuthorizationCodes

	// RefreshTokens routes [store.RefreshTokenStore] calls. Member of the
	// atomic-routing cluster.
	RefreshTokens

	// Grants routes [store.GrantStore] calls. Member of the
	// atomic-routing cluster.
	Grants

	// Sessions routes [store.SessionStore] calls. Outside the transactional
	// cluster: the OP tolerates session loss as a re-login event and does
	// not coordinate Session writes with token-endpoint commits.
	// Embedders MAY route Sessions to a volatile cache (Redis, Memcached)
	// without violating any invariant.
	Sessions

	// PushedAuthRequests routes [store.PushedAuthRequestStore] calls.
	// Member of the atomic-routing cluster.
	PushedAuthRequests

	// Interactions routes [store.InteractionStore] calls. Outside the
	// atomic-routing cluster.
	Interactions

	// ConsumedJTIs routes [store.ConsumedJTIStore] calls. Outside the
	// atomic-routing cluster.
	ConsumedJTIs

	// Users routes [store.UserStore] calls. Outside the transactional
	// cluster.
	Users

	// InitialAccessTokens routes [store.InitialAccessTokenStore] calls.
	// Used by the RFC 7591 dynamic-client-registration endpoint. Outside
	// the atomic-routing cluster.
	InitialAccessTokens

	// RegistrationAccessTokens routes [store.RegistrationAccessTokenStore]
	// calls. Used by the RFC 7592 management endpoints. Outside the
	// atomic-routing cluster.
	RegistrationAccessTokens

	// AccessTokens routes [store.AccessTokenRegistry] calls. Used by
	// the userinfo, introspection, revocation endpoints, and by the
	// code-replay cascade. Member of the atomic-routing cluster so
	// token registration, grant writes, and revocation cascades share
	// one backend consistency domain.
	AccessTokens

	// OpaqueAccessTokens routes [store.OpaqueAccessTokenStore] calls.
	// Used by the userinfo, introspection, revocation endpoints, and by
	// the code-replay cascade when opt-in opaque access tokens are
	// enabled. Member of the atomic-routing cluster for the same reason
	// as [AccessTokens].
	OpaqueAccessTokens

	// GrantRevocations routes [store.GrantRevocationStore] calls. Used
	// by the userinfo, introspection, and revocation endpoints to
	// enforce JWT access-token revocation under the grant-tombstone
	// strategy, and written by the code-replay / logout cascades. Member
	// of the atomic-routing cluster so tombstone / denylist writes share
	// the same backend consistency domain as the grants and refresh
	// tokens they protect.
	GrantRevocations

	// Metadata routes [store.MetadataStore] calls. Outside the
	// atomic-routing cluster: the substore is consulted only by the
	// op.New construction-time pairwise immutability gate.
	Metadata

	// DeviceCodes routes [store.DeviceCodeStore] calls. Used by the
	// /device_authorization endpoint, the verification page, and the
	// device_code grant at the token endpoint. Outside the
	// atomic-routing cluster: the approve→consume CAS in
	// [store.DeviceCodeStore.Consume] supplies the single-use
	// guarantee without coordinating with the access-token /
	// refresh-token writes.
	DeviceCodes

	// CIBARequests routes [store.CIBARequestStore] calls. Used by the
	// /bc-authorize endpoint, the embedder's authentication device
	// callback, and the CIBA grant at the token endpoint. Outside the
	// atomic-routing cluster: the approve→consume CAS in
	// [store.CIBARequestStore.Consume] supplies the single-use
	// guarantee without coordinating with the access-token /
	// refresh-token writes.
	CIBARequests
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
	DeviceCodes:              "DeviceCodes",
	CIBARequests:             "CIBARequests",
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
	DeviceCodes,
	CIBARequests,
}

// TxClusterKinds is the closed set of [Kind] values that must share a single
// backend. The OP core relies on per-substore CAS operations rather than
// opening transactions, but routing two of these kinds to different backends
// would still split the consistency domain for replay detection, refresh
// rotation, and revocation cascades.
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
	ErrTxClusterSplit = errors.New("composite: atomic-routing cluster Kinds split across backends")

	// ErrTxAnchorNotTx signals that the backend chosen as the
	// atomic-routing anchor does not implement [store.Transactional].
	// [New] returns this error rather than constructing a Store whose
	// method set advertises an unusable BeginTx capability.
	ErrTxAnchorNotTx = errors.New("composite: atomic-routing cluster anchor does not implement store.Transactional")

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
// MUST construct one through [New]. Every constructed Store exposes a usable
// BeginTx by delegating to its validated transactional anchor; the optional
// [store.ClientRegistry] capability is reachable through [Store.ClientRegistry].
type Store struct {
	// routes maps every [Kind] to the backend it resolves to. The map is
	// fully populated by [New] -- accessor methods rely on every Kind
	// being present and panic-free lookup.
	routes map[Kind]store.Store

	// txAnchor is the validated transactional view of the backend that owns
	// the entire atomic-routing cluster. New rejects a nil view.
	txAnchor store.Transactional

	// registry is the [store.ClientRegistry] view of the Clients backend
	// when that backend supports the extension. nil otherwise.
	registry store.ClientRegistry

	// staticReconciler is the atomic startup-seeding view of the Clients
	// backend when supported. It remains separate from registry because an
	// implementation may support one-record DCR writes without an atomic
	// multi-record reconciliation boundary.
	staticReconciler store.StaticClientReconciler
}

// New builds a composite [Store] from the supplied options. The validation
// order is fixed:
//
//  1. Every [Kind] is routed (either via [With] or [WithDefault]); otherwise
//     [ErrKindNotRouted] is returned with the offending Kind named.
//  2. Every member of [TxClusterKinds] resolves to the same backend (the
//     "routing anchor"); otherwise [ErrTxClusterSplit] is returned with the
//     conflicting Kinds and backend types named.
//  3. The routing anchor implements [store.Transactional]; otherwise
//     [ErrTxAnchorNotTx] is returned.
//
// The order is deliberate: missing routing is the most common configuration
// bug, so callers see that error first; cluster splits are the next-most
// common.
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
	staticReconciler, _ := routes[Clients].(store.StaticClientReconciler)
	txAnchor, ok := anchor.(store.Transactional)
	if !ok {
		return nil, fmt.Errorf(
			"%w: anchor backend %T does not satisfy store.Transactional",
			ErrTxAnchorNotTx, anchor,
		)
	}
	return &Store{
		routes:           routes,
		txAnchor:         txAnchor,
		registry:         registry,
		staticReconciler: staticReconciler,
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
// backend. The first kind in the cluster is the canonical anchor; subsequent
// kinds that resolve to a different backend produce [ErrTxClusterSplit].
func resolveAnchor(routes map[Kind]store.Store) (store.Store, error) {
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
	return anchor, nil
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
// atomic-routing anchor. Splitting the AT registry away from the
// other cluster members would re-introduce a code-replay cascade that
// revokes refresh tokens in one backend and access tokens in another,
// so the composite rejects such configurations at construction time
// via [TxClusterKinds].
func (s *Store) AccessTokens() store.AccessTokenRegistry {
	return s.routes[AccessTokens].AccessTokens()
}

// OpaqueAccessTokens implements [store.Store] by routing the call
// through the atomic-routing anchor. The substore belongs to the same
// consistency cluster as [AccessTokens] for the same reason:
// opaque-token writes and revocation reads must share a backend with
// the grant and refresh-token records they protect. The routed
// backend MAY return nil from its own
// [store.Store.OpaqueAccessTokens] accessor when opaque format is not
// enabled; the library checks the resulting nil at op.New time and
// rejects opaque-format options that have no place to persist.
func (s *Store) OpaqueAccessTokens() store.OpaqueAccessTokenStore {
	return s.routes[OpaqueAccessTokens].OpaqueAccessTokens()
}

// GrantRevocations implements [store.Store] by routing the call
// through the atomic-routing anchor. The substore belongs to the same
// consistency cluster as [Grants] and [RefreshTokens] so cascade
// revocations and subsequent grant / token checks see the same
// backend state. The routed backend MAY return nil from its own
// [store.Store.GrantRevocations] accessor when the grant-tombstone
// strategy is not enabled; the library checks the resulting nil at
// op.New time and rejects the strategy when its substore is missing.
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

// DeviceCodes implements [store.Store]. The composite passes the
// call through to the routed backend; nil from the backend surfaces
// as nil here so op.New can reject the device_code grant option
// when the substore is missing instead of panicking later. Routed
// backends MAY support the substore independently of the
// transactional anchor — DeviceCodes is intentionally outside
// [TxClusterKinds].
func (s *Store) DeviceCodes() store.DeviceCodeStore {
	return s.routes[DeviceCodes].DeviceCodes()
}

// CIBARequests implements [store.Store]. The composite passes the
// call through to the routed backend; nil from the backend surfaces
// as nil here so op.New can reject the op.WithCIBA option when the
// substore is missing instead of panicking later. Routed backends MAY
// support the substore independently of the transactional anchor —
// CIBARequests is intentionally outside [TxClusterKinds].
func (s *Store) CIBARequests() store.CIBARequestStore {
	return s.routes[CIBARequests].CIBARequests()
}

// BeginTx delegates to the transactional atomic-routing anchor validated by
// [New]. The OP core and embedders can rely on the store.Transactional type
// assertion: every constructed Store can begin a transaction or propagate the
// anchor's runtime error.
//
// If the anchor's BeginTx fails, the error is propagated verbatim; the
// composite adapter does not wrap it because callers commonly need to match
// transport-level sentinels (for example [context.Canceled]).
func (s *Store) BeginTx(ctx context.Context) (store.Tx, error) {
	inner, err := s.txAnchor.BeginTx(ctx)
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
// Dynamic Client Registration consumes this accessor. Static startup seeds
// use [Store.StaticClientReconciler] instead because sequential registry
// writes cannot provide the required all-or-nothing batch boundary.
func (s *Store) ClientRegistry() (store.ClientRegistry, bool) {
	if s.registry == nil {
		return nil, false
	}
	return s.registry, true
}

// StaticClientReconciler returns the atomic startup-seeding capability of the
// backend routed for [Clients]. A false result means op.WithStaticClients must
// reject the composition at construction time; falling back to sequential
// ClientRegistry writes would expose partial state on failure.
func (s *Store) StaticClientReconciler() (store.StaticClientReconciler, bool) {
	if s.staticReconciler == nil {
		return nil, false
	}
	return s.staticReconciler, true
}
