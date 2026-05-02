package store

// Store is the aggregate interface that bundles every substore an OP backend
// exposes to the library. A backend implements Store directly when it owns
// every record kind, or it composes several backends through the composite
// adapter ([github.com/libraz/go-oidc-provider/op/storeadapter/composite])
// to route record kinds to different physical stores. Either way, the
// embedding application passes a single Store value to the library.
//
// # Transactional capability is opt-in
//
// Implementations of Store MAY additionally implement [Transactional]; the
// library uses a runtime type assertion to detect support. Backends that
// participate in the transactional cluster (see the package-level godoc)
// MUST implement Transactional, and the composite adapter rejects
// configurations that route a transactional-cluster Kind to a backend that
// does not. Backends that only serve non-transactional substores (for
// example, a Redis-only deployment that hosts only [InteractionStore] and
// [ConsumedJTIStore]) need not implement Transactional.
type Store interface {
	// Clients returns the [ClientStore] for this backend.
	Clients() ClientStore

	// AuthorizationCodes returns the [AuthorizationCodeStore] for this
	// backend. Part of the transactional cluster.
	AuthorizationCodes() AuthorizationCodeStore

	// RefreshTokens returns the [RefreshTokenStore] for this backend.
	// Part of the transactional cluster.
	RefreshTokens() RefreshTokenStore

	// Grants returns the [GrantStore] for this backend. Part of the
	// transactional cluster.
	Grants() GrantStore

	// Sessions returns the [SessionStore] for this backend. Part of the
	// transactional cluster.
	Sessions() SessionStore

	// PushedAuthRequests returns the [PushedAuthRequestStore] for this
	// backend. Part of the transactional cluster.
	PushedAuthRequests() PushedAuthRequestStore

	// Interactions returns the [InteractionStore] for this backend.
	// Outside the transactional cluster.
	Interactions() InteractionStore

	// ConsumedJTIs returns the [ConsumedJTIStore] for this backend.
	// Outside the transactional cluster.
	ConsumedJTIs() ConsumedJTIStore

	// Users returns the [UserStore] for this backend. Read-only from
	// the library's perspective; outside the transactional cluster.
	Users() UserStore

	// InitialAccessTokens returns the [InitialAccessTokenStore] for
	// this backend. Backends without RFC 7591 Dynamic Client
	// Registration support MAY return nil; the library detects nil at
	// construction time and fails op.WithDynamicRegistration with a
	// clear error rather than panicking later. Outside the
	// transactional cluster.
	InitialAccessTokens() InitialAccessTokenStore

	// RegistrationAccessTokens returns the [RegistrationAccessTokenStore]
	// for this backend. Same nil semantics as
	// [Store.InitialAccessTokens]. Outside the transactional cluster.
	RegistrationAccessTokens() RegistrationAccessTokenStore

	// AccessTokens returns the [AccessTokenRegistry] for this backend.
	// The registry is consulted by the userinfo, introspection, and
	// revocation endpoints, and written by every grant issuance path
	// (RFC 6749 §4.1.2 code-replay revocation, RFC 6819 §5.2.1.1
	// detection invariant). Part of the transactional cluster: a
	// Register call accompanies a grant write so a partially-committed
	// token issuance cannot leave a wire token unaccounted for.
	AccessTokens() AccessTokenRegistry

	// OpaqueAccessTokens returns the [OpaqueAccessTokenStore] for this
	// backend. Backends that never enable op.WithAccessTokenFormat
	// (.../Opaque) MAY return nil; the library detects nil at op.New
	// construction time and rejects opaque-format options that have no
	// place to persist (fail-fast). Part of the transactional cluster:
	// a Save call accompanies the grant write so a partially-committed
	// token issuance cannot leave a wire token unaccounted for.
	OpaqueAccessTokens() OpaqueAccessTokenStore

	// GrantRevocations returns the [GrantRevocationStore] for this
	// backend (ADR 0025). The substore powers the grant-tombstone JWT
	// access-token revocation strategy: cascades write one row per
	// revoked grant rather than one row per access token, and
	// /revocation by jti writes a single denylist row. Backends that
	// never enable the grant-tombstone strategy MAY return nil; the
	// library detects nil at op.New construction time and rejects the
	// strategy when its substore is missing (fail-fast). Part of the
	// transactional cluster: RevokeGrant / RevokeJTI calls commit
	// alongside the grant or refresh-token writes that triggered the
	// cascade so a partially-committed revocation cannot leave a
	// tombstone next to a still-redeemable grant.
	GrantRevocations() GrantRevocationStore

	// Metadata returns the [MetadataStore] for OP-internal key/value
	// state that is neither user data nor token material — currently
	// the subject_mode marker the pairwise immutability gate consults
	// at construction time. Backends that have not yet provisioned
	// the substore MAY return nil; the library detects nil at op.New
	// and skips the immutability gate with a startup warning so the
	// process still boots. Outside the transactional cluster.
	Metadata() MetadataStore
}
