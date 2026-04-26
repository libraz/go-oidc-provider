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
}
