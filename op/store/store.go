package store

// Store is the aggregate interface that bundles every substore an OP backend
// exposes to the library. A backend implements Store directly when it owns
// every record kind, or it composes several backends through the composite
// adapter ([github.com/libraz/go-oidc-provider/op/storeadapter/composite])
// to route record kinds to different physical stores. Either way, the
// embedding application passes a single Store value to the library.
//
// # Transactional capability
//
// Implementations used with the browser authorization-code flow MUST also
// implement [Transactional]. The OP rejects that configuration at startup
// otherwise. Backends used only for non-browser grant types may omit the
// extension. The composite adapter keeps atomic-cluster members on one anchor
// and exposes Transactional only when that anchor supports transactions.
type Store interface {
	// Clients returns the [ClientStore] for this backend.
	Clients() ClientStore

	// AuthorizationCodes returns the [AuthorizationCodeStore] for this
	// backend. Part of the atomic-routing cluster.
	AuthorizationCodes() AuthorizationCodeStore

	// RefreshTokens returns the [RefreshTokenStore] for this backend.
	// Part of the atomic-routing cluster.
	RefreshTokens() RefreshTokenStore

	// Grants returns the [GrantStore] for this backend. Part of the
	// atomic-routing cluster.
	Grants() GrantStore

	// Sessions returns the [SessionStore] for this backend. Outside the
	// atomic-routing cluster.
	Sessions() SessionStore

	// PushedAuthRequests returns the [PushedAuthRequestStore] for this
	// backend. Part of the atomic-routing cluster.
	PushedAuthRequests() PushedAuthRequestStore

	// Interactions returns the [InteractionStore] for this backend.
	// Outside the atomic-routing cluster.
	Interactions() InteractionStore

	// ConsumedJTIs returns the [ConsumedJTIStore] for this backend.
	// Outside the atomic-routing cluster.
	ConsumedJTIs() ConsumedJTIStore

	// Users returns the [UserStore] for this backend. Read-only from
	// the library's perspective; outside the atomic-routing cluster.
	Users() UserStore

	// InitialAccessTokens returns the [InitialAccessTokenStore] for
	// this backend. Backends without RFC 7591 Dynamic Client
	// Registration support MAY return nil; the library detects nil at
	// construction time and fails op.WithDynamicRegistration with a
	// clear error rather than panicking later. Outside the
	// atomic-routing cluster.
	InitialAccessTokens() InitialAccessTokenStore

	// RegistrationAccessTokens returns the [RegistrationAccessTokenStore]
	// for this backend. Same nil semantics as
	// [Store.InitialAccessTokens]. Outside the atomic-routing cluster.
	RegistrationAccessTokens() RegistrationAccessTokenStore

	// AccessTokens returns the [AccessTokenRegistry] for this backend.
	// The registry is consulted by the userinfo, introspection, and
	// revocation endpoints, and written by every grant issuance path
	// (RFC 6749 §4.1.2 code-replay revocation, RFC 6819 §5.2.1.1
	// detection invariant). Part of the atomic-routing cluster so token
	// registration and revocation checks share the same backend
	// consistency domain as grants and refresh tokens.
	AccessTokens() AccessTokenRegistry

	// OpaqueAccessTokens returns the [OpaqueAccessTokenStore] for this
	// backend. Backends that never enable op.WithAccessTokenFormat
	// (.../Opaque) MAY return nil; the library detects nil at op.New
	// construction time and rejects opaque-format options that have no
	// place to persist (fail-fast). Part of the atomic-routing cluster.
	OpaqueAccessTokens() OpaqueAccessTokenStore

	// GrantRevocations returns the [GrantRevocationStore] for this
	// backend (ADR 0025). The substore powers the grant-tombstone JWT
	// access-token revocation strategy: cascades write one row per
	// revoked grant rather than one row per access token, and
	// /revocation by jti writes a single denylist row. Backends that
	// never enable the grant-tombstone strategy MAY return nil; the
	// library detects nil at op.New construction time and rejects the
	// strategy when its substore is missing (fail-fast). Part of the
	// atomic-routing cluster so tombstone / denylist writes share the
	// consistency domain of the grants and refresh tokens they protect.
	GrantRevocations() GrantRevocationStore

	// Metadata returns the [MetadataStore] for OP-internal key/value
	// state that is neither user data nor token material — currently
	// the subject_mode marker the pairwise immutability gate consults
	// at construction time. Backends that have not yet provisioned
	// the substore MAY return nil; the library detects nil at op.New
	// and skips the immutability gate with a startup warning so the
	// process still boots. Outside the atomic-routing cluster.
	Metadata() MetadataStore

	// DeviceCodes returns the [DeviceCodeStore] for RFC 8628
	// device-authorization records. Backends that have not yet
	// provisioned the substore MAY return nil; the library detects
	// nil at op.New and rejects the device_code grant option with a
	// clear error rather than panicking later. Outside the
	// atomic-routing cluster: the approve→consume CAS in
	// [DeviceCodeStore.Consume] supplies the single-use guarantee on
	// its own.
	DeviceCodes() DeviceCodeStore

	// CIBARequests returns the [CIBARequestStore] for OpenID Connect
	// CIBA Core 1.0 backchannel-authentication records. Backends that
	// have not yet provisioned the substore MAY return nil; the
	// library detects nil at op.New and rejects op.WithCIBA with a
	// clear error rather than panicking later. Outside the
	// atomic-routing cluster for the same reason as
	// [Store.DeviceCodes]: the approve→consume CAS in
	// [CIBARequestStore.Consume] supplies the single-use guarantee on
	// its own.
	CIBARequests() CIBARequestStore
}
