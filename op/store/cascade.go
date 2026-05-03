package store

import "context"

// RevokeByClient is the optional extension interface a substore
// implements when it can revoke every record bound to a specific
// client_id in one shot. The library probes for it during
// [OpenID Connect Dynamic Client Registration 1.0 §5] DELETE
// /register/{client_id} so a client deletion cascades through every
// substore that owns records keyed on the client.
//
// Implementing the interface is optional: a substore that returns
// nil from a probe leaves the cascade to the embedder's
// [RegistrationOption.OnClientDeleted] hook (the historical
// behaviour). Once an adapter implements it the library invokes the
// cascade unconditionally; a missing client is not an error and the
// implementation MUST treat the case as a no-op.
//
// Substores that own client-keyed records:
//
//   - [RefreshTokenStore] (every refresh token belongs to one client)
//   - [GrantStore] (every grant belongs to one client)
//   - [AccessTokenRegistry] / [OpaqueAccessTokenStore] (when the
//     adapter persists access tokens)
//
// Sessions / interactions are subject-keyed, not client-keyed, so the
// cascade does not reach them.
type RevokeByClient interface {
	// RevokeByClient revokes every record whose client_id field
	// equals clientID. Backends MAY delete or mark equivalently;
	// callers only require that subsequent Find / lookup calls
	// treat the records as absent. A non-existent client is not
	// an error.
	RevokeByClient(ctx context.Context, clientID string) error
}
