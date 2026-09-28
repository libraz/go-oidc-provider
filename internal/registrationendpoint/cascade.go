package registrationendpoint

import (
	"context"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/auditevent"
	"github.com/libraz/go-oidc-provider/op/store"
)

// cascadeRevokeByClient runs the in-tree client-deletion cascade
// against every substore that implements [store.RevokeByClient]. The
// helper isolates the type-assertion ladder so the rest of the
// delete handler remains linear.
//
// The probed substores cover refresh tokens, grants, the JWT
// access-token registry, and the opaque access-token store.
// Backends that do not implement [store.RevokeByClient] fall
// through silently; the embedder's [OnClientDeleted] hook is
// responsible for cleanup the library cannot reach.
//
// Failures are logged but do not abort the cascade or the response:
// the client record is already gone and re-creating it under the
// same id would clash with the RFC 7591 §3 contract.
//
// A JWT access-token registry that implements [store.RevokeByClient]
// marks its rows revoked here rather than deleting them, matching the
// interface's mark-revoked contract. A backend that does not
// implement it is still covered: the endpoints that verify a JWT AT
// — userinfo, introspection, token exchange — require the token's
// client to still be registered and treat a deleted client as
// revoked, so client deletion alone closes that token class even
// without this cascade step; see the client probe in
// internal/endpointsupport.
func cascadeRevokeByClient(ctx context.Context, deps Deps, clientID string) {
	probeRevokeByClient(ctx, deps, clientID, deps.RefreshTokens, auditevent.AuditDCRCascadeRefreshRevokeFailed)
	probeRevokeByClient(ctx, deps, clientID, deps.Grants, auditevent.AuditDCRCascadeGrantRevokeFailed)
	probeRevokeByClient(ctx, deps, clientID, deps.AccessTokens, auditevent.AuditDCRCascadeAccessTokenRevokeFailed)
	probeRevokeByClient(ctx, deps, clientID, deps.OpaqueAccessTokens, auditevent.AuditDCRCascadeOpaqueAccessTokenRevokeFailed)
}

// probeRevokeByClient runs the [store.RevokeByClient] type-assertion
// for one substore. The helper exists so [cascadeRevokeByClient]
// stays under the cognitive-complexity gate as more substores are
// added to the cascade; it is not exported.
//
// substore is the typed substore handle (a [store.RefreshTokenStore],
// [store.GrantStore], etc). A nil substore short-circuits — the
// caller's [Deps] field is allowed to be unset.
func probeRevokeByClient(ctx context.Context, deps Deps, clientID string, substore any, eventName auditevent.Name) {
	if substore == nil {
		return
	}
	rb, ok := substore.(store.RevokeByClient)
	if !ok {
		return
	}
	if err := rb.RevokeByClient(ctx, clientID); err != nil {
		deps.logger().Error(string(eventName), "err", err, "client_id", clientID)
		deps.audit().Emit(ctx, audit.Event{
			Name:     string(eventName),
			Level:    audit.LevelError,
			Message:  "dynamic client deletion credential cascade failed",
			ClientID: clientID,
			Extras:   map[string]any{"error": err.Error()},
		})
	}
}
