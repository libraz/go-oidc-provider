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
// Open follow-up: under [store.RevocationStrategyGrantTombstone] the
// JWT verifier reads tombstones from [store.GrantRevocationStore]
// keyed on grant_id (not client_id). A complete cascade under that
// strategy would enumerate the affected grant IDs before delete and
// write a tombstone for each via [GrantRevocationStore.RevokeGrant].
// The current cascade does not enumerate (no
// `Grants.ListByClient` exists) and so a freshly-issued JWT AT can
// remain verifiable until exp on a tombstone-strategy backend even
// after its client is deleted. The opaque-AT cascade and the
// JTI-registry strategy are unaffected; the gap is tracked for a
// v1.x grant enumeration extension.
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
