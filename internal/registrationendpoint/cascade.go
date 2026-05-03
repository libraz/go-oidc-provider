package registrationendpoint

import (
	"context"

	"github.com/libraz/go-oidc-provider/op/store"
)

// cascadeRevokeByClient runs the in-tree client-deletion cascade
// against every substore that implements [store.RevokeByClient]. The
// helper isolates the type-assertion ladder so the rest of the
// delete handler remains linear.
//
// Failures are logged but do not abort the cascade or the response:
// the client record is already gone and re-creating it under the
// same id would clash with the RFC 7591 §3 contract.
func cascadeRevokeByClient(ctx context.Context, deps Deps, clientID string) {
	if deps.RefreshTokens != nil {
		if rb, ok := deps.RefreshTokens.(store.RevokeByClient); ok {
			if err := rb.RevokeByClient(ctx, clientID); err != nil {
				deps.logger().Error("dcr.cascade.refresh_revoke_failed",
					"err", err, "client_id", clientID)
			}
		}
	}
	if deps.Grants != nil {
		if rb, ok := deps.Grants.(store.RevokeByClient); ok {
			if err := rb.RevokeByClient(ctx, clientID); err != nil {
				deps.logger().Error("dcr.cascade.grant_revoke_failed",
					"err", err, "client_id", clientID)
			}
		}
	}
}
