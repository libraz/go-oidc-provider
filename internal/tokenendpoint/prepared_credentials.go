package tokenendpoint

import (
	"context"

	"github.com/libraz/go-oidc-provider/internal/grants/teardown"
)

// cleanupPreparedCredentials retires persisted credentials created by a
// losing Device/CIBA poll before its final Consume CAS. JWTs are only signed
// in memory at that point; opaque and refresh credentials have durable rows
// and must be retired. The scope is the credentials this poll prepared, never
// the grant: a concurrent poll that won the CAS holds live credentials under
// the same grant. Errors are best-effort because no credential bytes were
// ever sent to the client and normal expiry/GC remains the backstop.
func cleanupPreparedCredentials(ctx context.Context, deps Deps, accessToken, refreshToken string, opaque bool) {
	if !opaque {
		// A JWT access token has no row to retire; passing it as a
		// credential id would ask the opaque substore to hash a value it
		// never stored.
		accessToken = ""
	}
	out := grantTeardown(deps, teardownReasonPreparedPoll).
		Run(ctx, teardown.IssuedCredentials(accessToken, refreshToken))
	reportTeardown(ctx, deps, out, auditTokenRevokeFailed, teardownReasonPreparedPoll, "")
}
