package tokenendpoint

import "context"

// cleanupPreparedCredentials retires persisted credentials created by a
// losing Device/CIBA poll before its final Consume CAS. JWTs are only signed
// in memory at that point; opaque and refresh credentials have durable rows
// and must be retired. Errors are best-effort because no credential bytes were
// ever sent to the client and normal expiry/GC remains the backstop.
func cleanupPreparedCredentials(ctx context.Context, deps Deps, accessToken, refreshToken string, opaque bool) {
	if opaque && accessToken != "" && deps.OpaqueAccessTokens != nil {
		_ = deps.OpaqueAccessTokens.RevokeByID(ctx, accessToken)
	}
	if refreshToken != "" && deps.RefreshTokens != nil {
		_ = deps.RefreshTokens.RevokeChain(ctx, refreshToken)
	}
}
