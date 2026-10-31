package tokenendpoint

import (
	"context"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/revocation"
)

// Teardown reasons. The value is written onto a grant tombstone and
// onto the audit record of a teardown that did not fully run, so an
// operator can tell which cascade fired without correlating timestamps.
const (
	teardownReasonCodeReplay      = "code_replay"
	teardownReasonRefreshReplay   = "refresh_replay"
	teardownReasonOrphanedMint    = "orphaned_mint"
	teardownReasonGrantTombstoned = "grant_tombstoned"
	teardownReasonPreparedPoll    = "prepared_poll_lost"
	teardownReasonRotation        = "refresh_rotation"
)

// grantTeardown returns the [revocation.Revoker] every credential
// retirement on this endpoint runs through. Building it from Deps in
// one place is what keeps the substore set and the revocation-strategy
// dispatch identical across the replay cascades and the post-mint
// cleanups; the call sites only choose a [revocation.Scope] and a reason.
func grantTeardown(deps Deps, reason string) revocation.Revoker {
	return revocation.Revoker{
		RefreshTokens:      deps.RefreshTokens,
		OpaqueAccessTokens: deps.OpaqueAccessTokens,
		AccessTokens:       deps.AccessTokens,
		GrantRevocations:   deps.GrantRevocations,
		Strategy:           deps.RevocationStrategy,
		Now:                deps.now().UTC(),
		TombstoneRetention: revocation.TombstoneRetention(deps.AccessTokenTTL),
		Reason:             reason,
	}
}

// reportTeardown raises the warn-level audit signal for a teardown that
// did not fully run. event is the catalogued name the cascade reports
// under and surface names the cascade itself, so an operator can tell a
// code replay from a refresh replay without correlating timestamps.
//
// An unresolved grant is reported as its own record rather than staying
// silent: a cascade that retired nothing because it never learned which
// grant to clear is indistinguishable, from the wire, from one that had
// nothing to clear — and only the first is a fail-open.
func reportTeardown(ctx context.Context, deps Deps, out revocation.Outcome, event, surface, grantID string) {
	if out.Complete() {
		return
	}
	if out.UnresolvedGrant {
		deps.audit().Emit(ctx, audit.Event{
			Name:    event,
			Level:   audit.LevelWarn,
			Message: "credential teardown resolved no grant to revoke",
			Extras: map[string]any{
				"surface": surface,
				"err":     "grant_unresolved",
			},
		})
		return
	}
	for _, f := range out.Failures {
		deps.audit().Emit(ctx, audit.Event{
			Name:    event,
			Level:   audit.LevelWarn,
			Message: "credential teardown failed",
			Extras: map[string]any{
				"surface":  surface + "_" + f.Surface,
				"grant_id": grantID,
				"err":      f.Err.Error(),
			},
		})
	}
}
