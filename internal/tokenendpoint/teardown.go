package tokenendpoint

import (
	"context"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/grants/teardown"
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
)

// tombstoneGrace is how far past an access token's expiry a grant
// tombstone must survive so a verifier whose clock trails the OP's
// still sees the revocation. Five minutes matches the floor the
// access-token registry GC uses.
const tombstoneGrace = 5 * time.Minute

// grantTeardown returns the [teardown.Revoker] every credential
// retirement on this endpoint runs through. Building it from Deps in
// one place is what keeps the substore set and the revocation-strategy
// dispatch identical across the replay cascades and the post-mint
// cleanups; the call sites only choose a [teardown.Scope] and a reason.
func grantTeardown(deps Deps, reason string) teardown.Revoker {
	return teardown.Revoker{
		RefreshTokens:      deps.RefreshTokens,
		OpaqueAccessTokens: deps.OpaqueAccessTokens,
		AccessTokens:       deps.AccessTokens,
		GrantRevocations:   deps.GrantRevocations,
		Strategy:           deps.RevocationStrategy,
		Now:                deps.now().UTC(),
		TombstoneRetention: tombstoneRetention(deps),
		Reason:             reason,
	}
}

// tombstoneRetention bounds the lifetime of a tombstone written by a
// teardown. The value is (access-token TTL + [tombstoneGrace]) so any
// access token issued before the cascade is guaranteed to have expired
// before its tombstone disappears. A zero/negative [Deps.AccessTokenTTL]
// is normalised to the token-endpoint default here as a defensive
// backstop so a partially constructed Deps value cannot accidentally
// disable tombstone GC.
func tombstoneRetention(deps Deps) time.Duration {
	ttl := deps.AccessTokenTTL
	if ttl <= 0 {
		ttl = defaultAccessTokenTTL
	}
	return ttl + tombstoneGrace
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
func reportTeardown(ctx context.Context, deps Deps, out teardown.Outcome, event, surface, grantID string) {
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
