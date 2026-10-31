package tokenendpoint

import (
	"context"
	"net/http"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/grants/refresh"
	"github.com/libraz/go-oidc-provider/internal/grants/teardown"
	"github.com/libraz/go-oidc-provider/op/store"
)

// enforceGrantTombstoneMintRefusal implements the mint- refusal check
// on the refresh path: under [store.RevocationStrategyGrantTombstone]
// the OP refuses to sign a fresh access token when the underlying
// grant has already been tombstoned. The lookup uses the consumed
// refresh token's IssuedAt (its [store.RefreshToken.CreatedAt]) so
// the verifier's "iat <= RevokedAt" rule is honoured: a chain that
// was minted strictly before the tombstone is rejected even if the
// wall-clock race produced an iat of "RevokedAt".
//
// The function is a no-op when:
//
//   - The strategy is not [store.RevocationStrategyGrantTombstone].
//     [store.RevocationStrategyJTIRegistry] preserves the per-JTI
//     behaviour where the next refresh attempt is blocked by the RT
//     cascade hitting the chain root, not by a per-mint check.
//     [store.RevocationStrategyNone] disables server-side JWT
//     revocation entirely.
//   - The substore is unwired (nil [Deps.GrantRevocations]). The
//     embedder either pinned a non-tombstone strategy or wired a
//     partial Store; either way the cascade is not enforced and the
//     refresh proceeds.
//   - The exchanged record carries no GrantID. A refresh chain
//     without an authorize-side grant has no tombstone to consult;
//     the rare case that surfaces here is a legacy chain issued
//     before the GrantID column landed.
//
// Returns true when the request may proceed; false when a response
// has already been written.
func enforceGrantTombstoneMintRefusal(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	exchanged *refresh.Exchanged,
) bool {
	if deps.RevocationStrategy != store.RevocationStrategyGrantTombstone {
		return true
	}
	if deps.GrantRevocations == nil || exchanged == nil || exchanged.GrantID == "" {
		return true
	}
	revoked, err := grantClosedToIssuance(ctx, deps.GrantRevocations, exchanged.GrantID, exchanged.IssuedAt)
	if err != nil {
		// Substore transport fault on the verify path: handling treats this
		// as fatal because silently allowing the request would re-introduce
		// a cascade gap. Surface as server_error rather than invalid_grant
		// so the embedder's monitoring distinguishes a substore outage from
		// a legitimate revocation.
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return false
	}
	if revoked {
		writeError(w, http.StatusBadRequest, errInvalidGrant, "refresh token rejected")
		return false
	}
	return true
}

// retirePriorOpaqueAccessTokens runs the prior-access-token cascade that
// every refresh exit path minting an opaque-format access token owes, and
// reports whether the caller may go on to mint. It is the single
// implementation of that step: a refresh answers 200 with a freshly minted
// access token from two places — the rotation itself and the
// sender-constrained re-mint of an RFC 9700 §2.2.2 grace retry — and both
// have to leave exactly one live opaque access token on the chain.
// Calling this immediately before the mint is the whole contract; anything
// added here reaches both paths.
//
// Opaque-format chains revoke the prior access token atomically with the new
// mint. Resource servers calling /oidc/introspect on every request observe
// the revocation immediately, so the stolen-but-still-valid window collapses
// to clock-skew. The JWT path deliberately leaves prior tokens alive: doing
// otherwise would force every JWT verification through introspection,
// defeating the JWT optimisation that motivated the registry design.
// Revocation runs BEFORE the new mint so a colliding hash on Save
// (impossible-by-construction with 256-bit entropy) cannot leave the chain
// in a half-revoked state, and a failed cascade ends the request rather than
// returning a success that left two live credentials behind.
//
// transactional reports whether the caller's mutations are still staged, so
// the failure audit can say truthfully whether the client may retry.
func retirePriorOpaqueAccessTokens(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	client *store.Client,
	exchanged *refresh.Exchanged,
	transactional bool,
) bool {
	if err := revokePriorOpaqueAT(ctx, deps, exchanged); err != nil {
		deps.audit().Emit(ctx, audit.Event{
			Name:     auditRefreshPriorAccessTokenRevokeFailed,
			Level:    audit.LevelError,
			Message:  "prior access-token revoke failed during refresh rotation",
			ActorID:  exchanged.Subject,
			ClientID: client.ID,
			Extras: map[string]any{
				"failure_stage": failureStagePriorAccessTokenRevoke,
				"retryable":     transactional,
			},
		})
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return false
	}
	return true
}

// revokePriorOpaqueAT revokes the opaque access tokens of the rotated
// chain when the rotation issues an opaque-format token. The grant is
// shared by every session of one subject on one client, so the teardown
// is chain-scoped and widens to the grant only for a chain written before
// chains were recorded or a store that cannot revoke by chain. The
// function is a no-op when:
//
//   - The deployment runs JWT-only (no OpaqueAccessTokens substore
//     wired). The JWT path leaves prior tokens alive on rotation by
//     design — see [issueRefreshResponse].
//   - The active per-audience policy returns
//     [store.AccessTokenFormatJWT] for this resource. A mixed-format
//     deployment may choose JWT for one audience and opaque for
//     another; only the opaque branch revokes.
//   - GrantID is empty. Refresh rotation always carries the parent
//     grant id; an empty value indicates a programmer error in the
//     exchanger. Treat the cascade as a silent no-op so a future
//     refactor that surfaces empty grants does not crash the path.
//
// Revocation errors are returned before a new access token is minted.
// This fail-closed ordering prevents a backend fault from creating a fresh
// bearer credential while a prior opaque credential remains active. The
// refresh-token grace path can safely retry the same idempotent cascade.
func revokePriorOpaqueAT(ctx context.Context, deps Deps, exchanged *refresh.Exchanged) error {
	if deps.OpaqueAccessTokens == nil || exchanged.GrantID == "" || refreshMintPinnedJWT(exchanged) {
		return nil
	}
	format := store.AccessTokenFormatJWT
	if deps.AccessTokenFormatFor != nil {
		format = deps.AccessTokenFormatFor(exchanged.Resource)
	}
	if format != store.AccessTokenFormatOpaque {
		return nil
	}
	return grantTeardown(deps, teardownReasonRotation).
		Run(ctx, teardown.OpaqueAccessTokensOfChain(exchanged.GrantID, exchanged.ChainID)).Err()
}

// refreshMintPinnedJWT reports whether a chain's access tokens are minted
// as JWTs whatever format the policy selects. A chain recording a public
// subject is pinned: an opaque row's subject is read as the OP-internal
// one and projected again, and the row would drop the handler-stated
// claims the chain replays. Such a chain therefore holds no opaque access
// token for a rotation to retire, and a grant it shares with another
// client's tokens must not be swept for one.
func refreshMintPinnedJWT(exchanged *refresh.Exchanged) bool {
	return exchanged.SubjectPublic
}
