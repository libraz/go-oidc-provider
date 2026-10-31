package tokenendpoint

import (
	"context"

	"github.com/libraz/go-oidc-provider/internal/revocation"
)

// replayCascade carries a detected refresh-token replay out of the
// exchange so the RFC 9700 §2.2.2 chain cascade runs once the surrounding
// transaction has settled, against non-transactional substore handles.
// The grant teardown owed to a deprovisioned subject rides the same way.
//
// Running the cascade on transaction-bound handles bounds it by whatever
// action limit the backend's transaction imposes, and a chain long enough
// to exceed it would be retired only in part — breadth-first from the
// root, so the newest node, the one an attacker presenting a stolen token
// holds, would survive. A rollback would discard the cascade entirely.
// Deferring past the settle point removes both failure modes, and the
// replay is the finding whichever way the transaction went.
type replayCascade struct {
	// token is the refresh_token the client presented, empty until a
	// replay is detected. Nothing else has to travel: the chain root and
	// the grant it belongs to are derived by walking parent pointers from
	// this value.
	token string

	// deprovisioned names the grant whose subject no longer exists; its
	// GrantID is empty until the exchange finds one.
	deprovisioned deprovisionedRedemption
}

// armDeprovisioned records a grant to tear down because its subject no
// longer exists, so the teardown runs at the next settle point.
func (c *replayCascade) armDeprovisioned(in deprovisionedRedemption) {
	if c == nil {
		return
	}
	c.deprovisioned = in
}

// arm records that presented was replayed, so the cascade runs at the
// next settle point.
func (c *replayCascade) arm(presented string) {
	if c == nil {
		return
	}
	c.token = presented
}

// armed reports whether the exchange detected a replay or a
// deprovisioned subject.
func (c *replayCascade) armed() bool {
	return c != nil && (c.token != "" || c.deprovisioned.Subject != "")
}

// run retires every credential still redeemable under the replayed or
// deprovisioned grant, through non-transactional substores. It is a
// no-op unless the exchange armed it and it never reports failure: a
// transport fault raises a warn-level audit event and the client keeps
// the invalid_grant answer it has already been given.
//
// A deprovisioned grant is torn down whole through [revocation.Revoker].
// A replay runs two rungs, in this order:
//
//   - The refresh chain, through the exchanger, which walks parent
//     pointers to the root and falls back to the whole grant. It hands
//     back the grant it resolved.
//   - Every access token issued under that grant, through the shared
//     [revocation.Revoker]: the JWT half under whatever
//     [store.AccessTokenRevocationStrategy] is configured, and the
//     opaque half independently of it. RFC 9700 §2.2.2 requires the
//     tokens issued from a compromised grant to be revoked, and an
//     attacker who redeemed the stolen refresh token holds exactly the
//     access token this rung retires.
func (c *replayCascade) run(ctx context.Context, deps Deps) {
	if !c.armed() {
		return
	}
	if c.deprovisioned.Subject != "" {
		retireDeprovisionedGrant(ctx, deps, c.deprovisioned)
	}
	if c.token == "" {
		return
	}
	exchanger, err := newRefreshExchanger(deps)
	if err != nil {
		// Unreachable in practice: the same construction already succeeded
		// during the exchange that detected the replay. Dropping the
		// cascade is the best-effort contract's answer, and the replay
		// audit event has already been emitted.
		return
	}
	replayed := exchanger.RevokeReplayedChain(ctx, c.token)
	// A token-exchange chain joins another client's grant: only the
	// chain's own opaque access tokens go, never the grant or its issuance.
	scope := revocation.CompromisedGrantAccessTokens(replayed.GrantID)
	if replayed.JoinedGrant {
		if replayed.ChainID == "" {
			return
		}
		scope = revocation.OpaqueAccessTokensOfChain(replayed.GrantID, replayed.ChainID)
	}
	out := grantTeardown(deps, teardownReasonRefreshReplay).Run(ctx, scope)
	reportTeardown(ctx, deps, out, auditRefreshGrantRevokeFailed, teardownReasonRefreshReplay, replayed.GrantID)
}
