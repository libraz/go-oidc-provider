package tokenendpoint

import (
	"context"
	"net/http"
	"time"

	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/revocation"
	"github.com/libraz/go-oidc-provider/op/store"
)

// issuedUnderGrant names what one /token exit issues under a grant: the
// grant, the instant the grant's closure is judged against, and the
// credentials the exit has persisted so far. AccessToken and RefreshToken
// are the wire values; either is empty when nothing of that class was
// persisted yet.
//
// IssuedAt is the issuance instant of the credential the exchange redeemed
// (the code's or the consumed refresh token's CreatedAt), never the
// redemption clock: the store treats a grant as closed for a credential
// iff its issuance is at or before the tombstone's RevokedAt.
type issuedUnderGrant struct {
	GrantID      string
	IssuedAt     time.Time
	AccessToken  string
	RefreshToken string
}

// refuseIssuanceUnderClosedGrant is the single place the token endpoint
// asks whether a grant is closed to issuance. Every exit that issues under
// an existing grant calls it after its last persistence step, so a
// revocation that completed while the exit was minting — and therefore
// could not see what it persisted — is still honoured; exits may also call
// it before minting to refuse early. On a closed grant, or a substore fault
// that leaves the answer unknown, it retires the credentials named in
// issued and writes the refusal. Only those credentials are retired: the
// grant is reused across authorizations, so a grant-wide teardown here
// would take down credentials issued after the closure.
//
// The check does not depend on the JWT access-token revocation strategy:
// the closure record is about issuance, which every strategy honours.
// Returns true when the exit may proceed; false when a response has been
// written.
func refuseIssuanceUnderClosedGrant(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	issued issuedUnderGrant,
	description string,
) bool {
	if deps.GrantRevocations == nil || issued.GrantID == "" {
		return true
	}
	closed, err := grantClosedToIssuance(ctx, deps.GrantRevocations, issued.GrantID, issued.IssuedAt)
	if err == nil && !closed {
		return true
	}
	out := grantTeardown(deps, teardownReasonGrantTombstoned).
		Run(ctx, revocation.IssuedCredentials(issued.AccessToken, issued.RefreshToken))
	reportTeardown(ctx, deps, out, auditTokenRevokeFailed, teardownReasonGrantTombstoned, issued.GrantID)
	if err != nil {
		// A substore outage is not a revocation; keep it distinguishable for monitoring.
		endpointsupport.WriteServerError(w)
		return false
	}
	endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidGrant, description)
	return false
}

// grantClosedToIssuance reports whether a credential issued under grantID
// at issuedAt may no longer mint. A store that keeps access-token-only
// tombstones apart answers through [store.IssuanceRevocationChecker], so
// revoking one refresh token leaves the grant's other chains and codes
// redeemable; any other store answers through IsRevoked, which counts
// every tombstone and so refuses more, never less.
func grantClosedToIssuance(ctx context.Context, revs store.GrantRevocationStore, grantID string, issuedAt time.Time) (bool, error) {
	if checker, ok := revs.(store.IssuanceRevocationChecker); ok {
		return checker.IsIssuanceRevoked(ctx, grantID, issuedAt)
	}
	return revs.IsRevoked(ctx, grantID, "", issuedAt)
}
