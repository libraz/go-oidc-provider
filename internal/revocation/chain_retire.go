package revocation

import (
	"context"

	"github.com/libraz/go-oidc-provider/op/store"
)

// chainWalkLimit caps how far [Retire] walks parent pointers. It guards
// against a looping or corrupted pointer graph, not against an honest
// history: every rotation slides the refresh-token expiry forward, so a
// chain kept alive by refreshing grows without bound. Reaching the limit
// therefore never decides whether a chain is retired; [Retire] falls back
// to the grant, a superset of the chain.
const chainWalkLimit = 1024

// Retirement reports what [Retire] did. The zero value means the chain
// was retired through its root.
type Retirement struct {
	// RootErr is the store fault that kept startID itself from
	// resolving. It is nil for an ordinary miss and for a walk that
	// stopped for any other reason.
	RootErr error

	// RootUnresolved reports that no chain root resolved, so the grant
	// rung ran instead of the chain rung.
	RootUnresolved bool

	// ChainErr is the [store.RefreshTokenStore.RevokeChain] fault after
	// which the grant rung ran.
	ChainErr error

	// GrantUnresolved reports that the grant rung was needed but no
	// grant was supplied to key it on: nothing was retired.
	GrantUnresolved bool

	// GrantErr is the [store.RefreshTokenStore.RevokeByGrant] fault.
	GrantErr error
}

// FellBackToGrant reports whether the grant rung was attempted.
func (r Retirement) FellBackToGrant() bool {
	return r.RootUnresolved || r.ChainErr != nil
}

// Retired reports whether one rung completed, so no token of the chain
// that holds startID is still redeemable.
func (r Retirement) Retired() bool {
	if !r.FellBackToGrant() {
		return true
	}
	return !r.GrantUnresolved && r.GrantErr == nil
}

// Retire revokes the rotation chain that holds startID: from its root
// through [store.RefreshTokenStore.RevokeChain] when the walk resolves
// one, otherwise every refresh token of grantID through
// [store.RefreshTokenStore.RevokeByGrant]. Every token of a chain carries
// the grant it was issued under, so the grant rung may retire sibling
// chains but never leaves a live successor of startID behind. grantID is
// resolved by the caller before anything is revoked, since either rung
// rewrites the records it would otherwise be read from.
func Retire(ctx context.Context, tokens store.RefreshTokenStore, startID, grantID string) Retirement {
	var out Retirement
	rootID, ok, err := FindRoot(ctx, tokens, startID, chainWalkLimit)
	if ok {
		if out.ChainErr = tokens.RevokeChain(ctx, rootID); out.ChainErr == nil {
			return out
		}
	} else {
		out.RootErr = err
		out.RootUnresolved = true
	}
	if grantID == "" {
		out.GrantUnresolved = true
		return out
	}
	out.GrantErr = tokens.RevokeByGrant(ctx, grantID)
	return out
}

// JoinsForeignGrant reports whether rec's GrantID names another client's
// consent, which a token-exchange chain joins for revocation only. Such a
// chain is retired on its own: the grant, its issuance and the other
// clients' credentials are not the holder's to tear down.
func JoinsForeignGrant(rec *store.RefreshToken) bool {
	return rec.Origin == store.RefreshOriginCustomGrant
}

// RetireRecord is [Retire] for a resolved record: the grant rung is keyed
// on rec's grant unless the chain [JoinsForeignGrant], in which case a
// chain whose root does not resolve is reported unretired rather than
// widened onto the foreign grant.
func RetireRecord(ctx context.Context, tokens store.RefreshTokenStore, startID string, rec *store.RefreshToken) Retirement {
	grantID := rec.GrantID
	if JoinsForeignGrant(rec) {
		grantID = ""
	}
	return Retire(ctx, tokens, startID, grantID)
}
