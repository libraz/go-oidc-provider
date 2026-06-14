// Package refreshchain contains backend-agnostic helpers for walking
// refresh-token rotation chains.
package refreshchain

import (
	"context"

	"github.com/libraz/go-oidc-provider/op/store"
)

// FindRoot follows RefreshToken.ParentID pointers from startID to the chain
// root and returns the root's chain handle.
//
// The first hop resolves startID as a bearer credential through the hash-only
// [store.RefreshTokenStore.Find]. Every later hop presents a stored parent
// handle (which a hash-on-store backend returns as a one-way digest) and is
// resolved through [store.RefreshChainResolver] when the backend implements it,
// falling back to Find for backends that return raw parent pointers. This keeps
// the public Find/Consume credential path hash-only — a leaked digest is never
// redeemable — while the chain walk still follows the hashed pointers.
func FindRoot(ctx context.Context, tokens store.RefreshTokenStore, startID string, limit int) (string, bool) {
	if tokens == nil || startID == "" || limit <= 0 {
		return "", false
	}
	current := startID
	var clientID string
	for i := range limit {
		rec, err := lookup(ctx, tokens, current, i == 0)
		if err != nil || rec == nil {
			return "", false
		}
		if clientID == "" {
			clientID = rec.ClientID
		} else if rec.ClientID != clientID {
			return "", false
		}
		if rec.ParentID == nil {
			return current, true
		}
		current = *rec.ParentID
	}
	return "", false
}

// FindByHandle resolves a record by a chain handle — a value previously
// returned as a [store.RefreshToken.ParentID] or as a [FindRoot] result —
// without treating it as a bearer credential. Backends that hash IDs on store
// implement [store.RefreshChainResolver] so the stored digest resolves
// directly; others round-trip their raw pointer through Find.
func FindByHandle(ctx context.Context, tokens store.RefreshTokenStore, handle string) (*store.RefreshToken, error) {
	return lookup(ctx, tokens, handle, false)
}

// lookup resolves a chain node. When credential is true the value is a bearer
// secret and goes through the hash-only Find; otherwise it is a stored chain
// handle resolved through [store.RefreshChainResolver] when available.
func lookup(ctx context.Context, tokens store.RefreshTokenStore, id string, credential bool) (*store.RefreshToken, error) {
	if !credential {
		if r, ok := tokens.(store.RefreshChainResolver); ok {
			return r.FindByStoredHandle(ctx, id)
		}
	}
	return tokens.Find(ctx, id)
}
