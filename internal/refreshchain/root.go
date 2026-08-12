// Package refreshchain contains backend-agnostic helpers for walking
// refresh-token rotation chains.
package refreshchain

import (
	"context"
	"errors"

	"github.com/libraz/go-oidc-provider/op/store"
)

// FindRoot follows RefreshToken.ParentID pointers from startID towards the
// chain root and returns the chain handle a revocation cascade should start
// from.
//
// The first hop resolves startID as a bearer credential through the hash-only
// [store.RefreshTokenStore.Find]. Every later hop presents a stored parent
// handle (which a hash-on-store backend returns as a one-way digest) and is
// resolved through [store.RefreshChainResolver] when the backend implements it,
// falling back to Find for backends that return raw parent pointers. This keeps
// the public Find/Consume credential path hash-only — a leaked digest is never
// redeemable — while the chain walk still follows the hashed pointers.
//
// # A missing ancestor is not a failed walk
//
// The walk stops at the deepest node it can resolve rather than giving up when
// an ancestor has gone. Rotation records are reclaimed oldest-first — by a
// scheduled sweep, or by a backend TTL, or by an operator's own retention — so
// the records that go missing are always a prefix of the chain, and every token
// that is still redeemable hangs below the boundary the walk stopped at.
// Revoking from there retires exactly the tokens a replay could still spend.
//
// Treating the gap as a failed walk would be strictly worse than useless:
// [store.RefreshTokenStore.RevokeChain] would never be called, so a chain whose
// oldest record had aged out would keep every live descendant alive after a
// replay was detected on it — and it is the long-lived chains, the ones an
// attacker has had the most time to work with, that lose their oldest records
// first.
//
// Two failures stay hard, because neither has a safe node to fall back to:
// startID itself not resolving (there is nothing to cascade from), and a record
// naming a different client than the one the walk began with (the pointer graph
// is not trustworthy, and following it further could retire another client's
// tokens). Exhausting limit also fails: a chain that long is a loop or a
// corrupted graph, not a rotation history.
func FindRoot(ctx context.Context, tokens store.RefreshTokenStore, startID string, limit int) (string, bool) {
	if tokens == nil || startID == "" || limit <= 0 {
		return "", false
	}
	current := startID
	var clientID, deepest string
	for i := range limit {
		rec, err := lookup(ctx, tokens, current, i == 0)
		if err != nil || rec == nil {
			if deepest != "" && errors.Is(err, store.ErrNotFound) {
				return deepest, true
			}
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
		deepest = current
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
//
// A backend that answers with a nil record and a nil error violates the store
// contract; lookup normalises that pair onto [store.ErrNotFound] so the walk
// stops instead of dereferencing the missing record.
func lookup(ctx context.Context, tokens store.RefreshTokenStore, id string, credential bool) (*store.RefreshToken, error) {
	rec, err := resolveNode(ctx, tokens, id, credential)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, store.ErrNotFound
	}
	return rec, nil
}

func resolveNode(ctx context.Context, tokens store.RefreshTokenStore, id string, credential bool) (*store.RefreshToken, error) {
	if !credential {
		if r, ok := tokens.(store.RefreshChainResolver); ok {
			return r.FindByStoredHandle(ctx, id)
		}
	}
	return tokens.Find(ctx, id)
}
