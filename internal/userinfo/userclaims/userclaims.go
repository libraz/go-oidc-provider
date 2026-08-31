// Package userclaims projects a [store.User] onto the claim source the
// OP resolves claim names against.
//
// The projection lives in its own package because two surfaces resolve
// the same names for the same (subject, grant): /userinfo and the
// id_token minted at /token. A claim released by one and dropped by the
// other is not a stricter policy, it is an inconsistency an RP has no
// way to detect — it sees an absent claim, not a refusal — and the
// library's public [store.User] documentation makes no distinction
// between the two objects.
package userclaims

import (
	"github.com/libraz/go-oidc-provider/op/store"
)

// Source returns the effective claim source for u.
//
// It is [store.User.Claims] plus the claims the library synthesises
// from the record's own columns:
//
//   - "updated_at", from [store.User.UpdatedAt] as Unix seconds, when
//     the timestamp is set and the embedder did not already populate
//     the claim itself. The embedder's own value always wins.
//
// The merge happens in a fresh map, so the embedder's backing store
// stays untouched: the store contract says Claims is read-only to the
// library. A nil user yields a nil map.
func Source(u *store.User) map[string]any {
	if u == nil {
		return nil
	}
	if u.UpdatedAt.IsZero() {
		return u.Claims
	}
	if _, has := u.Claims["updated_at"]; has {
		return u.Claims
	}
	out := make(map[string]any, len(u.Claims)+1)
	for k, v := range u.Claims {
		out[k] = v
	}
	out["updated_at"] = u.UpdatedAt.Unix()
	return out
}
