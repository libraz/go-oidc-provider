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
	"github.com/libraz/go-oidc-provider/internal/oidcscope"
	"github.com/libraz/go-oidc-provider/op/store"
)

// ScopeClaimNames returns the set of claim names the scopes authorise.
// The merge favours custom for scope names also present in the standard
// mapping; that lets embedders override (rare, but explicitly supported by
// OIDC Core 1.0 §5.4).
func ScopeClaimNames(scopes []string, custom map[string][]string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, scope := range scopes {
		if extras, ok := custom[scope]; ok {
			for _, name := range extras {
				out[name] = struct{}{}
			}
			continue
		}
		for _, name := range standardScopeClaims(scope) {
			out[name] = struct{}{}
		}
	}
	return out
}

// standardScopeClaims returns the claim names a recognised standard scope
// authorises, per OIDC Core 1.0 §5.4. Unknown scopes (and "openid", whose
// "sub" is always released) return nil. The slice is shared package
// data: callers must not modify it.
func standardScopeClaims(scope string) []string {
	switch scope {
	case oidcscope.ScopeProfile:
		return profileClaims
	case oidcscope.ScopeEmail:
		return emailClaims
	case oidcscope.ScopeAddress:
		return addressClaims
	case oidcscope.ScopePhone:
		return phoneClaims
	default:
		return nil
	}
}

// profileClaims is the closed set of claim names released by the
// "profile" scope (OIDC Core 1.0 §5.4).
var profileClaims = []string{ //nolint:gochecknoglobals // closed mapping per RFC.
	"name",
	"family_name",
	"given_name",
	"middle_name",
	"nickname",
	"preferred_username",
	"profile",
	"picture",
	"website",
	"gender",
	"birthdate",
	"zoneinfo",
	"locale",
	"updated_at",
}

// emailClaims is the closed set released by the "email" scope.
var emailClaims = []string{ //nolint:gochecknoglobals // closed mapping per RFC.
	"email",
	"email_verified",
}

// addressClaims is the closed set released by the "address" scope.
var addressClaims = []string{ //nolint:gochecknoglobals // closed mapping per RFC.
	"address",
}

// phoneClaims is the closed set released by the "phone" scope.
var phoneClaims = []string{ //nolint:gochecknoglobals // closed mapping per RFC.
	"phone_number",
	"phone_number_verified",
}

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
