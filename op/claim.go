package op

import (
	"sort"
	"strings"
)

// Scope is the typed wrapper for an OAuth 2.0 scope value (RFC 6749 §3.3).
// A Scope is a single space-free token; multi-scope strings are represented
// as [ScopeSet].
type Scope string

// String returns the underlying scope token.
func (s Scope) String() string { return string(s) }

// Standard scopes recognised by OpenID Connect Core 1.0 §5.4 and OAuth 2.0
// (RFC 6749). The library matches on these constants when releasing claim
// groups; custom scopes registered via op.WithScope are matched as Scope
// values returned from the registry.
const (
	// ScopeOpenID is required for any OpenID Connect flow. Without it the
	// authorization request is treated as plain OAuth 2.0.
	ScopeOpenID Scope = "openid"

	// ScopeProfile releases the profile claim group: name, family_name,
	// given_name, middle_name, nickname, preferred_username, profile,
	// picture, website, gender, birthdate, zoneinfo, locale, updated_at.
	ScopeProfile Scope = "profile"

	// ScopeEmail releases email and email_verified.
	ScopeEmail Scope = "email"

	// ScopeAddress releases the address claim group.
	ScopeAddress Scope = "address"

	// ScopePhone releases phone_number and phone_number_verified.
	ScopePhone Scope = "phone"

	// ScopeOfflineAccess permits issuance of a refresh_token at the token
	// endpoint per OpenID Connect Core 1.0 §11.
	ScopeOfflineAccess Scope = "offline_access"
)

// ScopeSet is the parsed form of an OAuth scope string: an unordered set of
// [Scope] tokens. Iteration order is undefined; callers MUST NOT rely on it
// for protocol-visible behaviour.
type ScopeSet map[Scope]struct{}

// ParseScopeSet splits an OAuth-style space-delimited scope string into a
// [ScopeSet]. Empty input yields an empty (non-nil) set so callers can use
// the result without nil checks.
func ParseScopeSet(raw string) ScopeSet {
	out := ScopeSet{}
	for _, tok := range strings.Fields(raw) {
		out[Scope(tok)] = struct{}{}
	}
	return out
}

// Has reports whether the set contains s.
func (set ScopeSet) Has(s Scope) bool {
	_, ok := set[s]
	return ok
}

// String returns the scope set serialised as the space-delimited form
// expected on the wire. The result is sorted lexicographically so the
// output is deterministic across runs.
func (set ScopeSet) String() string {
	if len(set) == 0 {
		return ""
	}
	tokens := make([]string, 0, len(set))
	for s := range set {
		tokens = append(tokens, string(s))
	}
	// Stable order so audit logs and golden tests are reproducible.
	sort.Strings(tokens)
	return strings.Join(tokens, " ")
}

// Claims is the map of claim name to claim value released to a relying
// party. Values are JSON-encoded as-is; callers SHOULD use the standard
// claim types (string, bool, int64, time.Time, []string, map[string]any).
//
// The library treats the map as read-only after it leaves the
// [interaction.Driver]; backends MUST NOT mutate it.
type Claims map[string]any

// Get returns the value stored under name and a flag indicating presence.
// It is a convenience wrapper that avoids zero-value ambiguity at call
// sites that need both the value and the absent/present distinction.
func (c Claims) Get(name string) (any, bool) {
	if c == nil {
		return nil, false
	}
	v, ok := c[name]
	return v, ok
}
