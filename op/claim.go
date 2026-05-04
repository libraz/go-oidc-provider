package op

import (
	"sort"
	"strings"
)

// ScopeName is the typed wrapper for a single OAuth 2.0 scope token
// (RFC 6749 §3.3): an opaque, space-free string identifier such as
// "openid" or "read:projects". Scope tokens are case-sensitive on the
// wire and the type intentionally does not normalise the value.
//
// Scope metadata (titles, descriptions, visibility, client allowlist) is
// carried by [Scope]; ScopeName is only the identifier.
type ScopeName string

// String returns the underlying scope token.
func (s ScopeName) String() string { return string(s) }

// Standard scope names recognised by OpenID Connect Core 1.0 §5.4 and
// OAuth 2.0 (RFC 6749). The library matches on these constants when
// releasing claim groups; custom scope identifiers registered via
// [WithScope] are matched as [ScopeName] values returned from the
// registry.
const (
	// ScopeNameOpenID is required for any OpenID Connect flow. Without
	// it the authorization request is treated as plain OAuth 2.0.
	ScopeNameOpenID ScopeName = "openid"

	// ScopeNameProfile releases the profile claim group: name,
	// family_name, given_name, middle_name, nickname,
	// preferred_username, profile, picture, website, gender,
	// birthdate, zoneinfo, locale, updated_at.
	ScopeNameProfile ScopeName = "profile"

	// ScopeNameEmail releases email and email_verified.
	ScopeNameEmail ScopeName = "email"

	// ScopeNameAddress releases the address claim group.
	ScopeNameAddress ScopeName = "address"

	// ScopeNamePhone releases phone_number and phone_number_verified.
	ScopeNamePhone ScopeName = "phone"

	// ScopeNameOfflineAccess is the OpenID Connect Core 1.0 §11
	// scope value. The library advertises it in the discovery
	// document's `scopes_supported` for OIDC compatibility but does
	// NOT use it as a control flag: refresh tokens are issued whenever
	// the granted scope contains "openid" AND the client's GrantTypes
	// includes "refresh_token". A request that adds "offline_access"
	// to the granted scope is rejected as scope widening at the
	// refresh-time exchange (see internal/grants/refresh).
	//
	// To disable refresh tokens for a client, omit "refresh_token"
	// from the client's GrantTypes; to disable them globally, override
	// [WithGrants]. Refresh-token lifetime is controlled by
	// [WithRefreshTokenTTL].
	ScopeNameOfflineAccess ScopeName = "offline_access"
)

// Scope is the registered metadata for a single OAuth 2.0 scope. It
// bundles the wire identifier (Name) with everything the OP needs to
// describe the scope on the consent prompt, in the discovery document,
// and in client allowlists.
//
// Scopes are registered through [WithScope]. The OIDC standard scopes
// (openid, profile, email, address, phone, offline_access) are
// registered automatically with built-in defaults; embedders that want
// custom titles, translations, or claim mappings can override them by
// calling [WithScope] with the matching Name. The standard scopes are
// always Public: true; passing Public: false for any of them at
// registration time causes [New] to fail.
type Scope struct {
	// Name is the wire identifier (the value RPs send in the scope
	// parameter). It MUST be non-empty and MUST be unique within the
	// configured set; duplicates fail [New] at construction.
	Name string

	// Title is the short, user-facing label rendered on the consent
	// prompt. It is the default ("en") string; per-language overrides
	// live in [Scope.I18n].
	Title string

	// Description is the longer user-facing explanation rendered next
	// to the title on the consent prompt. It is the default ("en")
	// string; per-language overrides live in [Scope.I18n].
	Description string

	// Icon is the optional UI hint the SPA can use to pick an icon
	// glyph. The library does not interpret the value; it is passed
	// through to the consent prompt verbatim.
	Icon string

	// Category groups related scopes on the consent prompt (for
	// example "identity", "data:read", "data:write"). The library
	// does not interpret the value beyond echoing it to the SPA.
	Category string

	// Claims lists the userinfo claim names this scope releases. The
	// library releases these claim names from /userinfo when the scope
	// is granted, in addition to surfacing them on the consent prompt.
	// Standard OIDC scopes keep their RFC-defined mappings; this field
	// is the custom-scope hook.
	Claims []string

	// Required marks scopes the user cannot decline. The OIDC
	// standard "openid" scope is always required when present in the
	// request, regardless of this flag.
	Required bool

	// I18n carries per-locale overrides of [Scope.Title] and
	// [Scope.Description]. The map key is a BCP 47 language tag (for
	// example "ja", "en-GB"). Locales not listed fall back to the
	// default Title / Description.
	I18n map[string]ScopeI18n

	// Public, when false, omits the scope from the discovery
	// scopes_supported list. Acceptance is governed by
	// [Scope.AllowedClients]. Defaults to true.
	//
	// The OIDC standard scopes (openid, profile, email, address,
	// phone, offline_access) are forced Public: true; registering any
	// of them with Public: false is rejected at [New] construction
	// time so the discovery document never violates OpenID Connect
	// Discovery 1.0 §3.
	Public bool

	// AllowedClients, when non-empty, restricts the scope to the
	// listed client_id values. Any other client requesting the scope
	// is rejected with invalid_scope per RFC 6749 §5.2. An empty
	// value means every client may request the scope.
	AllowedClients []string
}

// ScopeI18n is a single locale's override of [Scope.Title] and
// [Scope.Description]. Either field may be empty to fall back to the
// default ("en") value declared on the [Scope] itself.
type ScopeI18n struct {
	// Title overrides [Scope.Title] for this locale.
	Title string

	// Description overrides [Scope.Description] for this locale.
	Description string
}

// ScopeSet is the parsed form of an OAuth scope string: an unordered
// set of [ScopeName] tokens. Iteration order is undefined; callers
// MUST NOT rely on it for protocol-visible behaviour.
type ScopeSet map[ScopeName]struct{}

// ParseScopeSet splits an OAuth-style space-delimited scope string
// into a [ScopeSet]. Empty input yields an empty (non-nil) set so
// callers can use the result without nil checks.
func ParseScopeSet(raw string) ScopeSet {
	out := ScopeSet{}
	for _, tok := range strings.Fields(raw) {
		out[ScopeName(tok)] = struct{}{}
	}
	return out
}

// Has reports whether the set contains s.
func (set ScopeSet) Has(s ScopeName) bool {
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
