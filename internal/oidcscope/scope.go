// Package oidcscope is the canonical home for scope-string helpers
// shared across the OP's grant pipelines.
//
// The package is a tiny, dependency-free utility layer: it owns the
// well-known scope-name constants ([ScopeOpenID], [ScopeOfflineAccess])
// and the three membership / parsing helpers ([ContainsOpenID],
// [ContainsOfflineAccess], [Parse]) that the token endpoint, the
// authorization layer, and the userinfo projector all need. Centralising
// the strings (rather than letting each consumer redeclare its own
// const) prevents a typo in one branch from drifting the spec
// interpretation away from the others.
//
// # Spec references
//
//   - RFC 6749 §3.3 defines the wire syntax of the "scope" parameter:
//     a list of space-delimited, case-sensitive strings, with empty
//     entries silently dropped. [Parse] implements this grammar.
//   - OIDC Core 1.0 §3.1.2.1 reiterates the case-sensitive treatment
//     for the OIDC "scope" parameter and mandates the presence of
//     "openid" on requests that want id_token issuance.
//   - OIDC Core 1.0 §5.4 defines the "offline_access" scope and gates
//     refresh-token issuance on its presence (under the strict reading
//     also referenced at §11).
//
// # Allocation posture
//
// [ContainsOpenID] and [ContainsOfflineAccess] iterate the supplied
// slice in place; they never allocate. [Parse] allocates a fresh
// backing slice once per call and returns nil for empty / whitespace-
// only input so callers can treat "scope absent" identically to
// "scope empty".
package oidcscope

import "strings"

// ScopeOpenID is the OIDC Core 1.0 §3.1.2.1 well-known scope name that
// drives id_token issuance. The value is case-sensitive on the wire
// (RFC 6749 §3.3); compare with byte equality, not a normalised form.
const ScopeOpenID = "openid"

// ScopeOfflineAccess is the OIDC Core 1.0 §5.4 / §11 scope name that
// gates refresh-token issuance under the strict offline_access reading
// and selects the offline TTL bucket under the lax default. The value
// is case-sensitive on the wire (RFC 6749 §3.3).
const ScopeOfflineAccess = "offline_access"

// ContainsOpenID reports whether scopes lists [ScopeOpenID]. The match
// is byte-equal per OIDC Core 1.0 §3.1.2.1: scope tokens are
// case-sensitive and the server does not normalise them. The function
// is allocation-free.
func ContainsOpenID(scopes []string) bool {
	for _, s := range scopes {
		if s == ScopeOpenID {
			return true
		}
	}
	return false
}

// ContainsOfflineAccess reports whether scopes lists
// [ScopeOfflineAccess]. The match is byte-equal per OIDC Core 1.0
// §3.1.2.1: scope tokens are case-sensitive and the server does not
// normalise them. The function is allocation-free.
func ContainsOfflineAccess(scopes []string) bool {
	for _, s := range scopes {
		if s == ScopeOfflineAccess {
			return true
		}
	}
	return false
}

// Parse splits the canonical RFC 6749 §3.3 space-delimited scope
// string into its constituent tokens. Empty tokens (produced by
// repeated separators) are dropped silently so a caller can pass
// the raw form value verbatim without normalising it first. An
// empty / whitespace-only input yields a nil slice so callers can
// treat "scope absent" identically to "scope empty".
//
// The function never trims non-space whitespace: RFC 6749 §3.3
// names ASCII space (0x20) as the only separator, and allowing
// other whitespace silently would invent grammar the spec does
// not authorise.
func Parse(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, " ")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
