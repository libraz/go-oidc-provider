// Package grantscope holds the scope-set predicate every grant applies
// against a client's registration.
//
// The check exists because a registration can be narrowed while grants
// issued under the old registration are still live. Re-applying it at
// issuance — not only at the authorization request that created the
// grant — is what makes narrowing a client's registered Scopes an
// effective containment action rather than a change that only affects
// future authorizations.
package grantscope

// Subset reports whether every entry of granted appears in allowed.
//
// An empty granted set is a subset of any allowed set; an empty allowed
// set rejects every non-empty grant, because a client registered for no
// scopes is registered for nothing.
func Subset(granted, allowed []string) bool {
	if len(granted) == 0 {
		return true
	}
	idx := make(map[string]struct{}, len(allowed))
	for _, s := range allowed {
		idx[s] = struct{}{}
	}
	for _, s := range granted {
		if _, ok := idx[s]; !ok {
			return false
		}
	}
	return true
}
