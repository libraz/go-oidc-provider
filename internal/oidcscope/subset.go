package oidcscope

// Subset reports whether every entry of granted appears in allowed.
// Comparison is byte-equal because scope tokens are case-sensitive
// (RFC 6749 §3.3).
//
// An empty granted set is a subset of any allowed set; an empty allowed
// set rejects every non-empty grant, because a client registered for no
// scopes is registered for nothing. Grants re-apply this check against the
// client's current registration at issuance, so narrowing a client's
// registered scopes contains grants issued under the old registration.
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
