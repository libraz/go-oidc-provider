package tokenexchange

import (
	"github.com/libraz/go-oidc-provider/internal/resourceindicator"
)

// dedupe collapses duplicate entries in s while preserving order.
func dedupe(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(s))
	out := make([]string, 0, len(s))
	for _, v := range s {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// scopeSubset reports whether every entry of want is present in have.
// An empty want vacuously satisfies the check.
func scopeSubset(want, have []string) bool {
	if len(want) == 0 {
		return true
	}
	idx := make(map[string]struct{}, len(have))
	for _, v := range have {
		idx[v] = struct{}{}
	}
	for _, v := range want {
		if _, ok := idx[v]; !ok {
			return false
		}
	}
	return true
}

// audienceSubset reports whether every entry of granted appears in
// requested. Equality is [resourceindicator.ContainsLabel], the OP-wide
// policy, so a policy-granted "HTTPS://API.EXAMPLE:443/" matches a
// requested "https://api.example" here exactly as it does at
// client_credentials. An empty granted vacuously passes.
func audienceSubset(granted, requested []string) bool {
	for _, v := range granted {
		if !resourceindicator.ContainsLabel(requested, v) {
			return false
		}
	}
	return true
}

// intersectScope returns the entries of want that also appear in
// allowed, preserving want's order. The function is the natural
// "narrow want by allowed" operation; an empty allowed yields an
// empty result, an empty want yields an empty result.
func intersectScope(want, allowed []string) []string {
	if len(want) == 0 || len(allowed) == 0 {
		return nil
	}
	idx := make(map[string]struct{}, len(allowed))
	for _, v := range allowed {
		idx[v] = struct{}{}
	}
	out := make([]string, 0, len(want))
	for _, v := range want {
		if _, ok := idx[v]; ok {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
