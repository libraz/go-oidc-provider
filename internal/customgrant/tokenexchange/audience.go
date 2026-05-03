package tokenexchange

import (
	"net/url"
	"strings"
)

// normaliseResource applies the RFC 8707 §2 canonicalisation rule to
// a resource indicator: lowercase scheme + host, strip the trailing
// slash from the path (including the bare "/" root that net/url
// preserves). Values that do not parse as URLs are returned verbatim
// so the caller can still route them through the AllowedResources
// allowlist (and reject unknown values uniformly).
func normaliseResource(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return raw
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	return u.String()
}

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
