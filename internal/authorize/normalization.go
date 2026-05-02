package authorize

import (
	"net/url"
	"strconv"
	"strings"
)

// parseMaxAge extracts the max_age parameter into a *int64 so the caller
// can tell "absent" from "0". An empty string is treated as absent. Non-
// integer values, negative values, and integers that overflow int64 are
// rejected with [ErrMaxAgeInvalid].
func parseMaxAge(v url.Values) (*int64, error) {
	raw, err := singleValue(v, "max_age")
	if err != nil {
		return nil, err
	}
	if raw == "" {
		return nil, nil //nolint:nilnil // documented "absent" sentinel
	}
	parsed, parseErr := strconv.ParseInt(raw, 10, 64)
	if parseErr != nil || parsed < 0 {
		return nil, ErrMaxAgeInvalid
	}
	return &parsed, nil
}

// dedupePreserve returns a copy of in with duplicate elements removed,
// preserving the first occurrence's position. It is the order-stable
// equivalent of slices.Compact for an unsorted input.
func dedupePreserve(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// splitPrompt splits the prompt parameter on a single ASCII space, matching
// the OIDC Core §3.1.2.1 grammar exactly. It is intentionally NOT
// [strings.Fields]: tabs and newlines in prompt are illegal under the
// spec, and collapsing them silently would mask malformed clients.
func splitPrompt(s string) []string {
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
