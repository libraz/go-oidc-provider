package tokenexchange

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
