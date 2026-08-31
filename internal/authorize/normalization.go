package authorize

import (
	"net/url"
	"strconv"
	"strings"
	"time"
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

// AuthenticationIsStale reports whether an authentication performed at
// authTime is older than maxAge seconds as of now, i.e. whether it fails
// the OIDC Core 1.0 §3.1.2.1 max_age constraint.
//
// The comparison is done in seconds rather than by widening maxAge into
// a [time.Duration]. [parseMaxAge] admits the whole non-negative int64
// range, and a duration holds only about 292 years of nanoseconds, so
// the multiplication wraps for any max_age past ~9.2e9 — landing in
// bands where a larger max_age is treated as *stricter* than a smaller
// one, and where a request asking for a centuries-long window is
// refused as stale. Seconds cannot wrap: elapsed is itself a duration,
// so its second count is bounded by the same ~292 years, and the
// comparison against maxAge is then exact for every value the parser
// accepts. The predicate is therefore monotone in maxAge — raising it
// never turns a fresh authentication stale.
//
// A zero maxAge is stale by definition (§3.1.2.1: the RP demands an
// authentication performed "just now"). A zero authTime is stale too:
// it records no authentication, and [time.Time.Sub] saturates rather
// than overflows against it, which would otherwise let a large max_age
// accept an authentication that never happened.
func AuthenticationIsStale(authTime, now time.Time, maxAge int64) bool {
	if maxAge <= 0 || authTime.IsZero() {
		return true
	}
	elapsed := now.UTC().Sub(authTime.UTC())
	if elapsed <= 0 {
		return false
	}
	return int64(elapsed/time.Second) > maxAge
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
