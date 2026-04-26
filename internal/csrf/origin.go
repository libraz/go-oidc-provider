package csrf

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// ErrOriginRejected is returned by [CheckOrigin] when neither Origin nor
// Referer matches the allowlist. The error path is opaque to avoid hinting
// to attackers which signal triggered the rejection.
var ErrOriginRejected = errors.New("csrf: origin not in allowlist")

// Allowlist is an immutable, concurrency-safe set of origins (scheme://host
// optionally + ":port") accepted as the source of state-changing requests.
//
// The zero value is unusable; build via [NewAllowlist] which canonicalises
// every entry to "scheme://host[:port]" form so input variations like
// trailing slashes do not cause spurious matches.
type Allowlist struct {
	origins map[string]struct{}
}

// NewAllowlist constructs an [Allowlist] from the supplied origin strings.
// Each origin must parse as an absolute URL with non-empty scheme and host;
// path / query / fragment are stripped. Duplicates are deduplicated silently.
func NewAllowlist(origins []string) (*Allowlist, error) {
	out := make(map[string]struct{}, len(origins))
	for _, raw := range origins {
		canon, err := CanonicalOrigin(raw)
		if err != nil {
			return nil, err
		}
		out[canon] = struct{}{}
	}
	return &Allowlist{origins: out}, nil
}

// Contains reports whether the (already canonicalised) origin is allowed.
func (a *Allowlist) Contains(origin string) bool {
	if a == nil {
		return false
	}
	_, ok := a.origins[origin]
	return ok
}

// Len reports the number of distinct origins in the list. Useful for
// emitting a startup log so operators can verify the auto-derived allowlist.
func (a *Allowlist) Len() int {
	if a == nil {
		return 0
	}
	return len(a.origins)
}

// CheckOrigin validates a state-changing request's Origin or Referer header
// against allow. The §F.3.1 algorithm is:
//
//  1. If Origin is present and matches → accept.
//  2. If Origin is absent and Referer matches → accept (same-origin POST
//     fallback for legacy browsers / privacy modes).
//  3. Otherwise → reject.
//
// The function does not consult the request body or cookies. Callers should
// pair it with a token equality check via [ConstantTimeEqual].
func CheckOrigin(r *http.Request, allow *Allowlist) error {
	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
		canon, err := CanonicalOrigin(origin)
		if err != nil {
			return ErrOriginRejected
		}
		if allow.Contains(canon) {
			return nil
		}
		return ErrOriginRejected
	}
	// Origin missing — fall back to Referer.
	referer := strings.TrimSpace(r.Header.Get("Referer"))
	if referer == "" {
		return ErrOriginRejected
	}
	canon, err := CanonicalOrigin(referer)
	if err != nil {
		return ErrOriginRejected
	}
	if !allow.Contains(canon) {
		return ErrOriginRejected
	}
	return nil
}

// CanonicalOrigin reduces a URL to "scheme://host[:port]" form. The default
// ports for http (80) and https (443) are stripped so "https://x" and
// "https://x:443" compare equal.
func CanonicalOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", errors.New("csrf: origin must be an absolute URL")
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	if port != "" {
		return scheme + "://" + host + ":" + port, nil
	}
	return scheme + "://" + host, nil
}
