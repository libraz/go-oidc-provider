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
// against allow. The algorithm is:
//
//  1. If Origin is present and matches → accept.
//  2. If Origin is absent, fall back to Referer. The Referer fallback is
//     gated on a Fetch Metadata signal: the request MUST carry
//     Sec-Fetch-Site: same-origin (so a browser that emits Fetch
//     Metadata vouches the request originated from the OP's own pages).
//     A request that supplies Referer alone, with no Sec-Fetch-Site or a
//     non-same-origin value, is rejected — modern browsers always emit
//     Origin on state-changing fetches, and the Referer-only path is
//     reserved for legacy UAs that also do not emit Fetch Metadata.
//  3. If both Origin and Referer are absent → reject.
//
// The function does not consult the request body or cookies. Callers should
// pair it with a token equality check via [ConstantTimeEqual].
//
// Hardening rationale: Referer is omitted on same-origin POSTs by some
// privacy modes / extensions / Strict-Origin-When-Cross-Origin policies
// even when Origin is also absent (the earlier code admitted that path
// when Referer matched the allowlist). Combined with a CSRF token
// pre-stamped via document.cookie, that gap let an attacker who could
// observe the cookie reach the gate without forging headers. Tying the
// Referer fallback to Sec-Fetch-Site closes the gap on every browser
// that ships Fetch Metadata (Chromium / Firefox / Safari since 2020)
// without breaking same-origin SSR posts that include the header.
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
	// Origin missing — fall back to Referer, gated on Fetch Metadata.
	if !strings.EqualFold(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")), "same-origin") {
		return ErrOriginRejected
	}
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
//
// Hardening: only the http and https schemes are accepted; userinfo
// ("user:pass@host"), opaque URLs ("javascript:..."), and absent host
// components are rejected because each has been used in past parser-confusion
// attacks (e.g. "https://evil.example/?@trusted.example" where attackers rely
// on a downstream parser misreading the userinfo segment).
//
// A literal IPv6 host is re-bracketed on the way out. [url.URL.Hostname]
// strips the brackets, and an origin reassembled without them is not a URL
// any parser or browser would produce: the colons of the address run
// together with the port separator. It would never equal the Origin header
// a browser sends for the same host, so the comparison this function exists
// to make would silently fail.
func CanonicalOrigin(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("csrf: origin must not be empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", errors.New("csrf: origin must be an absolute URL")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", errors.New("csrf: origin scheme must be http or https")
	}
	if u.Opaque != "" {
		return "", errors.New("csrf: opaque URLs are not valid origins")
	}
	if u.User != nil {
		return "", errors.New("csrf: userinfo is not allowed in an origin")
	}
	host, err := canonicalHost(u)
	if err != nil {
		return "", err
	}
	port := u.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	if port != "" {
		return scheme + "://" + host + ":" + port, nil
	}
	return scheme + "://" + host, nil
}

// canonicalHost lower-cases the host component and restores the brackets
// around a literal IPv6 address that [url.URL.Hostname] removes. A host
// containing a colon can only be an IPv6 literal at this point: the port
// has already been split off, and a registered name cannot contain one.
func canonicalHost(u *url.URL) (string, error) {
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", errors.New("csrf: origin must include a host")
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]", nil
	}
	return host, nil
}
