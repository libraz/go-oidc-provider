// Package resourceindicator implements a single, system-wide normalisation
// and comparison policy for RFC 8707 resource indicators. Every endpoint that
// accepts a "resource" parameter (authorize, token / client_credentials,
// device_authorization, backchannel_authentication) and every option that
// keys behaviour off a registered audience (for example
// op.WithAccessTokenFormatPerAudience) MUST route validation and equality
// through this package so the same value is not accepted at one surface and
// rejected at another.
//
// # Canonical form
//
// The canonical form is derived from RFC 3986 §6 (URI Comparison) and
// RFC 8707 §2 (Resource Parameter):
//
//   - The value MUST be an absolute URI: a non-empty scheme followed by
//     "://" and a non-empty host. Relative or scheme-less values are
//     rejected.
//   - Scheme and host are lowercased. The path component is preserved
//     case-sensitive per RFC 3986 §6.2.2.
//   - The default port for the scheme (80 for http, 443 for https) is
//     stripped. Non-default ports are preserved verbatim.
//   - A single trailing '/' on the path is stripped. The empty path is
//     treated as equivalent to '/' per RFC 3986 §6.2.3, so both values
//     canonicalise to the empty path.
//   - The fragment component is FORBIDDEN: RFC 8707 §2 says the resource
//     MUST NOT contain a fragment. A fragment-bearing value is rejected
//     even if it is empty after the '#'.
//   - The userinfo component is FORBIDDEN. RFC 8707 §2 does not address
//     userinfo, but a resource indicator is an audience identifier, not
//     a credential carrier; permitting userinfo opens parser-confusion
//     attacks (https://trusted@evil/ reads as host=evil in Go's parser
//     but as host=trusted to a casual reader). Rejecting it here mirrors
//     the policy applied to redirect_uri / jwks_uri / sector_identifier_uri
//     by the registration validator.
//   - The query component is preserved verbatim: RFC 8707 §2 allows the
//     resource to carry query parameters that further scope the audience.
//
// # Equality
//
// [Equal] canonicalises both inputs and compares the byte form. If either
// input fails canonicalisation, [Equal] returns false: a non-canonical or
// malformed value cannot equal anything by definition. [Contains] applies
// the same rule to a registered allowlist, which lets historical records
// that were persisted before this package existed continue to match a
// canonical request without an explicit migration step.
//
// # Error wire mapping
//
// The sentinels below are intentionally narrow so the calling endpoint can
// translate them onto its own wire-error catalogue. The OAuth wire code is
// "invalid_target" (RFC 8707 §3) for every failure mode; the catalogue split
// here gives the caller a structured reason field for audit / debug logs.
package resourceindicator

import (
	"errors"
	"net/url"
	"strings"
)

// Sentinel errors. Callers compare via [errors.Is] and translate to the
// endpoint's wire shape (typically OAuth invalid_target).
var (
	// ErrEmpty indicates the input is the empty string. The caller is
	// expected to short-circuit "resource omitted" before invoking this
	// package; a validator that reaches us with "" therefore signals a
	// caller bug.
	ErrEmpty = errors.New("resourceindicator: value is empty")

	// ErrParse indicates the value did not parse as a URI at all
	// ([url.Parse] returned an error). The caller wraps this onto an
	// OAuth invalid_target response.
	ErrParse = errors.New("resourceindicator: value is not a valid URI")

	// ErrNotAbsolute indicates the value parsed but did not carry a
	// scheme + host, or [url.URL.IsAbs] returned false. RFC 8707 §2
	// requires an absolute URI.
	ErrNotAbsolute = errors.New("resourceindicator: value is not an absolute URI with scheme and host")

	// ErrFragment indicates the value carried a fragment. RFC 8707 §2
	// forbids fragments on resource indicators.
	ErrFragment = errors.New("resourceindicator: value must not contain a fragment")

	// ErrUserinfo indicates the value carried a userinfo component
	// ("user@host" or "user:pass@host"). The package rejects userinfo
	// uniformly to close the parser-confusion vector
	// "https://trusted@evil/...".
	ErrUserinfo = errors.New("resourceindicator: value must not contain userinfo")
)

// defaultPortForScheme returns the IANA default port number (as a decimal
// string) for the named scheme. Returns the empty string when the scheme
// has no canonical default (or when the package author did not register
// one). The list is intentionally short — http and https cover every
// resource indicator the OP routes today.
func defaultPortForScheme(scheme string) string {
	switch scheme {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}

// Canonicalize parses raw, validates the structural rules documented on
// the package, and returns the canonical form per the rules above.
//
// The canonical form is derived from a fresh [url.URL] (Go's parser
// already lowercases the scheme); the helper additionally lowercases the
// host, strips a default port for the scheme, and normalises the path's
// trailing slash. The query is preserved verbatim. The returned string is
// suitable for direct byte comparison via [Equal].
//
// Callers that only need a yes/no validity verdict can use [Validate],
// which is implemented as Canonicalize-and-discard.
func Canonicalize(raw string) (string, error) {
	if raw == "" {
		return "", ErrEmpty
	}
	// Reject the fragment marker before url.Parse so the diagnostic
	// points at the actual offending byte. Go's parser tolerates an
	// empty fragment ("foo#") and the post-parse u.Fragment check would
	// then miss the violation; the explicit IndexByte catches every
	// case uniformly.
	if strings.IndexByte(raw, '#') >= 0 {
		return "", ErrFragment
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", ErrParse
	}
	if !u.IsAbs() || u.Scheme == "" || u.Host == "" {
		return "", ErrNotAbsolute
	}
	if u.User != nil {
		return "", ErrUserinfo
	}
	// Defence in depth: url.Parse should have surfaced the fragment
	// already, but a future Go change that admits a fragment-bearing
	// URL into u.RawFragment without populating u.Fragment would still
	// be rejected here.
	if u.Fragment != "" || u.RawFragment != "" {
		return "", ErrFragment
	}

	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = canonicalHost(u.Host, u.Scheme)
	u.Path = canonicalPath(u.Path)
	// RawPath is used by url.URL.String when the encoded path differs
	// from the unencoded form; clearing it forces the encoder to
	// re-derive from the canonicalised Path so a request whose original
	// trailing slash was percent-encoded does not round-trip back into
	// the canonical form.
	u.RawPath = ""

	return u.String(), nil
}

// Validate reports whether raw is a syntactically valid resource
// indicator. It is implemented as a discarded [Canonicalize]; callers
// that also need the canonical form should call Canonicalize directly.
func Validate(raw string) error {
	_, err := Canonicalize(raw)
	return err
}

// Equal reports whether a and b denote the same resource indicator after
// canonicalisation. Returns false if either side fails canonicalisation —
// a malformed or empty value cannot equal anything.
//
// The function is intentionally tolerant of stored records that pre-date
// the canonicalisation policy: the registered side is canonicalised on
// every call, so a database row that was persisted in mixed-case form
// continues to match an equivalent canonical request without an explicit
// migration step.
func Equal(a, b string) bool {
	canonA, err := Canonicalize(a)
	if err != nil {
		return false
	}
	canonB, err := Canonicalize(b)
	if err != nil {
		return false
	}
	return canonA == canonB
}

// Contains reports whether the registered allowlist set contains a value
// equal to raw under [Equal]. The function is the canonical replacement
// for [slices.Contains] at every site that holds a resource-indicator
// allowlist; the byte-comparison form mis-handles mixed-case host /
// trailing-slash variants the wire form admits.
func Contains(set []string, raw string) bool {
	canon, err := Canonicalize(raw)
	if err != nil {
		return false
	}
	for _, candidate := range set {
		canonCandidate, err := Canonicalize(candidate)
		if err != nil {
			continue
		}
		if canon == canonCandidate {
			return true
		}
	}
	return false
}

// NormalizeLabel returns the comparison form of an audience label:
// values that canonicalise as resource indicators come back canonical,
// and values that are not resource indicators at all — an RFC 8693
// audience is a logical name, which need not be a URI — come back
// verbatim so they still compare exactly.
//
// A value rejected for carrying a fragment or userinfo comes back
// verbatim too, but [EqualLabel] and [ContainsLabel] refuse to match it:
// the policy that forbids those components would be void if a surface
// could fall back to a byte comparison and admit them.
//
// Use this at the surfaces that only need a stable stored form; use
// [EqualLabel] / [ContainsLabel] wherever the answer decides whether a
// request is authorized.
func NormalizeLabel(raw string) string {
	canon, err := Canonicalize(raw)
	if err != nil {
		return raw
	}
	return canon
}

// EqualLabel reports whether two audience labels denote the same
// audience, under the same rules [NormalizeLabel] documents. A label
// that carries a fragment or userinfo never matches anything, including
// an identical string.
func EqualLabel(a, b string) bool {
	keyA, okA := labelKey(a)
	keyB, okB := labelKey(b)
	return okA && okB && keyA == keyB
}

// ContainsLabel reports whether set holds a label equal to raw under
// [EqualLabel]. It is the canonical replacement for a
// [slices.Contains] over a registered audience list.
func ContainsLabel(set []string, raw string) bool {
	key, ok := labelKey(raw)
	if !ok {
		return false
	}
	for _, candidate := range set {
		candidateKey, candidateOK := labelKey(candidate)
		if candidateOK && candidateKey == key {
			return true
		}
	}
	return false
}

// labelKey returns the value an audience-label comparison keys on and
// whether the label may match at all.
//
// The split follows the reason canonicalisation failed. A value that is
// not a URI ([ErrParse], [ErrNotAbsolute]) is an opaque audience name
// and compares verbatim. A value that IS URI-shaped but carries a
// component the policy forbids ([ErrFragment], [ErrUserinfo]) is
// unmatchable: admitting it through a verbatim comparison would let a
// registration written with userinfo authorize the parser-confusion
// forms the canonical path exists to reject. The empty string is
// unmatchable because it names no audience.
func labelKey(raw string) (string, bool) {
	canon, err := Canonicalize(raw)
	switch {
	case err == nil:
		return canon, true
	case errors.Is(err, ErrFragment), errors.Is(err, ErrUserinfo), errors.Is(err, ErrEmpty):
		return "", false
	default:
		return raw, true
	}
}

// canonicalHost lowercases host and strips the default port for scheme.
// host arrives in the "name:port" form url.URL.Host uses; the function
// preserves IPv6 literal brackets verbatim.
func canonicalHost(host, scheme string) string {
	host = strings.ToLower(host)
	defaultPort := defaultPortForScheme(scheme)
	if defaultPort == "" {
		return host
	}
	// IPv6 literal: "[::1]:80" → split on the LAST ':' so the bracketed
	// authority survives. A bracketed host with no port has no trailing
	// ':' so the function falls through unchanged.
	idx := strings.LastIndex(host, ":")
	if idx < 0 {
		return host
	}
	// If the preceding byte is ']' we are looking at an IPv6 bracketed
	// host with a port. If not — and the host carries a '[' — the ':'
	// belongs to the IPv6 address itself, not a port separator.
	hostPart, portPart := host[:idx], host[idx+1:]
	if strings.IndexByte(hostPart, '[') >= 0 && !strings.HasSuffix(hostPart, "]") {
		return host
	}
	if portPart == defaultPort {
		return hostPart
	}
	return host
}

// canonicalPath strips trailing '/' characters from path. The empty path is
// preserved as the empty string; "/" collapses to the empty string so an
// authority-only URL ("https://example.com") and the same with the lone
// slash ("https://example.com/") both canonicalise to the empty path.
// Multi-segment paths keep their leading slash and lose trailing slashes
// ("/api//" -> "/api").
func canonicalPath(path string) string {
	if path == "" || path == "/" {
		return ""
	}
	return strings.TrimRight(path, "/")
}
