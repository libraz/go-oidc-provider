package cimd

import (
	"net/url"
	"strings"
)

// maxClientIDBytes is the longest client_id URL the resolver accepts. It
// matches the VARCHAR(255) client_id column the sql store adapter persists
// grants under, so a resolvable id can always be stored.
const maxClientIDBytes = 255

// validClientIDURL reports whether id satisfies the draft's client_id URL
// rules as this OP tightens them: https (http only when allowHTTP), an ASCII
// host, a path other than "/", no dot segments, fragment, userinfo or query,
// and at most [maxClientIDBytes] bytes. The raw string is inspected rather
// than a re-serialised form because the id is compared byte-for-byte with the
// document's client_id.
func validClientIDURL(id string, allowHTTP bool) bool {
	if id == "" || len(id) > maxClientIDBytes {
		return false
	}
	// "?" and "#" cannot appear unescaped anywhere but as the query and
	// fragment delimiters, so their presence alone means one of them.
	if strings.ContainsAny(id, "?#") {
		return false
	}
	rest, ok := strings.CutPrefix(id, "https://")
	if !ok {
		if !allowHTTP {
			return false
		}
		if rest, ok = strings.CutPrefix(id, "http://"); !ok {
			return false
		}
	}
	authority, path, ok := strings.Cut(rest, "/")
	if !ok || !validAuthority(authority) {
		return false
	}
	path = "/" + path
	if path == "/" || hasDotSegment(path) {
		return false
	}
	u, err := url.Parse(id)
	return err == nil && u.User == nil && u.Opaque == "" && u.Hostname() != ""
}

// validAuthority rejects userinfo, percent-encoded or non-ASCII hosts and an
// empty authority. The port, when present, is left to [url.Parse].
func validAuthority(authority string) bool {
	if authority == "" || strings.ContainsAny(authority, "@%") {
		return false
	}
	for i := range len(authority) {
		if authority[i] >= 0x80 || authority[i] <= 0x20 {
			return false
		}
	}
	return true
}

// hasDotSegment reports whether path carries a "." or ".." segment, in plain
// or percent-encoded form (RFC 3986 §2.3 makes "%2E" equivalent to ".").
func hasDotSegment(path string) bool {
	for seg := range strings.SplitSeq(path, "/") {
		decoded := strings.ReplaceAll(strings.ToLower(seg), "%2e", ".")
		if decoded == "." || decoded == ".." {
			return true
		}
	}
	return false
}
