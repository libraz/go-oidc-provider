package endpointsupport

import "strings"

// BearerSchemeBearer / BearerSchemeDPoP name the two Authorization
// header schemes the OP recognises for bearer-style credentials. The
// constants stay exported so endpoints that need to construct or
// inspect challenges share one canonical spelling.
const (
	BearerSchemeBearer = "Bearer"
	BearerSchemeDPoP   = "DPoP"
)

// BearerFromHeader extracts the credential carried by an Authorization
// header value, matching the RFC 6750 §2.1 ("Bearer") and RFC 9449 §7.1
// ("DPoP") schemes. The match is case-insensitive on the scheme name;
// the returned token is whitespace-trimmed.
//
// The second return reports whether a recognised credential was
// observed at all. An empty header, an unknown scheme, or a scheme
// without a value all return ("", false).
//
// The helper is the consolidated form of the bearer-extraction
// snippets each endpoint was carrying inline. The userinfo handler's
// extractBearer continues to layer additional rules (POST body
// channel, multi-channel rejection) on top of this primitive; only
// the header-parsing slice is shared.
func BearerFromHeader(value string) (string, bool) {
	for _, scheme := range []string{BearerSchemeBearer + " ", BearerSchemeDPoP + " "} {
		if len(value) <= len(scheme) {
			continue
		}
		if !strings.EqualFold(value[:len(scheme)], scheme) {
			continue
		}
		tok := strings.TrimSpace(value[len(scheme):])
		if tok == "" {
			return "", false
		}
		return tok, true
	}
	return "", false
}

// IsFormContent reports whether ct is application/x-www-form-urlencoded.
// Parameters (charset, boundary, etc.) are tolerated. Mirrors the helper
// each form-accepting endpoint had its own copy of so the form-content
// contract stays uniform.
func IsFormContent(ct string) bool {
	return matchMediaType(ct, "application/x-www-form-urlencoded")
}

// IsJSONContent reports whether ct is application/json. Parameters
// (charset, etc.) are tolerated. Mirrors the helper in the registration
// / par / token endpoints so the JSON-content contract stays uniform.
func IsJSONContent(ct string) bool {
	return matchMediaType(ct, "application/json")
}

// matchMediaType is the shared comparator the IsFormContent /
// IsJSONContent helpers delegate to. It strips any parameters after
// the first ';' and compares the remainder case-insensitively.
func matchMediaType(ct, want string) bool {
	if ct == "" {
		return false
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.EqualFold(strings.TrimSpace(ct), want)
}
