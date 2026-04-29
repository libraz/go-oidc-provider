package httpx

import "net/http"

// ErrorBody is the OAuth 2.0 / OIDC error payload schema (RFC 6749 §5.2).
// Every error response from the OP — token, authorize JSON variants,
// userinfo, introspect, revoke — uses this shape so RPs can parse error
// codes consistently.
type ErrorBody struct {
	// Error is the machine-readable code (e.g. "invalid_request").
	Error string `json:"error"`

	// ErrorDescription is the optional human-readable hint. It MUST NOT
	// contain sensitive material (raw inputs, tokens) — operators rely on
	// audit logs for diagnosis, RPs only need a short string.
	ErrorDescription string `json:"error_description,omitempty"`

	// ErrorURI is an optional URL pointing to a documentation page about
	// the error. Reserved for future use; the library does not currently
	// publish per-code documentation.
	ErrorURI string `json:"error_uri,omitempty"`
}

// WriteError emits an OAuth-style error response. status fixes the HTTP
// status; code is the machine-readable error name; description is the
// optional human-readable hint. The function does not log; callers must
// record the failure in their own audit pipeline.
//
// The Cache-Control: no-store header is applied unconditionally because
// even errors must not be cached: an attacker who tricks a cache into
// storing an error response can replay it to legitimate users (RFC 6749
// §5.1). Pragma: no-cache is stamped alongside for HTTP/1.0 caches the
// RFC 6749 §5.1 recommendation set still mentions; the duplicate value
// is cheap and the gain in interop with legacy intermediaries is
// straightforward.
func WriteError(w http.ResponseWriter, status int, code, description string) error {
	w.Header().Set("Pragma", "no-cache")
	return WriteJSON(w, status, ErrorBody{
		Error:            code,
		ErrorDescription: description,
	})
}

// WriteOAuthBearerChallenge writes an RFC 6750 §3 WWW-Authenticate challenge
// alongside the error body. Used by userinfo / introspect / revoke when the
// client supplied a malformed or expired bearer token.
//
// realm names the protection space (typically the issuer URL); scope is the
// optional space-delimited list of scopes the resource accepts. Either may
// be empty, in which case the corresponding parameter is omitted from the
// challenge.
func WriteOAuthBearerChallenge(
	w http.ResponseWriter,
	status int,
	code, description, realm, scope string,
) error {
	w.Header().Set("WWW-Authenticate", buildBearerChallenge(code, description, realm, scope))
	return WriteError(w, status, code, description)
}

// buildBearerChallenge assembles the WWW-Authenticate header value. It is
// extracted into its own function so it can be unit-tested without a full
// HTTP round-trip.
func buildBearerChallenge(code, description, realm, scope string) string {
	out := "Bearer"
	first := true
	add := func(name, value string) {
		if value == "" {
			return
		}
		if first {
			out += " "
			first = false
		} else {
			out += ", "
		}
		out += name + `="` + escapeQuoted(value) + `"`
	}
	add("realm", realm)
	add("error", code)
	add("error_description", description)
	add("scope", scope)
	return out
}

// escapeQuoted produces a `quoted-string` (RFC 7235 §2.1) safe encoding.
// Backslash and double-quote are escaped; control characters (bytes below
// 0x20 and the 0x7F DEL) are dropped entirely. The drop is the CRLF-injection
// defence: an attacker who could push a CR or LF through into a description
// field would otherwise smuggle a header break into the WWW-Authenticate
// value. The library never legitimately needs CTLs in OAuth error fields.
func escapeQuoted(s string) string {
	out := make([]byte, 0, len(s))
	for i := range len(s) {
		c := s[i]
		if c < 0x20 || c == 0x7F {
			continue
		}
		switch c {
		case '\\', '"':
			out = append(out, '\\', c)
		default:
			out = append(out, c)
		}
	}
	return string(out)
}
