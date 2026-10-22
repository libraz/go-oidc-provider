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
