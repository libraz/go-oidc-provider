package tokenendpoint

import (
	"encoding/json"
	"net/http"
)

// RFC 6749 §5.2 wire codes the handler emits. The list is closed; ad-hoc
// codes are forbidden so the discoverable error surface stays auditable.
// "invalid_client" and "use_dpop_nonce" are emitted from
// [internal/clientauth/clientauthhttp] and [internal/dpop] respectively
// so the constants live there; this list omits them.
const (
	errInvalidRequest       = "invalid_request"
	errInvalidGrant         = "invalid_grant"
	errUnauthorizedClient   = "unauthorized_client"
	errUnsupportedGrantType = "unsupported_grant_type"
	errInvalidScope         = "invalid_scope"
	errInvalidTarget        = "invalid_target"
	errServerError          = "server_error"
)

// errorResponse is the JSON envelope the token endpoint returns for every
// failure (RFC 6749 §5.2). The "error_description" field is human-readable
// and intentionally generic so it cannot be used as an oracle by an
// attacker probing for credential validity.
type errorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// writeError emits the §5.2 envelope with the supplied status, code, and
// description. Cache-Control / Pragma are stamped here so every error
// path automatically satisfies §5.1; callers MUST NOT re-stamp them.
func writeError(w http.ResponseWriter, status int, code, description string) {
	stampNoStore(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body := errorResponse{Error: code, ErrorDescription: description}
	// Encoding a tiny fixed-shape struct into a buffered writer never
	// fails in practice; an error here would be a programmer bug, not a
	// runtime fault. Mirror the userinfo handler's posture: drop the
	// error rather than risk a partial body collision.
	_ = json.NewEncoder(w).Encode(body)
}

// stampNoStore writes the cache-control headers RFC 6749 §5.1 mandates on
// every token-endpoint response, success or failure. Splitting the helper
// keeps the success path and the error path from drifting.
func stampNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}
