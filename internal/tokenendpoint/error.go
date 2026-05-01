package tokenendpoint

import (
	"encoding/json"
	"net/http"
)

// RFC 6749 §5.2 wire codes the handler emits. The list is closed; ad-hoc
// codes are forbidden so the discoverable error surface stays auditable.
const (
	errInvalidRequest       = "invalid_request"
	errInvalidClient        = "invalid_client"
	errInvalidGrant         = "invalid_grant"
	errUnauthorizedClient   = "unauthorized_client"
	errUnsupportedGrantType = "unsupported_grant_type"
	errInvalidScope         = "invalid_scope"
	errInvalidTarget        = "invalid_target"
	errServerError          = "server_error"

	// errUseDPoPNonce is the RFC 9449 §8 wire code the token endpoint
	// emits when the request must be retried with a fresh
	// server-supplied DPoP nonce. The companion "DPoP-Nonce" response
	// header carries the value the client should embed in the next
	// proof's "nonce" claim.
	errUseDPoPNonce = "use_dpop_nonce"
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

// writeInvalidClient is the dedicated 401 path for the "invalid_client"
// code: per RFC 6749 §5.2, a request that authenticated via HTTP Basic
// MUST receive a WWW-Authenticate challenge so RP libraries that follow
// the Basic-auth state machine retry intelligently. The realm value is
// fixed to "oidc" to match the userinfo handler's naming.
func writeInvalidClient(w http.ResponseWriter, basic bool, description string) {
	if basic {
		w.Header().Set("WWW-Authenticate", `Basic realm="oidc"`)
	}
	writeError(w, http.StatusUnauthorized, errInvalidClient, description)
}

// stampNoStore writes the cache-control headers RFC 6749 §5.1 mandates on
// every token-endpoint response, success or failure. Splitting the helper
// keeps the success path and the error path from drifting.
func stampNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}
