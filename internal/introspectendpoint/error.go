package introspectendpoint

import (
	"encoding/json"
	"net/http"
)

// RFC 6749 §5.2 wire codes the handler emits for pre-authentication
// failures. The list is closed; ad-hoc codes are forbidden so the
// discoverable error surface stays auditable.
const (
	errInvalidRequest = "invalid_request"
	errInvalidClient  = "invalid_client"
	errServerError    = "server_error"
)

// errorResponse is the JSON envelope the introspection endpoint returns
// for pre-authentication failures (RFC 6749 §5.2). It mirrors the token
// and PAR endpoints so embedders see a single error surface across all
// three.
type errorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// writeError emits the §5.2 envelope with the supplied status, code, and
// description. Cache-Control is stamped here so every error path
// automatically satisfies RFC 7662 §4; callers MUST NOT re-stamp it.
func writeError(w http.ResponseWriter, status int, code, description string) {
	stampNoStore(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body := errorResponse{Error: code, ErrorDescription: description}
	// Encoding a tiny fixed-shape struct into a buffered writer never
	// fails in practice; an error here would be a programmer bug, not a
	// runtime fault. Mirror the parendpoint posture and drop the error
	// rather than risk a partial body collision.
	_ = json.NewEncoder(w).Encode(body)
}

// writeInvalidClient is the dedicated 401 path for the "invalid_client"
// code. Per RFC 6749 §5.2 a request that authenticated via HTTP Basic
// MUST receive a WWW-Authenticate challenge so RP libraries that follow
// the Basic-auth state machine retry intelligently. The realm value is
// fixed to "oidc" to match the token / par handlers.
func writeInvalidClient(w http.ResponseWriter, basic bool, description string) {
	if basic {
		w.Header().Set("WWW-Authenticate", `Basic realm="oidc"`)
	}
	writeError(w, http.StatusUnauthorized, errInvalidClient, description)
}

// stampNoStore writes the cache-control header RFC 7662 §4 mandates on
// every introspection response (success or error). Centralising the
// helper keeps the success and error paths from drifting.
func stampNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}
