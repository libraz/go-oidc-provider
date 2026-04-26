package parendpoint

import (
	"encoding/json"
	"net/http"
)

// RFC 6749 §5.2 wire codes the handler emits. The list is closed; ad-hoc
// codes are forbidden so the discoverable error surface stays auditable.
const (
	errInvalidRequest       = "invalid_request"
	errInvalidClient        = "invalid_client"
	errUnauthorizedClient   = "unauthorized_client"
	errInvalidScope         = "invalid_scope"
	errServerError          = "server_error"
	errInvalidRequestObject = "invalid_request_object"
)

// errorResponse is the JSON envelope the PAR endpoint returns for every
// failure (RFC 6749 §5.2). It mirrors the token endpoint's shape so embedders
// see a single error surface across both endpoints.
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
	// runtime fault. Drop the error rather than risk a partial body
	// collision with the WriteHeader call we already issued.
	_ = json.NewEncoder(w).Encode(body)
}

// writeInvalidClient is the dedicated 401 path for the "invalid_client"
// code: per RFC 6749 §5.2 a request that authenticated via HTTP Basic MUST
// receive a WWW-Authenticate challenge so RP libraries that follow the
// Basic-auth state machine retry intelligently. The realm value is fixed to
// "oidc" to match the token / userinfo handlers.
func writeInvalidClient(w http.ResponseWriter, basic bool, description string) {
	if basic {
		w.Header().Set("WWW-Authenticate", `Basic realm="oidc"`)
	}
	writeError(w, http.StatusUnauthorized, errInvalidClient, description)
}

// stampNoStore writes the cache-control headers RFC 6749 §5.1 mandates on
// every PAR response, success or failure. Splitting the helper keeps the
// success path and the error path from drifting.
func stampNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}
