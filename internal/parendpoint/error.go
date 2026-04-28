package parendpoint

import (
	"net/http"

	"github.com/libraz/go-oidc-provider/internal/httpx"
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

// writeError emits the RFC 6749 §5.2 envelope with the supplied status,
// code, and description. The implementation delegates to
// [httpx.WriteError] so the JSON shape, Content-Type, Cache-Control:
// no-store, and Pragma: no-cache headers stay synchronised across every
// endpoint that emits an OAuth error envelope.
func writeError(w http.ResponseWriter, status int, code, description string) {
	_ = httpx.WriteError(w, status, code, description)
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

// stampNoStore writes the cache-control headers RFC 6749 §5.1 mandates
// on every PAR success response. The error path goes through
// [httpx.WriteError] which stamps the same headers; this helper covers
// the success path so the two never drift.
func stampNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}
