package parendpoint

import (
	"net/http"

	"github.com/libraz/go-oidc-provider/internal/httpx"
)

// RFC 6749 §5.2 wire codes the handler emits. The list is closed; ad-hoc
// codes are forbidden so the discoverable error surface stays auditable.
// "invalid_client" and "use_dpop_nonce" are emitted from
// [internal/clientauth/clientauthhttp] and [internal/dpop] respectively
// so the constants live there; this list omits them.
const (
	errInvalidRequest       = "invalid_request"
	errUnauthorizedClient   = "unauthorized_client"
	errInvalidScope         = "invalid_scope"
	errServerError          = "server_error"
	errInvalidRequestObject = "invalid_request_object"
	// errInvalidAuthorizationDetails is RFC 9396 §5's wire code for a
	// pushed authorization_details the OP cannot honour.
	errInvalidAuthorizationDetails = "invalid_authorization_details"
)

// writeError emits the RFC 6749 §5.2 envelope with the supplied status,
// code, and description. The implementation delegates to
// [httpx.WriteError] so the JSON shape, Content-Type, Cache-Control:
// no-store, and Pragma: no-cache headers stay synchronised across every
// endpoint that emits an OAuth error envelope.
func writeError(w http.ResponseWriter, status int, code, description string) {
	_ = httpx.WriteError(w, status, code, description)
}

// stampNoStore writes the cache-control headers RFC 6749 §5.1 mandates
// on every PAR success response. The error path goes through
// [httpx.WriteError] which stamps the same headers; this helper covers
// the success path so the two never drift.
func stampNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}
