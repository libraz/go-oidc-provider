package cibaendpoint

import (
	"net/http"

	"github.com/libraz/go-oidc-provider/internal/httpx"
)

// Wire codes the handler emits. RFC 6749 §5.2 defines the OAuth
// catalogue; CIBA Core §13 introduces three additional values
// ("unknown_user_id", "invalid_binding_message", and the OIDC Core
// "login_required" reuse) that surface only on /bc-authorize.
// "invalid_client" is emitted from
// [internal/clientauth/clientauthhttp] so the constant lives there
// and is omitted from this list.
const (
	errInvalidRequest        = "invalid_request"
	errInvalidRequestObject  = "invalid_request_object"
	errInvalidScope          = "invalid_scope"
	errInvalidTarget         = "invalid_target"
	errUnauthorizedClient    = "unauthorized_client"
	errAccessDenied          = "access_denied"
	errServerError           = "server_error"
	errUnknownUserID         = "unknown_user_id"
	errInvalidBindingMessage = "invalid_binding_message"
	errLoginRequired         = "login_required"
)

// writeError emits the RFC 6749 §5.2 envelope with the supplied
// status, code, and description. The implementation delegates to
// [httpx.WriteError] so the JSON shape, Content-Type, Cache-Control:
// no-store, and Pragma: no-cache headers stay synchronised across
// every endpoint that emits an OAuth error envelope.
func writeError(w http.ResponseWriter, status int, code, description string) {
	_ = httpx.WriteError(w, status, code, description)
}

// stampNoStore writes the cache-control headers RFC 6749 §5.1
// mandates on every backchannel-authentication success response.
// The error path goes through [httpx.WriteError] which stamps the
// same headers; this helper covers the success path so the two
// never drift.
func stampNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}
