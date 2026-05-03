package devicecodeendpoint

import (
	"net/http"

	"github.com/libraz/go-oidc-provider/internal/httpx"
)

// RFC 6749 §5.2 wire codes the handler emits. The list is closed;
// "invalid_client" is emitted from
// [internal/clientauth/clientauthhttp] so the constant lives there
// and is omitted from this list. RFC 8628 §3.5 itself does not
// define new error codes for the device-authorization endpoint
// (its codes apply to the token endpoint poll); the issuance
// handler reuses the §5.2 catalogue.
const (
	errInvalidRequest      = "invalid_request"
	errInvalidScope        = "invalid_scope"
	errInvalidTarget       = "invalid_target"
	errUnauthorizedClient  = "unauthorized_client"
	errAccessDenied        = "access_denied"
	errServerError         = "server_error"
	errSlowDown            = "slow_down"
	errUnsupportedResponse = "unsupported_response_type"
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
// mandates on every device-authorization success response. The
// error path goes through [httpx.WriteError] which stamps the same
// headers; this helper covers the success path so the two never
// drift.
func stampNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}
