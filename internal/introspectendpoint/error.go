package introspectendpoint

import (
	"net/http"

	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
)

// RFC 6749 §5.2 wire codes the handler emits for pre-authentication
// failures. The list is closed; ad-hoc codes are forbidden so the
// discoverable error surface stays auditable.
const (
	errInvalidRequest = endpointsupport.ErrInvalidRequest
	errServerError    = endpointsupport.ErrServerError
)

// writeError emits the RFC 6749 §5.2 envelope with the supplied status,
// code, and description. The implementation delegates to
// [endpointsupport.WriteOAuthError] so the JSON shape, Content-Type,
// Cache-Control: no-store, and Pragma: no-cache headers stay
// synchronised across every endpoint that emits an OAuth error envelope.
func writeError(w http.ResponseWriter, status int, code, description string) {
	endpointsupport.WriteOAuthError(w, status, code, description)
}

// stampNoStore writes the cache-control header RFC 7662 §4 mandates on
// every introspection success response. The error path goes through
// [endpointsupport.WriteOAuthError] which stamps the same headers; this
// helper covers the success path so the two never drift.
func stampNoStore(w http.ResponseWriter) {
	endpointsupport.StampNoStore(w)
}
