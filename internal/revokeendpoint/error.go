package revokeendpoint

import (
	"net/http"

	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
)

// RFC 6749 §5.2 wire codes the handler emits for pre-authentication
// failures. The list is closed; ad-hoc codes are forbidden so the
// discoverable error surface stays auditable.
// RFC 7009 §2.2.1 also defines "unsupported_token_type" for ASes that
// reject revocation of a particular token type, but v1.0 supports both
// access_token and refresh_token (the only two values RFC 7009 §2.1
// defines for token_type_hint), so the code never reaches the wire and
// is intentionally not declared as a constant.
const (
	errInvalidRequest = endpointsupport.ErrInvalidRequest
)

// writeError emits the RFC 6749 §5.2 envelope with the supplied status,
// code, and description. The implementation delegates to
// [endpointsupport.WriteOAuthError] so the JSON shape, Content-Type,
// Cache-Control: no-store, and Pragma: no-cache headers stay
// synchronised across every endpoint that emits an OAuth error envelope.
func writeError(w http.ResponseWriter, status int, code, description string) {
	endpointsupport.WriteOAuthError(w, status, code, description)
}

// stampNoStore writes the cache-control headers the package applies to
// the success path. The error path goes through
// [endpointsupport.WriteOAuthError] which stamps the same headers; this
// helper keeps the two consistent.
func stampNoStore(w http.ResponseWriter) {
	endpointsupport.StampNoStore(w)
}
