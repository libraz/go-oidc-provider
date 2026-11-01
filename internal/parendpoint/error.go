package parendpoint

import "github.com/libraz/go-oidc-provider/internal/endpointsupport"

// RFC 6749 §5.2 wire codes the handler emits directly. The list is
// closed; ad-hoc codes are forbidden so the discoverable error surface
// stays auditable. Codes the endpoint emits through another package's
// catalogue are absent so there is exactly one definition of each:
// "invalid_client" and "use_dpop_nonce" come from
// internal/endpointsupport and internal/dpop, and the
// request-gate codes — RFC 9396 §5's "invalid_authorization_details"
// among them — come from internal/authorize's sentinels, whose Code
// [validateRequestExtensions] renders verbatim.
const (
	errInvalidRequest       = endpointsupport.ErrInvalidRequest
	errServerError          = endpointsupport.ErrServerError
	errInvalidRequestObject = "invalid_request_object"
)
