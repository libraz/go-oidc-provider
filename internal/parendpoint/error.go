package parendpoint

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
	errInvalidRequest       = "invalid_request"
	errUnauthorizedClient   = "unauthorized_client"
	errInvalidScope         = "invalid_scope"
	errServerError          = "server_error"
	errInvalidRequestObject = "invalid_request_object"
)
