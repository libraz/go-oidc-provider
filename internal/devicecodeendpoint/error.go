package devicecodeendpoint

// RFC 6749 §5.2 wire codes the handler emits. The list is closed;
// "invalid_client" is emitted from
// internal/endpointsupport so the constant lives there
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
