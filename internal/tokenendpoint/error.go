package tokenendpoint

// RFC 6749 §5.2 wire codes the handler emits. The list is closed; ad-hoc
// codes are forbidden so the discoverable error surface stays auditable.
// "invalid_client" and "use_dpop_nonce" are emitted from
// internal/endpointsupport and internal/dpop respectively
// so the constants live there; this list omits them.
const (
	errInvalidRequest       = "invalid_request"
	errInvalidGrant         = "invalid_grant"
	errUnauthorizedClient   = "unauthorized_client"
	errUnsupportedGrantType = "unsupported_grant_type"
	errInvalidScope         = "invalid_scope"
	errInvalidTarget        = "invalid_target"
	errInvalidAuthzDetails  = "invalid_authorization_details"
	errServerError          = "server_error"
)
