package cibaendpoint

// Wire codes the handler emits. RFC 6749 §5.2 defines the OAuth
// catalogue; CIBA Core §13 introduces three additional values
// ("unknown_user_id", "invalid_binding_message", and the OIDC Core
// "login_required" reuse) that surface only on /bc-authorize.
// "invalid_client" is emitted from
// internal/endpointsupport so the constant lives there
// and is omitted from this list.
const (
	errInvalidRequest        = "invalid_request"
	errInvalidScope          = "invalid_scope"
	errInvalidTarget         = "invalid_target"
	errUnauthorizedClient    = "unauthorized_client"
	errAccessDenied          = "access_denied"
	errServerError           = "server_error"
	errUnknownUserID         = "unknown_user_id"
	errInvalidBindingMessage = "invalid_binding_message"
	errLoginRequired         = "login_required"
)
