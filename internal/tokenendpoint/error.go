package tokenendpoint

import "github.com/libraz/go-oidc-provider/internal/endpointsupport"

// RFC 6749 §5.2 wire codes the handler emits. The list is closed; ad-hoc
// codes are forbidden so the discoverable error surface stays auditable.
// "invalid_client" and "use_dpop_nonce" are emitted from
// internal/endpointsupport and internal/dpop respectively
// so the constants live there; this list omits them.
const (
	errInvalidRequest       = endpointsupport.ErrInvalidRequest
	errInvalidGrant         = endpointsupport.ErrInvalidGrant
	errUnauthorizedClient   = endpointsupport.ErrUnauthorizedClient
	errUnsupportedGrantType = "unsupported_grant_type"
	errInvalidScope         = endpointsupport.ErrInvalidScope
	errInvalidTarget        = endpointsupport.ErrInvalidTarget
	errInvalidAuthzDetails  = "invalid_authorization_details"
	errServerError          = endpointsupport.ErrServerError

	// RFC 8628 §3.5 / CIBA Core §11 codes shared by the polling grants.
	errAuthorizationPending = "authorization_pending"
	errSlowDown             = "slow_down"
	errAccessDenied         = endpointsupport.ErrAccessDenied
	errExpiredToken         = "expired_token"
)
