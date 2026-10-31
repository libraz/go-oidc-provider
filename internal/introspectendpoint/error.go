package introspectendpoint

import (
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
)

// RFC 6749 §5.2 wire codes the handler emits for pre-authentication
// failures. The list is closed; ad-hoc codes are forbidden so the
// discoverable error surface stays auditable.
const (
	errInvalidRequest = endpointsupport.ErrInvalidRequest
	errServerError    = endpointsupport.ErrServerError
)
