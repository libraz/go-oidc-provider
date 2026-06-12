package tokenendpoint

import (
	"net/http"

	"github.com/libraz/go-oidc-provider/internal/httpx"
)

// RFC 6749 §5.2 wire codes the handler emits. The list is closed; ad-hoc
// codes are forbidden so the discoverable error surface stays auditable.
// "invalid_client" and "use_dpop_nonce" are emitted from
// [internal/clientauth/clientauthhttp] and [internal/dpop] respectively
// so the constants live there; this list omits them.
const (
	errInvalidRequest       = "invalid_request"
	errInvalidGrant         = "invalid_grant"
	errUnauthorizedClient   = "unauthorized_client"
	errUnsupportedGrantType = "unsupported_grant_type"
	errInvalidScope         = "invalid_scope"
	errInvalidTarget        = "invalid_target"
	errServerError          = "server_error"
)

// writeError emits the §5.2 envelope with the supplied status, code, and
// description. Cache-Control / Pragma are stamped here so every error
// path automatically satisfies §5.1; callers MUST NOT re-stamp them.
func writeError(w http.ResponseWriter, status int, code, description string) {
	_ = httpx.WriteError(w, status, code, description)
}
