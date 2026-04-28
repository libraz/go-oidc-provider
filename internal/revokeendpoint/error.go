package revokeendpoint

import (
	"net/http"

	"github.com/libraz/go-oidc-provider/internal/httpx"
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
	errInvalidRequest = "invalid_request"
	errInvalidClient  = "invalid_client"
	errServerError    = "server_error"
)

// writeError emits the RFC 6749 §5.2 envelope with the supplied status,
// code, and description. The implementation delegates to
// [httpx.WriteError] so the JSON shape, Content-Type, Cache-Control:
// no-store, and Pragma: no-cache headers stay synchronised across every
// endpoint that emits an OAuth error envelope.
func writeError(w http.ResponseWriter, status int, code, description string) {
	_ = httpx.WriteError(w, status, code, description)
}

// writeInvalidClient is the dedicated 401 path for the "invalid_client"
// code. Per RFC 6749 §5.2 a request that authenticated via HTTP Basic
// MUST receive a WWW-Authenticate challenge so RP libraries that
// follow the Basic-auth state machine retry intelligently. The realm
// value is fixed to "oidc" to match the token / par / introspect
// handlers.
func writeInvalidClient(w http.ResponseWriter, basic bool, description string) {
	if basic {
		w.Header().Set("WWW-Authenticate", `Basic realm="oidc"`)
	}
	writeError(w, http.StatusUnauthorized, errInvalidClient, description)
}

// stampNoStore writes the cache-control headers the package applies to
// the success path. The error path goes through [httpx.WriteError]
// which stamps the same headers; this helper keeps the two consistent.
func stampNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}
