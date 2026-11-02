package endpointsupport

import (
	"errors"
	"net/http"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/httpx"
	"github.com/libraz/go-oidc-provider/internal/rpjwks"
)

// RFC 6749 §5.2 wire codes the helpers emit. The list is closed; ad-hoc
// codes are forbidden so the discoverable error surface stays auditable.
// Endpoints with their own extension codes (e.g. RFC 7591
// "invalid_client_metadata") layer them on top of these constants.
const (
	// ErrInvalidRequest is the canonical "the request is malformed"
	// code (RFC 6749 §5.2). 400 status.
	ErrInvalidRequest = "invalid_request"

	// ErrInvalidClient is the canonical "client authentication failed"
	// code (RFC 6749 §5.2). 401 status; on Basic auth the response also
	// carries a WWW-Authenticate Basic challenge.
	ErrInvalidClient = "invalid_client"

	// ErrServerError is the canonical "internal server error" code
	// (RFC 6749 §5.2). 500 status; the description is left empty so
	// the wire response does not leak internals.
	ErrServerError = "server_error"

	// ErrInvalidGrant is the RFC 6749 §5.2 "grant is invalid, expired,
	// revoked or issued to another client" code. 400 status.
	ErrInvalidGrant = "invalid_grant"

	// ErrInvalidScope is the RFC 6749 §5.2 "requested scope is invalid
	// or exceeds what was granted" code. 400 status.
	ErrInvalidScope = "invalid_scope"

	// ErrAccessDenied is the RFC 6749 §4.1.2.1 / RFC 8628 §3.5 "the
	// resource owner denied the request" code.
	ErrAccessDenied = "access_denied"
)

// WriteServerError emits the 500 "server_error" envelope with an empty
// description so the response does not leak internals.
func WriteServerError(w http.ResponseWriter) {
	WriteOAuthError(w, http.StatusInternalServerError, ErrServerError, "")
}

// WriteOAuthError emits the RFC 6749 §5.2 envelope with the supplied
// status, code, and description. The implementation delegates to
// [httpx.WriteError] so the JSON shape, Content-Type, Cache-Control:
// no-store, and Pragma: no-cache headers stay synchronised across every
// endpoint that emits an OAuth error envelope.
//
// The helper is the consolidated form of the per-endpoint writeError
// wrappers (introspect / revoke / par / token) which all called
// httpx.WriteError with identical arguments.
func WriteOAuthError(w http.ResponseWriter, status int, code, description string) {
	_ = httpx.WriteError(w, status, code, description)
}

// WriteInvalidClient is the dedicated 401 path for the "invalid_client"
// code. Per RFC 6749 §5.2 a request that authenticated via HTTP Basic
// MUST receive a WWW-Authenticate challenge so RP libraries that follow
// the Basic-auth state machine retry intelligently. The realm value is
// fixed to "oidc" to match the token / par / introspect / revoke
// handlers.
func WriteInvalidClient(w http.ResponseWriter, basic bool, description string) {
	if basic {
		w.Header().Set("WWW-Authenticate", `Basic realm="oidc"`)
	}
	WriteOAuthError(w, http.StatusUnauthorized, ErrInvalidClient, description)
}

// WriteAuthnError maps an authentication error onto the wire response.
// The mapping is the canonical RFC 6749 §5.2 table augmented by this
// library's sentinel discrimination, identical across the token / par /
// introspect / revoke endpoints.
//
// The function is the consolidated form of the writeAuthnError helpers
// each endpoint package was carrying its own copy of.
func WriteAuthnError(w http.ResponseWriter, err error, usedBasic bool) {
	switch {
	case errors.Is(err, clientauth.ErrNoCredentials):
		WriteInvalidClient(w, usedBasic, "client authentication required")
	case errors.Is(err, clientauth.ErrAmbiguousCredentials),
		errors.Is(err, clientauth.ErrUnsupportedMethod):
		WriteOAuthError(w, http.StatusBadRequest, ErrInvalidRequest,
			"client authentication parameters are malformed")
	case errors.Is(err, clientauth.ErrClientMismatch),
		errors.Is(err, clientauth.ErrCredentialsInvalid),
		errors.Is(err, clientauth.ErrAssertionMalformed),
		errors.Is(err, clientauth.ErrAssertionReplayed):
		WriteInvalidClient(w, usedBasic, "client authentication failed")
	case rpjwks.IsKeySourceUnavailable(err):
		// A JWKS fetch refused for capacity or failing transiently is
		// the OP's fault and retryable; answered as /authorize answers
		// its own fetch-capacity exhaustion.
		WriteOAuthError(w, http.StatusServiceUnavailable, ErrServerError,
			"client keys are temporarily unavailable")
	default:
		WriteServerError(w)
	}
}
