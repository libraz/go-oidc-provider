package endpointsupport

import (
	"net/http"

	"github.com/libraz/go-oidc-provider/internal/httpx"
)

// HintRefreshToken is the "token_type_hint" (RFC 7662 §2.1 / RFC 7009
// §2.1) that moves the opaque-token lookup ahead of JWT verification.
// Any other hint falls through in the default order.
const HintRefreshToken = "refresh_token"

// TokenLookupSingleValuedParams is the closed list of introspection and
// revocation request parameters (RFC 7662 §2.1, RFC 7009 §2.1) plus the
// shared client-authentication credentials that must not appear more
// than once.
//
//nolint:gochecknoglobals // closed allow-list, intentional package state.
var TokenLookupSingleValuedParams = []string{
	"token",
	"token_type_hint",
	"client_id",
	"client_secret",
	"client_assertion_type",
	"client_assertion",
}

// ParseFormRequest runs the request-shape gates every form-bodied POST
// endpoint clears before any cryptographic or business work: HTTP
// method, content type, body size, body parse, and the RFC 6749 §3.2
// rejection of a repeated name from singleValued (nil skips that
// check). On failure it writes the OAuth error envelope and returns
// false; on success r.PostForm is populated.
func ParseFormRequest(w http.ResponseWriter, r *http.Request, singleValued []string) bool {
	if !httpx.EnforceMethod(w, r, http.MethodPost) {
		return false
	}
	if !IsFormContent(r.Header.Get("Content-Type")) {
		WriteOAuthError(w, http.StatusBadRequest, ErrInvalidRequest,
			"content-type must be application/x-www-form-urlencoded")
		return false
	}
	LimitFormBody(w, r)
	if err := r.ParseForm(); err != nil {
		WriteOAuthError(w, http.StatusBadRequest, ErrInvalidRequest, "malformed form body")
		return false
	}
	if name, ok := httpx.FirstDuplicateParameter(r.PostForm, singleValued); !ok {
		WriteOAuthError(w, http.StatusBadRequest, ErrInvalidRequest,
			"parameter "+name+" must not be repeated")
		return false
	}
	return true
}
