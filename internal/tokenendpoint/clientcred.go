package tokenendpoint

import (
	"errors"
	"net/http"

	"github.com/libraz/go-oidc-provider/internal/grants/clientcred"
	"github.com/libraz/go-oidc-provider/op/store"
)

// handleClientCredentials implements the "grant_type=client_credentials"
// branch of RFC 6749 §4.4. The function is a thin orchestration: client
// authentication, scope/grant policy via [clientcred.Authorize], DPoP /
// mTLS binding, access-token mint, and the response. Refresh tokens and
// id_tokens are intentionally absent: §4.4.3 forbids the former and the
// grant has no end-user identity to certify in the latter.
//
// Decomposing into named helpers mirrors [handleAuthorizationCode] and
// keeps the cyclomatic complexity well under the project's cap.
func handleClientCredentials(w http.ResponseWriter, r *http.Request, deps Deps) {
	ctx := r.Context()
	client, _, ok := authenticate(ctx, w, r, deps)
	if !ok {
		return
	}
	requested, ok := parseClientCredsRequest(w, r)
	if !ok {
		return
	}
	authorized, ok := authorizeClientCreds(w, client, requested)
	if !ok {
		return
	}
	dpopOut, ok := verifyTokenDPoP(w, r, deps)
	if !ok {
		return
	}
	mtlsOut, ok := verifyTokenMTLS(w, r, deps, dpopOut.JKT)
	if !ok {
		return
	}
	issueClientCredsResponse(w, deps, client, authorized.Scope, tokenBinding{
		DPoPJKT:        dpopOut.JKT,
		MTLSThumbprint: mtlsOut.Thumbprint,
	})
}

// parseClientCredsRequest extracts the optional "scope" form parameter.
// RFC 6749 §4.4 makes scope optional; an absent or empty value yields a
// nil slice and the authorizer falls back to the client's registered
// set. The function returns ok=false only on a structurally malformed
// body, which the dispatcher has already filtered through
// [http.Request.ParseForm].
func parseClientCredsRequest(_ http.ResponseWriter, r *http.Request) ([]string, bool) {
	return parseScopeParam(r.PostForm.Get("scope")), true
}

// authorizeClientCreds wraps [clientcred.Authorize] and maps its
// sentinels onto wire codes via [writeClientCredsAuthError]. Returns
// ok=false when a response has already been written.
func authorizeClientCreds(
	w http.ResponseWriter,
	client *store.Client,
	requested []string,
) (*clientcred.Authorized, bool) {
	authorized, err := clientcred.Authorize(clientcred.AuthorizeInput{
		Client:         client,
		RequestedScope: requested,
	})
	if err != nil {
		writeClientCredsAuthError(w, err)
		return nil, false
	}
	return authorized, true
}

// writeClientCredsAuthError translates [clientcred.Err*] sentinels onto
// the wire form. The mapping is:
//
//   - ErrPublicClient, ErrGrantNotPermitted → 400 unauthorized_client.
//     RFC 6749 §5.2 reserves "unauthorized_client" for "the
//     authenticated client is not authorized to use this authorization
//     grant type", which is exactly the case here. The two failure
//     modes converge on the same code so an attacker cannot tell
//     "client is public" apart from "grant not registered" by the
//     wire code alone.
//
//   - ErrOpenIDScope, ErrScopeForbidden → 400 invalid_scope. Both are
//     scope-policy violations the §5.2 definition of invalid_scope
//     covers verbatim ("requested scope is invalid, unknown,
//     malformed, or exceeds the scope granted by the resource
//     owner").
//
//   - default → 500 server_error. The "nil client" case from the
//     authorizer falls here; it indicates a programmer bug in the
//     handler glue and must not leak as a wire code.
func writeClientCredsAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, clientcred.ErrPublicClient),
		errors.Is(err, clientcred.ErrGrantNotPermitted):
		writeError(w, http.StatusBadRequest, errUnauthorizedClient,
			"client is not authorized for client_credentials")
	case errors.Is(err, clientcred.ErrOpenIDScope):
		writeError(w, http.StatusBadRequest, errInvalidScope,
			"openid scope is not permitted on client_credentials")
	case errors.Is(err, clientcred.ErrScopeForbidden):
		writeError(w, http.StatusBadRequest, errInvalidScope,
			"requested scope exceeds the client's registered set")
	default:
		writeError(w, http.StatusInternalServerError, errServerError, "")
	}
}

// issueClientCredsResponse mints the access token and writes the success
// body. The response intentionally omits "refresh_token" and "id_token":
// §4.4.3 forbids the former and the latter has no subject to certify.
//
// The "sub" claim is populated with the client_id. RFC 9068 §2.2 and
// FAPI 2.0 baseline both adopt this posture for client_credentials
// because the client is the subject acting on its own behalf — there
// is no distinct end-user to identify. The sender-constraint binding
// (cnf.jkt for DPoP, cnf.x5t#S256 for mTLS) is propagated through the
// existing [tokenBinding] plumbing so a client_credentials access
// token inherits the same protections an authorization_code token
// would.
func issueClientCredsResponse(
	w http.ResponseWriter,
	deps Deps,
	client *store.Client,
	scope []string,
	binding tokenBinding,
) {
	now := deps.now().UTC()
	// AuthTime is zero: client_credentials has no end-user to time-stamp.
	// The mint helper omits the claim from the encoded JWT when the
	// value is zero, so this is the right shape for RFC 9068 §2.2.
	accessToken, err := mintAccessToken(deps, client.ID, client.ID, scope, now, 0, binding)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return
	}
	writeSuccess(w, successResponse{
		AccessToken: accessToken,
		TokenType:   binding.tokenTypeFor(),
		ExpiresIn:   int64(deps.AccessTokenTTL.Seconds()),
		Scope:       joinScope(scope),
	})
}
