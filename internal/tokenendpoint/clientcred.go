package tokenendpoint

import (
	"context"
	"errors"
	"net/http"

	"github.com/libraz/go-oidc-provider/internal/grants/clientcred"
	"github.com/libraz/go-oidc-provider/internal/oidcscope"
	"github.com/libraz/go-oidc-provider/internal/resourceindicator"
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
	// Proof verification, client authentication, and the proof's
	// replay marking run in the order [authenticateWithDPoP] documents.
	ctx := r.Context()
	dpopOut, client, ok := authenticateWithDPoP(ctx, w, r, deps)
	if !ok {
		return
	}
	requested, resource, ok := parseClientCredsRequest(w, r)
	if !ok {
		return
	}
	if !validateClientCredsResource(w, client, resource) {
		return
	}
	authorizationDetails, ok := parseTokenAuthorizationDetails(w, r, deps, client)
	if !ok {
		return
	}
	authorized, ok := authorizeClientCreds(w, deps, client, requested)
	if !ok {
		return
	}
	mtlsOut, ok := verifyTokenMTLS(w, r, deps, dpopOut.JKT)
	if !ok {
		return
	}
	binding := tokenBinding{
		DPoPJKT:        dpopOut.JKT,
		MTLSThumbprint: mtlsOut.Thumbprint,
	}
	if !enforceSenderConstraint(w, deps, binding) {
		return
	}
	issueClientCredsResponse(ctx, w, deps, client, authorized.Scope, resource, binding, authorizationDetails)
}

// parseClientCredsRequest extracts the optional "scope" and "resource"
// form parameters. RFC 6749 §4.4 makes scope optional; an absent or
// empty value yields a nil slice and the authorizer falls back to the
// client's registered set. RFC 8707 §2 permits at most one resource
// indicator on a token request in this profile: the form parser
// surfaces a wire error when the same parameter occurs more than once
// with differing values, mirroring the authorize-side single-value
// posture (see internal/authorize.singleValue). Repeated identical
// values are tolerated so an HTTP middleware that re-emits the body
// does not break the handler.
//
// The returned resource string is the canonical form per
// [resourceindicator.Canonicalize] so downstream lookups (the
// per-audience access-token format map, the access-token aud claim)
// see the same bytes regardless of the wire-side casing or trailing
// slash. Malformed values surface as 400 invalid_target before the
// allowlist check runs.
func parseClientCredsRequest(w http.ResponseWriter, r *http.Request) ([]string, string, bool) {
	scope := oidcscope.Parse(r.PostForm.Get("scope"))
	values := r.PostForm["resource"]
	if len(values) == 0 {
		return scope, "", true
	}
	first := values[0]
	for _, candidate := range values[1:] {
		if candidate != first {
			writeError(w, http.StatusBadRequest, errInvalidTarget,
				"only a single resource indicator value is supported")
			return nil, "", false
		}
	}
	canonical, err := resourceindicator.Canonicalize(first)
	if err != nil {
		writeError(w, http.StatusBadRequest, errInvalidTarget,
			"resource parameter is not a valid absolute URI")
		return nil, "", false
	}
	return scope, canonical, true
}

// validateClientCredsResource enforces the RFC 8707 §3 allowlist for
// the client_credentials grant: when the request carries a resource
// indicator the value MUST appear in [store.Client.Resources]. Empty
// resource is the no-op path; the issuance helper falls back to the
// issuer audience. The error code matches internal/authorize.ErrResourceNotAllowed
// verbatim so a client porting a request from /authorize sees the same
// wire shape on /token.
//
// The allowlist check uses [resourceindicator.Contains] so a registered
// entry that pre-dates the canonicalisation policy still matches a
// canonical request without an explicit migration step.
func validateClientCredsResource(w http.ResponseWriter, client *store.Client, resource string) bool {
	if resource == "" {
		return true
	}
	if client == nil || !resourceindicator.Contains(client.Resources, resource) {
		writeError(w, http.StatusBadRequest, errInvalidTarget,
			"resource indicator is missing, or unknown")
		return false
	}
	return true
}

// authorizeClientCreds wraps [clientcred.Authorize] and maps its
// sentinels onto wire codes via [writeClientCredsAuthError]. Returns
// ok=false when a response has already been written.
func authorizeClientCreds(
	w http.ResponseWriter,
	deps Deps,
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
	if !checkTokenScopeAllowlist(w, deps, client.ID, authorized.Scope) {
		return nil, false
	}
	return authorized, true
}

func checkTokenScopeAllowlist(
	w http.ResponseWriter,
	deps Deps,
	clientID string,
	granted []string,
) bool {
	for _, s := range granted {
		if !deps.Scopes.Allows(s, clientID) {
			writeError(w, http.StatusBadRequest, errInvalidScope,
				"scope is restricted to a different client")
			return false
		}
	}
	return true
}

// writeClientCredsAuthError translates clientcred.Err* sentinels onto
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
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	client *store.Client,
	scope []string,
	resource string,
	binding tokenBinding,
	authorizationDetails []map[string]any,
) {
	now := deps.now().UTC()
	// AuthTime is zero: client_credentials has no end-user to time-stamp.
	// The mint helper omits the claim from the encoded JWT when the
	// value is zero, so this is the right shape for RFC 9068 §2.2.
	// GrantID is empty: client_credentials has no authorize-side grant.
	// The registry stores the empty value verbatim and RevokeByGrant("")
	// is a no-op, which is the correct shape — there is no chain to
	// cascade because the wire token is already the only artefact tied
	// to this issuance.
	// resource carries the validated RFC 8707 §3 indicator (empty when
	// the request omitted it); mintAccessToken puts it in aud.
	// client_credentials has no end-user, so the public sub == raw sub
	// == client.ID. SubjectProjector is intentionally not invoked: the
	// pairwise projection is an OIDC §8.1 concept defined for end-user
	// subjects, and projecting client.ID would produce a value the
	// resource server cannot correlate against any authenticated
	// principal.
	accessToken, err := mintAccessToken(ctx, deps, client.ID, client.ID, client.ID, "", scope, resource, now, 0, binding, authorizationDetails)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return
	}
	writeSuccess(w, successResponse{
		AccessToken:          accessToken,
		TokenType:            binding.tokenTypeFor(),
		ExpiresIn:            int64(deps.AccessTokenTTL.Seconds()),
		Scope:                joinScope(scope),
		AuthorizationDetails: cloneAuthorizationDetails(authorizationDetails),
	})
}
