package cibaendpoint

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/ciba"
	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/dpop"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/mtls"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/store"
)

// auditClientAuthnFailure aliases the canonical event constant so
// the boundary helper and the local emission sites cannot drift.
const auditClientAuthnFailure = endpointsupport.EventClientAuthnFailure

// authenticateWithDPoP runs DPoP proof verification and client
// authentication through the shared [dpop.Gate] and returns the
// proof's RFC 7638 thumbprint ("" when no proof was presented)
// alongside the authenticated client.
//
// The gate documents the verify → authenticate → commit ordering and
// the reasons behind it; /bc-authorize inherits it unchanged. The
// deferred replay commit matters here because the endpoint requires a
// credential: a proof burned on a request that never authenticated
// would make the legitimate retry look like a replay.
//
// The function writes the response on every failure path; the caller
// only checks the bool.
func authenticateWithDPoP(w http.ResponseWriter, r *http.Request, deps Deps) (string, *store.Client, bool) {
	var client *store.Client
	checked, ok := dpopGate(deps).Authenticate(r.Context(), w, r, func() bool {
		var authOK bool
		client, _, authOK = authenticate(r.Context(), w, r, deps)
		return authOK
	})
	if !ok {
		return "", nil, false
	}
	return checked.Thumbprint(), client, true
}

// dpopGate projects [Deps] onto the shared proof lifecycle. A nil
// [Deps.DPoP] yields a gate that admits every request without a proof;
// the profile-level requirement that a proof be presented at all is a
// separate gate ([enforceSenderConstraint]).
func dpopGate(deps Deps) dpop.Gate {
	return dpop.Gate{Verifier: deps.DPoP, Nonces: deps.DPoPNonces}
}

// authenticate resolves the client credentials carried by the
// request, looks the client up in the registry, and verifies the
// credentials. The helper delegates to a per-request
// [endpointsupport.AuthenticateClient] so /bc-authorize shares an
// identical authentication contract with the token, PAR, and
// device-authorization endpoints.
func authenticate(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	deps Deps,
) (*store.Client, *clientauth.Credentials, bool) {
	return endpointsupport.AuthenticateClient(ctx, w, r,
		endpointsupport.AuthenticateOpts{
			Clients:           deps.Clients,
			SecretVerifier:    deps.SecretVerifier,
			AssertionVerifier: deps.AssertionVerifier,
			AllowedMethods:    deps.AllowedClientAuthMethods,
			Now:               deps.now(),
			Audit:             deps.auditEmitter(),
		},
		endpointsupport.AuditAuthnFailure(ctx, deps.auditEmitter(), auditClientAuthnFailure,
			"client authentication failed at backchannel-authentication endpoint"),
	)
}

// extractMTLSThumbprint returns the SHA-256 thumbprint of the
// inbound mTLS leaf certificate. Returns ("", true) when [Deps.MTLS]
// is nil or the request did not present a certificate at all; a
// certificate that was presented but unusable writes the wire error
// and returns ("", false) so the caller fails closed instead of
// silently treating the request as unbound, matching how the token
// endpoint's verifyTokenMTLS behaves.
func extractMTLSThumbprint(w http.ResponseWriter, r *http.Request, deps Deps) (string, bool) {
	if deps.MTLS == nil {
		return "", true
	}
	thumb, err := deps.MTLS.ThumbprintFromRequest(r)
	if err != nil {
		if errors.Is(err, mtls.ErrNoClientCert) {
			return "", true
		}
		writeMTLSError(w, err)
		return "", false
	}
	return thumb, true
}

// writeMTLSError translates an mtls.Err* sentinel onto the wire
// form, mirroring the mapping the token endpoint uses:
// invalid_request for a certificate that could not be parsed, and
// invalid_client (RFC 8705 §3) for one that failed chain
// validation against the configured trust anchors.
func writeMTLSError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, mtls.ErrCertMalformed):
		writeError(w, http.StatusBadRequest, errInvalidRequest, "client certificate malformed")
	case errors.Is(err, mtls.ErrCertUntrusted):
		endpointsupport.WriteInvalidClient(w, false, "client certificate is not trusted")
	default:
		writeError(w, http.StatusInternalServerError, errServerError, "")
	}
}

// enforceSenderConstraint applies the FAPI 2.0 / FAPI-CIBA rule
// that no /bc-authorize request MAY produce a bearer token. When
// [Deps.RequireSenderConstraint] is true and the request carries
// neither DPoP nor mTLS, the function writes invalid_request and
// returns false.
func enforceSenderConstraint(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	dpopJKT, mtlsThumbprint, clientID string,
) bool {
	if !deps.RequireSenderConstraint {
		return true
	}
	if dpopJKT != "" || mtlsThumbprint != "" {
		return true
	}
	deps.auditEmitter().Emit(ctx, audit.Event{
		Name:     ciba.AuditAuthorizationUnboundRejected,
		Level:    audit.LevelWarn,
		Message:  "backchannel-authentication rejected: unbound request under sender-constraint profile",
		ClientID: clientID,
		Extras: map[string]any{
			"profile": "fapi2_baseline",
			"reason":  "unbound_request",
		},
	})
	writeError(w, http.StatusBadRequest, errInvalidRequest,
		"backchannel authentication requires DPoP or mTLS under the active profile")
	return false
}

// verifyClientGrantTypeAllowed rejects clients whose registered
// GrantTypes do not include the CIBA URN. The check matches the
// token-endpoint poll's gate so a misconfigured client cannot
// even initiate a CIBA flow.
func verifyClientGrantTypeAllowed(ctx context.Context, w http.ResponseWriter, deps Deps, client *store.Client) bool {
	if slices.Contains(client.GrantTypes, grant.CIBA.String()) {
		return true
	}
	deps.auditEmitter().Emit(ctx, audit.Event{
		Name:     ciba.AuditAuthorizationRejected,
		Level:    audit.LevelWarn,
		Message:  "backchannel-authentication rejected: client not registered for grant",
		ClientID: client.ID,
		Extras: map[string]any{
			"reason": "grant_type_not_permitted",
		},
	})
	writeError(w, http.StatusBadRequest, errUnauthorizedClient,
		"client is not authorized for the ciba grant")
	return false
}
