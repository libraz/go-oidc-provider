package cibaendpoint

import (
	"context"
	"net/http"

	"github.com/libraz/go-oidc-provider/internal/ciba"
	"github.com/libraz/go-oidc-provider/internal/dpop"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/store"
)

// authenticateWithDPoP runs DPoP proof verification and client
// authentication through [endpointsupport.AuthenticateWithDPoP] and
// returns the proof's RFC 7638 thumbprint ("" when no proof was
// presented) alongside the authenticated client. It writes the
// response on every failure path; the caller only checks the bool.
func authenticateWithDPoP(w http.ResponseWriter, r *http.Request, deps Deps) (string, *store.Client, bool) {
	return endpointsupport.AuthenticateWithDPoP(w, r,
		dpop.Gate{Verifier: deps.DPoP, Nonces: deps.DPoPNonces},
		endpointsupport.AuthenticateOpts{
			Clients:           deps.Clients,
			SecretVerifier:    deps.SecretVerifier,
			AssertionVerifier: deps.AssertionVerifier,
			AllowedMethods:    deps.AllowedClientAuthMethods,
			Now:               deps.now(),
			Audit:             deps.auditEmitter(),
		},
		"client authentication failed at backchannel-authentication endpoint",
	)
}

// enforceSenderConstraint applies the FAPI 2.0 / FAPI-CIBA rule
// that no /bc-authorize request MAY produce a bearer token when
// [Deps.RequireSenderConstraint] is true.
func enforceSenderConstraint(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	dpopJKT, mtlsThumbprint, clientID string,
) bool {
	return endpointsupport.EnforceSenderConstraint(ctx, w, deps.auditEmitter(),
		deps.RequireSenderConstraint,
		endpointsupport.SenderConstraintRejection{
			Event:        ciba.AuditAuthorizationUnboundRejected,
			AuditMessage: "backchannel-authentication rejected: unbound request under sender-constraint profile",
			Description:  "backchannel authentication requires DPoP or mTLS under the active profile",
		},
		dpopJKT, mtlsThumbprint, clientID)
}

// verifyClientGrantTypeAllowed rejects clients whose registered
// GrantTypes do not include the CIBA URN.
func verifyClientGrantTypeAllowed(ctx context.Context, w http.ResponseWriter, deps Deps, client *store.Client) bool {
	return endpointsupport.VerifyClientGrantType(ctx, w, deps.auditEmitter(), client, grant.CIBA.String(),
		endpointsupport.GrantRejection{
			Event:        ciba.AuditAuthorizationRejected,
			AuditMessage: "backchannel-authentication rejected: client not registered for grant",
			Description:  "client is not authorized for the ciba grant",
		})
}
