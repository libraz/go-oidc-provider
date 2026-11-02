package cibaendpoint

import (
	"github.com/libraz/go-oidc-provider/internal/ciba"
	"github.com/libraz/go-oidc-provider/internal/dpop"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/op/grant"
)

// initiationGate builds the client-authentication, sender-constraint
// (FAPI 2.0 / FAPI-CIBA) and grant-registration gates for /bc-authorize.
func (d *Deps) initiationGate() endpointsupport.InitiationGate {
	return endpointsupport.InitiationGate{
		DPoP: dpop.Gate{Verifier: d.DPoP, Nonces: d.DPoPNonces},
		Auth: endpointsupport.AuthenticateOpts{
			Clients:           d.Clients,
			SecretVerifier:    d.SecretVerifier,
			AssertionVerifier: d.AssertionVerifier,
			AllowedMethods:    d.AllowedClientAuthMethods,
			Now:               d.now(),
			Audit:             d.auditEmitter(),
		},
		AuthFailureMessage:      "client authentication failed at backchannel-authentication endpoint",
		RequireSenderConstraint: d.RequireSenderConstraint,
		Unbound: endpointsupport.SenderConstraintRejection{
			Event:        ciba.AuditAuthorizationUnboundRejected,
			AuditMessage: "backchannel-authentication rejected: unbound request under sender-constraint profile",
			Description:  "backchannel authentication requires DPoP or mTLS under the active profile",
		},
		GrantURN: grant.CIBA.String(),
		GrantMissing: endpointsupport.GrantRejection{
			Event:        ciba.AuditAuthorizationRejected,
			AuditMessage: "backchannel-authentication rejected: client not registered for grant",
			Description:  "client is not authorized for the ciba grant",
		},
	}
}
