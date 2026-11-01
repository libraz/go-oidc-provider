package tokenexchange

import (
	"slices"

	"github.com/libraz/go-oidc-provider/internal/customgrant"
	"github.com/libraz/go-oidc-provider/internal/mtls"
	"github.com/libraz/go-oidc-provider/internal/tokens"
)

// buildCnfClaim returns the RFC 7800 confirmation object the issued
// id_token MUST carry when the request was sender-constrained, or
// nil for an unbound request. The result mirrors what the wire layer
// stamps on the issued access_token via tokenBinding.confirmation in
// internal/tokenendpoint/binding.go so a resource server inspecting
// either token sees the same proof-of-possession material.
//
// Population rules (RFC 7800 §3 allows multiple cnf members):
//
//   - DPoP-bound request yields cnf.jkt (RFC 9449 §6.1).
//   - mTLS-bound request yields cnf.x5t#S256 (RFC 8705 §3.1).
//   - A dual-bound request yields BOTH members; the access-token side
//     stamps both as well so the two carriers do not diverge.
//   - A bearer request returns nil; the caller MUST NOT pollute an
//     unbound id_token with a synthesised cnf.
func buildCnfClaim(req customgrant.Request) map[string]string {
	var x5t string
	if req.MTLSCert != nil {
		x5t = mtls.Thumbprint(req.MTLSCert)
	}
	return tokens.Confirmation(req.DPoPJKT, x5t)
}

// requireMatchingSenderConstraint enforces that every confirmation method
// the subject_token (or actor_token) carries is matched by the exchange
// request. AND-evaluation across populated methods is required because
// RFC 7800 §3 permits multiple confirmation members on one token: a
// switch-on-first-present would let a stolen multi-bound token be
// exchanged against a request that only satisfies one of its methods.
func requireMatchingSenderConstraint(req customgrant.Request, tok TokenView) error {
	if tok.Confirmation == nil {
		return nil
	}
	if tok.Confirmation.JKT != "" {
		if req.DPoPJKT != tok.Confirmation.JKT {
			return invalidGrant("sender-constrained token requires matching DPoP proof")
		}
	}
	if tok.Confirmation.X5tS256 != "" {
		if req.MTLSCert == nil || mtls.Thumbprint(req.MTLSCert) != tok.Confirmation.X5tS256 {
			return invalidGrant("sender-constrained token requires matching mTLS certificate")
		}
	}
	return nil
}

func requireIDTokenAudience(callerClientID string, tok TokenView) error {
	if tok.Type != TokenTypeIDToken {
		return nil
	}
	if !slices.Contains(tok.Audience, callerClientID) {
		return invalidGrant("id_token audience does not include the calling client")
	}
	if tok.ClientID != "" && tok.ClientID != callerClientID {
		return invalidGrant("id_token authorized party does not match the calling client")
	}
	return nil
}
