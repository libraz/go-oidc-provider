package tokenexchange

import (
	"github.com/libraz/go-oidc-provider/internal/customgrant"
	"github.com/libraz/go-oidc-provider/internal/mtls"
)

// buildCnfClaim returns the RFC 7800 confirmation object the issued
// id_token MUST carry when the request was sender-constrained, or
// nil for an unbound request. The result mirrors what the wire layer
// stamps on the issued access_token via tokenBinding.confirmation in
// internal/tokenendpoint/binding.go so a resource server inspecting
// either token sees the same proof-of-possession key.
//
// Precedence matches the access-token mint:
//
//   - DPoP wins over mTLS (RFC 9449 §6.1 + FAPI 2.0 §5.3.2.2). When
//     both are present the access-token side already collapses to
//     cnf.jkt; the id_token follows suit so the two carriers do not
//     diverge.
//   - mTLS-only requests yield cnf.x5t#S256 (RFC 8705 §3.1).
//   - A bearer request returns nil; the caller MUST NOT pollute an
//     unbound id_token with a synthesised cnf.
func buildCnfClaim(req customgrant.Request) map[string]string {
	if req.DPoPJKT != "" {
		return map[string]string{"jkt": req.DPoPJKT}
	}
	if req.MTLSCert != nil {
		thumb := mtls.Thumbprint(req.MTLSCert)
		if thumb != "" {
			return map[string]string{"x5t#S256": thumb}
		}
	}
	return nil
}
