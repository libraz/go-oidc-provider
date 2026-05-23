package tokenendpoint

import "github.com/libraz/go-oidc-provider/op/store"

// tokenBinding bundles the sender-constraint fields a token-endpoint
// response inherits from the inbound request. Issuance code threads
// the value through the access-token mint, the id_token mint, and
// the refresh-token persist so the wire shape and the persisted
// record stay in lock-step.
type tokenBinding struct {
	// DPoPJKT is the RFC 7638 thumbprint extracted from a presented
	// DPoP proof. Empty when the request did not carry a proof.
	DPoPJKT string

	// MTLSThumbprint is the RFC 8705 §3.1 thumbprint extracted from
	// a presented client cert. Empty when the request did not
	// terminate mTLS at the OP (or the proxy header path).
	MTLSThumbprint string
}

// confirmation projects the binding onto the cnf claim shape RFC
// 7800 §3 prescribes. An empty binding returns nil so the access-
// token mint can guard the cnf assignment with a non-nil check.
func (b tokenBinding) confirmation() map[string]string {
	if b.DPoPJKT == "" && b.MTLSThumbprint == "" {
		return nil
	}
	out := make(map[string]string, 2)
	if b.DPoPJKT != "" {
		out["jkt"] = b.DPoPJKT
	}
	if b.MTLSThumbprint != "" {
		out["x5t#S256"] = b.MTLSThumbprint
	}
	return out
}

// tokenTypeFor returns the "token_type" wire value: "DPoP" when a DPoP
// proof bound the token, "Bearer" otherwise. RFC 8705 explicitly
// keeps the bearer token_type for cert-bound tokens (§3.1) because
// the binding is on the cnf claim, not the wire token type.
func (b tokenBinding) tokenTypeFor() string {
	if b.DPoPJKT != "" {
		return "DPoP"
	}
	return "Bearer"
}

// constrained reports whether the binding carries either a DPoP
// thumbprint or an mTLS thumbprint. It is the single source of truth
// for the FAPI 2.0 §3.1.4 "sender-constrained tokens MUST be issued"
// check that [enforceSenderConstraint] consults.
func (b tokenBinding) constrained() bool {
	return b.DPoPJKT != "" || b.MTLSThumbprint != ""
}

// refreshDPoPJKT returns the JKT to persist on a refresh-token record
// for the given client. Public clients MUST have refresh tokens DPoP-bound
// per RFC 9449 §5.4. Confidential clients ([private_key_jwt],
// [client_secret_*], [tls_client_auth]) MAY bind or not (RFC 9449 §5.0);
// the library leaves them unbound so
// the client can rotate its DPoP key across refresh requests, which
// is the OFCS conformance suite's expectation for FAPI 2.0 plans.
//
// The chain remains DPoP-protected at the access-token level: every
// refresh continues to issue a new access token bound to whatever
// DPoP key the client presents on the refresh request, so any holder
// of the access token still needs the matching private key to use it.
func refreshDPoPJKT(client *store.Client, dpopJKT string) string {
	if dpopJKT == "" {
		return ""
	}
	if client != nil && !client.PublicClient && client.TokenEndpointAuthMethod != "none" {
		return ""
	}
	return dpopJKT
}
