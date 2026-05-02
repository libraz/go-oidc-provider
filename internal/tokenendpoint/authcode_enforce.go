package tokenendpoint

import (
	"net/http"

	"github.com/libraz/go-oidc-provider/internal/grants/authcode"
	"github.com/libraz/go-oidc-provider/op/store"
)

// enforcePKCEDowngradeGuard refuses an authorization_code exchange
// when a public client redeems a code that was issued without a PKCE
// challenge. RFC 9700 §2.1.1 (OAuth 2.0 Security Best Current
// Practice) requires PKCE on every public-client code flow; this
// check is defence-in-depth in case the
// authorize-side gate (which is profile-conditional) was misconfigured
// or bypassed via a forged stored record. Confidential clients are
// free to opt out of PKCE per RFC 6749 §4.1, so the guard scopes to
// [store.Client.PublicClient] and [store.Client.TokenEndpointAuthMethod]
// == "none". The error code is "invalid_grant" because the violation
// is a property of the redeemed grant, not of the request shape.
func enforcePKCEDowngradeGuard(
	w http.ResponseWriter,
	client *store.Client,
	exchanged *authcode.Exchanged,
) bool {
	if exchanged == nil || client == nil {
		return true
	}
	publicClient := client.PublicClient || client.TokenEndpointAuthMethod == "none"
	if !publicClient {
		return true
	}
	if exchanged.HadCodeChallenge {
		return true
	}
	writeError(w, http.StatusBadRequest, errInvalidGrant,
		"PKCE is required for public clients (RFC 9700 §2.1.1)")
	return false
}

// enforceDPoPJKTBinding implements the RFC 9449 §10 contract: when the
// authorization request committed to a DPoP key via the "dpop_jkt"
// parameter, the token endpoint MUST refuse a proof that does not
// match. A non-empty stored thumbprint also requires a proof to be
// presented at all — admitting an unbound token would let an attacker
// who stole the code circumvent the commitment.
//
// When the stored thumbprint is empty the inbound proof's JKT is the
// only binding, so this function is a no-op.
func enforceDPoPJKTBinding(w http.ResponseWriter, exchanged *authcode.Exchanged, binding tokenBinding) bool {
	if exchanged == nil || exchanged.DPoPJKT == "" {
		return true
	}
	if binding.DPoPJKT == "" {
		writeError(w, http.StatusBadRequest, errInvalidGrant,
			"authorization code is bound to a DPoP key but no proof was presented")
		return false
	}
	if binding.DPoPJKT != exchanged.DPoPJKT {
		writeError(w, http.StatusBadRequest, errInvalidGrant,
			"DPoP proof key does not match the dpop_jkt commitment")
		return false
	}
	return true
}

// enforceSenderConstraint refuses an issuance when the deployment
// requires sender-constrained tokens but the inbound request did not
// present one. It writes the wire error and returns false on the
// reject path; the success path is a no-op true so callers can chain
// it like the other guard helpers in the handler. The error code is
// "invalid_request" because the missing proof is a property of the
// HTTP request shape, not of the credential or the grant: an RP that
// learns of the FAPI policy can fix the problem by re-trying with a
// proof header or a client certificate.
func enforceSenderConstraint(w http.ResponseWriter, deps Deps, b tokenBinding) bool {
	if !deps.RequireSenderConstrainedTokens || b.constrained() {
		return true
	}
	writeError(w, http.StatusBadRequest, errInvalidRequest,
		"sender-constrained access token required: present a DPoP proof or a client certificate")
	return false
}
