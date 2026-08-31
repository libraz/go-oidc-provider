package tokenendpoint

import (
	"context"
	"net/http"
	"slices"

	"github.com/libraz/go-oidc-provider/internal/dpop"
	"github.com/libraz/go-oidc-provider/op/store"
)

// dpopOutcome is the result of the token endpoint's proof phase: a
// (possibly empty) thumbprint plus a flag reporting whether a proof was
// actually presented. The split lets handler code distinguish "no
// proof, issue bearer token" from "proof verified, bind to jkt" without
// inspecting the Verifier directly.
type dpopOutcome struct {
	// JKT is the RFC 7638 thumbprint extracted from the proof. Empty
	// when no proof was presented.
	JKT string

	// JTI is the proof's "jti" claim, exposed so downstream consumers
	// (e.g. custom-grant dispatch) can include the value in audit
	// emission without re-parsing the proof.
	JTI string

	// Presented reports whether the request carried a DPoP header at
	// all. Useful for refresh-token enforcement: a chain bound to a
	// jkt requires a proof to be presented even if the verifier is
	// configured to issue bearer tokens by default.
	Presented bool
}

// newDPoPOutcome projects the shared [dpop.Checked] onto the shape the
// grant handlers consume. A nil proof — DPoP disabled, or no header on
// the request — yields the zero outcome, which routes the handler onto
// the bearer path.
func newDPoPOutcome(checked *dpop.Checked) *dpopOutcome {
	if checked == nil {
		return &dpopOutcome{}
	}
	return &dpopOutcome{JKT: checked.JKT, JTI: checked.JTI, Presented: true}
}

// dpopGate projects [Deps] onto the shared proof lifecycle. A nil
// [Deps.DPoP] yields a gate that admits every request without a proof,
// so the handler issues bearer tokens.
func dpopGate(deps Deps) dpop.Gate {
	return dpop.Gate{Verifier: deps.DPoP, Nonces: deps.DPoPNonces}
}

// authenticateWithDPoP runs DPoP proof verification and client
// authentication through the shared [dpop.Gate], and is the entry
// point every grant handler uses.
//
// The gate documents the verify → authenticate → commit ordering and
// the reasons behind it; the token endpoint inherits it unchanged and
// folds the per-client grant gate into the authentication step, so
// that check too runs between the two proof phases.
//
// grantType is the wire grant_type the calling handler implements. The
// per-client authorization gate ([store.Client.GrantTypes]) runs here,
// after the identity is known and before the handler touches any
// credential record, so a client that is not registered for the grant
// cannot consume a code, rotate a refresh chain, or burn a device_code.
// Threading it through this one entry point is deliberate: a new grant
// handler has to name its grant_type to authenticate at all, so the
// gate cannot be forgotten the way a per-handler `if` can.
//
// The function writes the response on every failure path; the caller
// only checks the bool.
func authenticateWithDPoP(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	deps Deps,
	grantType string,
) (*dpopOutcome, *store.Client, bool) {
	var client *store.Client
	checked, ok := dpopGate(deps).Authenticate(ctx, w, r, func() bool {
		var authOK bool
		client, _, authOK = authenticate(ctx, w, r, deps)
		if !authOK {
			return false
		}
		return clientPermitsGrant(w, client, grantType)
	})
	if !ok {
		return nil, nil, false
	}
	return newDPoPOutcome(checked), client, true
}

// clientPermitsGrant enforces [store.Client.GrantTypes]. An empty list
// means the client may not call the token endpoint at all, so the gate
// is a plain membership test with no "unset means everything" arm —
// that reading would make narrowing a compromised client's registration
// a no-op.
//
// The per-client set is an additional restriction on top of the
// provider's enabled grants, never a substitute for it: both gates run.
func clientPermitsGrant(w http.ResponseWriter, client *store.Client, grantType string) bool {
	if client == nil {
		writeError(w, http.StatusBadRequest, errInvalidRequest, "client is required")
		return false
	}
	if slices.Contains(client.GrantTypes, grantType) {
		return true
	}
	writeError(w, http.StatusBadRequest, errUnauthorizedClient,
		"the client is not authorized to use this grant type")
	return false
}

// enforceDPoPRefreshBinding reconciles the post-exchange DPoP state for
// the refresh_token grant. Proof verification (signature, htu/htm, RFC
// 9449 §8 nonce challenge) ran upfront in [authenticateWithDPoP] so the
// use_dpop_nonce 400 fires before any client_assertion jti is consumed;
// this helper only enforces the bound-chain invariants RFC 9449 §5.2
// owes the rotation, which depend on data the exchange surfaces:
//
//   - DPoP feature off + chain bound  → invalid_grant. The OP was
//     reconfigured between issuance and refresh; admitting the
//     request would silently downgrade a sender-constrained chain to
//     bearer.
//   - No proof presented + chain bound → invalid_grant (proof required).
//   - Proof presented + chain bound + jkt mismatch → invalid_grant
//     (key mismatch).
//   - Bearer chain (boundJKT == "") with or without proof → accepted;
//     a presented proof opportunistically binds the rotated tokens.
func enforceDPoPRefreshBinding(w http.ResponseWriter, deps Deps, out *dpopOutcome, boundJKT string) bool {
	if deps.DPoP == nil {
		if boundJKT != "" {
			writeError(w, http.StatusBadRequest, errInvalidGrant,
				"refresh token is DPoP-bound but DPoP is not enabled")
			return false
		}
		return true
	}
	if !out.Presented {
		if boundJKT == "" {
			return true
		}
		writeError(w, http.StatusBadRequest, errInvalidGrant,
			"DPoP proof required for sender-constrained refresh token")
		return false
	}
	if boundJKT != "" && out.JKT != boundJKT {
		writeError(w, http.StatusBadRequest, errInvalidGrant,
			"DPoP proof key does not match the bound thumbprint")
		return false
	}
	return true
}
