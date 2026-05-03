package tokenendpoint

import (
	"context"
	"net/http"

	"github.com/libraz/go-oidc-provider/internal/dpop"
)

// dpopOutcome is the result of [verifyTokenDPoP]: a (possibly empty)
// thumbprint plus a flag reporting whether a proof was actually
// presented. The split lets handler code distinguish "no proof, issue
// bearer token" from "proof verified, bind to jkt" without inspecting
// the Verifier directly.
type dpopOutcome struct {
	// JKT is the RFC 7638 thumbprint extracted from the proof. Empty
	// when no proof was presented.
	JKT string

	// JTI is the proof's "jti" claim. Already marked consumed by the
	// time the caller observes the value; exposed so downstream
	// consumers (e.g. custom-grant dispatch) can include the value in
	// audit emission without re-parsing the proof.
	JTI string

	// Presented reports whether the request carried a DPoP header at
	// all. Useful for refresh-token enforcement: a chain bound to a
	// jkt requires a proof to be presented even if the verifier is
	// configured to issue bearer tokens by default.
	Presented bool
}

// verifyTokenDPoP runs the DPoP verifier over the inbound request when
// the feature is wired and a proof header is present. The function
// emits an HTTP error and returns (nil, false) on every failure path so
// the caller only checks the bool. When DPoP is not enabled or no
// proof is presented the function returns (&dpopOutcome{}, true) — the
// caller proceeds with bearer-token issuance.
func verifyTokenDPoP(w http.ResponseWriter, r *http.Request, deps Deps) (*dpopOutcome, bool) {
	if deps.DPoP == nil {
		return &dpopOutcome{}, true
	}
	header := r.Header.Get("DPoP")
	if header == "" {
		return &dpopOutcome{}, true
	}
	res, err := deps.DPoP.VerifyHTTPRequest(r.Context(), r, "")
	if err != nil {
		writeDPoPError(w, deps, err)
		return nil, false
	}
	return &dpopOutcome{JKT: res.JKT, JTI: res.JTI, Presented: true}, true
}

// requireDPoPMatch is the refresh-time variant of [verifyTokenDPoP].
// When boundJKT is non-empty (the consumed refresh token was DPoP-
// bound) the function REQUIRES a proof header AND verifies its
// thumbprint matches. When boundJKT is empty (bearer chain) the
// function accepts an absent proof; if a proof IS presented it is
// still verified and the resulting jkt is propagated so the rotated
// access token can be bound to the same key (RFC 9449 §5.2).
func requireDPoPMatch(w http.ResponseWriter, r *http.Request, deps Deps, boundJKT string) (*dpopOutcome, bool) {
	if deps.DPoP == nil {
		// DPoP feature off but the chain claims a binding: the OP was
		// reconfigured between issuance and refresh. The library's
		// posture is "fail closed" — admitting the request would
		// silently downgrade a sender-constrained chain to bearer.
		if boundJKT != "" {
			writeError(w, http.StatusBadRequest, errInvalidGrant,
				"refresh token is DPoP-bound but DPoP is not enabled")
			return nil, false
		}
		return &dpopOutcome{}, true
	}
	header := r.Header.Get("DPoP")
	if header == "" {
		if boundJKT == "" {
			return &dpopOutcome{}, true
		}
		writeError(w, http.StatusBadRequest, errInvalidGrant,
			"DPoP proof required for sender-constrained refresh token")
		return nil, false
	}
	res, err := deps.DPoP.VerifyHTTPRequest(r.Context(), r, "")
	if err != nil {
		writeDPoPError(w, deps, err)
		return nil, false
	}
	if boundJKT != "" && res.JKT != boundJKT {
		writeError(w, http.StatusBadRequest, errInvalidGrant,
			"DPoP proof key does not match the bound thumbprint")
		return nil, false
	}
	return &dpopOutcome{JKT: res.JKT, JTI: res.JTI, Presented: true}, true
}

// writeDPoPError translates a [dpop.Err*] sentinel onto the wire form.
// The package-local helper is a thin wrapper over [dpop.WriteError]
// so the token / PAR / future endpoints share an identical
// boundary mapping; see the godoc on [dpop.WriteError] for the wire
// taxonomy and on the nonce-challenge response specifically.
//
// The wrapper takes a [Deps] (rather than the broader [dpop.NonceSource]
// directly) so call sites stay symmetric with the rest of the
// package's helpers; the [dpop.NonceSourceFromIssuer] adapter
// transports the wire shape of [Deps.DPoPNonces] into the shared
// helper without leaking dpop-package details upward. The
// [context.Background] argument is acceptable because the nonce
// adapter ignores the context (the issuer is a synchronous
// in-memory call); when a request-scoped context is required (e.g.
// for tracing) the call site can be migrated to
// [dpop.WriteError] directly.
func writeDPoPError(w http.ResponseWriter, deps Deps, err error) {
	dpop.WriteError(context.Background(), w, err, dpop.NonceSourceFromIssuer(deps.DPoPNonces))
}
