package tokenendpoint

import (
	"errors"
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
	return &dpopOutcome{JKT: res.JKT, Presented: true}, true
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
	return &dpopOutcome{JKT: res.JKT, Presented: true}, true
}

// writeDPoPError translates a [dpop.Err*] sentinel onto the wire form.
// RFC 9449 §7 prescribes "invalid_dpop_proof" but we re-use the OAuth
// "invalid_request" / "invalid_grant" envelope already shared by the
// rest of the token endpoint so RP libraries that key off the OAuth
// codes do not need to learn a new code class. The description echoes
// the closest RFC 9449 wording; the wrapped sentinel cause is dropped
// to avoid leaking timing-side-channel signal.
//
// The nonce sentinels ([dpop.ErrProofNonceMissing] /
// [dpop.ErrProofNonceInvalid]) take a separate code: §8 defines
// "use_dpop_nonce" specifically so the client knows to retry with the
// fresh value carried in the companion "DPoP-Nonce" response header.
func writeDPoPError(w http.ResponseWriter, deps Deps, err error) {
	if dpop.IsNonceError(err) {
		writeUseDPoPNonce(w, deps)
		return
	}
	switch {
	case errors.Is(err, dpop.ErrProofMalformed),
		errors.Is(err, dpop.ErrProofMissingJTI):
		writeError(w, http.StatusBadRequest, errInvalidRequest, "DPoP proof malformed")
	case errors.Is(err, dpop.ErrProofSignature):
		writeError(w, http.StatusBadRequest, errInvalidRequest, "DPoP proof signature invalid")
	case errors.Is(err, dpop.ErrProofIatWindow):
		writeError(w, http.StatusBadRequest, errInvalidRequest, "DPoP proof iat outside acceptable window")
	case errors.Is(err, dpop.ErrProofReplayed):
		writeError(w, http.StatusBadRequest, errInvalidRequest, "DPoP proof replayed")
	case errors.Is(err, dpop.ErrProofHTMMismatch),
		errors.Is(err, dpop.ErrProofHTUMismatch):
		writeError(w, http.StatusBadRequest, errInvalidRequest, "DPoP proof does not bind to this request")
	case errors.Is(err, dpop.ErrProofATHMismatch):
		writeError(w, http.StatusBadRequest, errInvalidRequest, "DPoP proof does not bind to the access token")
	default:
		writeError(w, http.StatusInternalServerError, errServerError, "")
	}
}

// writeUseDPoPNonce emits the RFC 9449 §8 nonce challenge: a 400
// JSON envelope with error="use_dpop_nonce" plus a "DPoP-Nonce"
// response header carrying a fresh value the client should embed in
// the next proof's "nonce" claim. A nil [Deps.DPoPNonces] omits the
// header (the issuer is offline) but still emits the JSON body so a
// debugger can see the gate fired; the client then has no nonce to
// retry with, which is the most truthful signal the server can give
// in that misconfiguration.
func writeUseDPoPNonce(w http.ResponseWriter, deps Deps) {
	if deps.DPoPNonces != nil {
		if nonce := deps.DPoPNonces.IssueNonce(); nonce != "" {
			w.Header().Set("DPoP-Nonce", nonce)
		}
	}
	writeError(w, http.StatusBadRequest, errUseDPoPNonce,
		"DPoP proof requires a server-supplied nonce; retry using the value in the DPoP-Nonce response header")
}
