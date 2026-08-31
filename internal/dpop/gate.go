package dpop

import (
	"context"
	"net/http"
)

// Gate bundles the two dependencies an HTTP endpoint needs to run the
// RFC 9449 proof lifecycle over an inbound request — the verifier that
// owns the stateless gates and the replay store, and the nonce issuer
// consulted by the §8 challenge — and exposes that lifecycle as one
// call.
//
// Every endpoint that accepts a proof (/token, /par,
// /device_authorization, /bc-authorize) drives the lifecycle through
// this type rather than re-implementing it, so a change to any phase
// (the presence test, the phase ordering, the replay commit, the error
// envelope) reaches all of them from a single edit, and an endpoint
// added later inherits the current behaviour instead of a copy of it.
//
// The zero value is a working gate with DPoP disabled: a nil
// [Gate.Verifier] admits every request without a proof, which is the
// bearer-token path.
type Gate struct {
	// Verifier runs the RFC 9449 §4.3 checks and owns the replay
	// store. Nil disables DPoP verification entirely.
	Verifier *Verifier

	// Nonces supplies the value stamped on the RFC 9449 §8
	// `use_dpop_nonce` challenge. Nil omits the DPoP-Nonce response
	// header; see [WriteError].
	Nonces NonceIssuer
}

// Authenticate runs proof verification, the caller's client
// authentication, and the proof's replay commit in the one order that
// satisfies the constraints both mechanisms impose, and returns the
// accepted proof (nil when none was presented).
//
// Proof verification runs FIRST so the RFC 9449 §8 `use_dpop_nonce`
// challenge fires before any client_assertion jti is consumed: §8
// contemplates a verbatim retry of the request body with only the proof
// refreshed, and RP libraries rebuild only the DPoP header, reusing the
// original client_assertion. Marking the assertion's jti on the first
// attempt would surface on the retry as invalid_client. Nothing in the
// verification depends on the resolved client identity — the proof is
// bound to the request and to its own key, never to the client's
// credential.
//
// The proof's replay marker is written LAST, after authentication
// succeeds. That write is the only durable storage effect on this path,
// and leaving it ahead of authentication would let an unauthenticated
// request rate translate directly into storage cost. Deferring it
// weakens nothing: the marker still lands before the endpoint acts on
// the request, and a proof replayed on a request that cannot
// authenticate is refused on the credential instead.
//
// authenticate reports whether the request may proceed and MUST have
// written its own response when it returns false; endpoints that gate
// on more than the credential (e.g. the token endpoint's per-client
// grant check) fold those checks into the same callback so they too
// run between the two proof phases. The gate writes the response on
// every DPoP failure path, so the caller only checks the bool.
func (g Gate) Authenticate(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	authenticate func() bool,
) (*Checked, bool) {
	checked, ok := g.Check(ctx, w, r)
	if !ok {
		return nil, false
	}
	if !authenticate() {
		return nil, false
	}
	if !g.Commit(ctx, w, checked) {
		return nil, false
	}
	return checked, true
}

// Check runs the stateless RFC 9449 §4.3 gates over the optional DPoP
// header and returns the accepted proof when one was presented. A nil
// [Gate.Verifier] or a request without a proof yields (nil, true) — the
// caller proceeds on the bearer path. On rejection the function writes
// the wire envelope and returns (nil, false).
//
// The proof is not single-use until [Gate.Commit] has run; see
// [Gate.Authenticate] for why the two phases are kept apart.
func (g Gate) Check(ctx context.Context, w http.ResponseWriter, r *http.Request) (*Checked, bool) {
	if g.Verifier == nil || !HasProof(r) {
		return nil, true
	}
	checked, err := g.Verifier.CheckHTTPRequest(ctx, r, "")
	if err != nil {
		g.WriteError(ctx, w, err)
		return nil, false
	}
	return checked, true
}

// Commit writes the replay marker for the proof [Gate.Check] accepted,
// making it single-use. It is a no-op when no proof was presented. The
// function emits the response and returns false on failure; a repeated
// or concurrent use of the same proof surfaces through the same
// [WriteError] mapping the single-phase verifier produces.
func (g Gate) Commit(ctx context.Context, w http.ResponseWriter, checked *Checked) bool {
	if checked == nil {
		return true
	}
	if err := g.Verifier.Commit(ctx, checked); err != nil {
		g.WriteError(ctx, w, err)
		return false
	}
	return true
}

// WriteError translates an [Err*] sentinel onto the wire form using the
// gate's nonce issuer. It is the boundary mapping every proof-accepting
// endpoint shares; see the godoc on [WriteError] for the wire taxonomy,
// including the RFC 9449 §8 nonce challenge.
func (g Gate) WriteError(ctx context.Context, w http.ResponseWriter, err error) {
	WriteError(ctx, w, err, NonceSourceFromIssuer(g.Nonces))
}

// HasProof reports whether r carries a DPoP proof header at all. It is
// the presence test every HTTP entrance to the package MUST use, and it
// is deliberately value-count based rather than value-content based:
// RFC 9449 §4.1 allows exactly one proof per request, and rejecting the
// multi-value case belongs to the verifier ([Verifier.CheckHTTPRequest]
// maps it onto [ErrProofMalformed]). Reading only the first value would
// let a request whose first "DPoP" header is empty and whose second
// carries a real proof read as "no proof presented" and silently fall
// through to the unbound bearer path.
func HasProof(r *http.Request) bool {
	if r == nil {
		return false
	}
	return len(r.Header.Values("DPoP")) > 0
}
