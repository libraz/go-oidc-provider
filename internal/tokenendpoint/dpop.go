package tokenendpoint

import (
	"context"
	"net/http"

	"github.com/libraz/go-oidc-provider/internal/dpop"
	"github.com/libraz/go-oidc-provider/op/store"
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

	// JTI is the proof's "jti" claim, exposed so downstream consumers
	// (e.g. custom-grant dispatch) can include the value in audit
	// emission without re-parsing the proof.
	JTI string

	// Presented reports whether the request carried a DPoP header at
	// all. Useful for refresh-token enforcement: a chain bound to a
	// jkt requires a proof to be presented even if the verifier is
	// configured to issue bearer tokens by default.
	Presented bool

	// checked is the accepted-but-uncommitted proof whose replay
	// marker [commitTokenDPoP] writes. Nil when no proof was
	// presented or when DPoP is not enabled.
	checked *dpop.Checked
}

// authenticateWithDPoP runs DPoP proof verification and client
// authentication in the one order that satisfies both of the
// constraints the two mechanisms impose, and is the entry point every
// grant handler uses.
//
// Proof verification runs FIRST because RFC 9449 §8 contemplates a
// verbatim retry of the client-side request body with only the proof
// refreshed: RP libraries rebuild the DPoP header and resend the
// original client_assertion, so a `use_dpop_nonce` challenge raised
// after the assertion's jti had been consumed would surface on the
// retry as invalid_client. The proof is bound to the request, never to
// the client's credential, so nothing in the verification depends on
// the resolved identity.
//
// The proof's own replay marker is written LAST, after authentication
// succeeds. That write is the only durable storage effect on this path,
// and leaving it ahead of authentication would let an unauthenticated
// request rate translate directly into storage cost. Deferring it
// weakens nothing: a replayed proof on a request that cannot
// authenticate is refused on the credential, and any request that
// reaches the commit is refused with the same ErrProofReplayed it
// would have seen under the single-phase verifier.
//
// The function writes the response on every failure path; the caller
// only checks the bool.
func authenticateWithDPoP(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	deps Deps,
) (*dpopOutcome, *store.Client, bool) {
	out, ok := verifyTokenDPoP(w, r, deps)
	if !ok {
		return nil, nil, false
	}
	client, _, ok := authenticate(ctx, w, r, deps)
	if !ok {
		return nil, nil, false
	}
	if !commitTokenDPoP(ctx, w, deps, out) {
		return nil, nil, false
	}
	return out, client, true
}

// verifyTokenDPoP runs the stateless DPoP gates over the inbound
// request when the feature is wired and a proof header is present. The
// function emits an HTTP error and returns (nil, false) on every
// failure path so the caller only checks the bool. When DPoP is not
// enabled or no proof is presented the function returns
// (&dpopOutcome{}, true) — the caller proceeds with bearer-token
// issuance.
//
// The proof is not yet single-use when this returns; see
// [commitTokenDPoP].
func verifyTokenDPoP(w http.ResponseWriter, r *http.Request, deps Deps) (*dpopOutcome, bool) {
	if deps.DPoP == nil {
		return &dpopOutcome{}, true
	}
	header := r.Header.Get("DPoP")
	if header == "" {
		return &dpopOutcome{}, true
	}
	checked, err := deps.DPoP.CheckHTTPRequest(r.Context(), r, "")
	if err != nil {
		writeDPoPError(w, deps, err)
		return nil, false
	}
	return &dpopOutcome{JKT: checked.JKT, JTI: checked.JTI, Presented: true, checked: checked}, true
}

// commitTokenDPoP writes the replay marker for the proof
// [verifyTokenDPoP] accepted, making it single-use. It is a no-op when
// no proof was presented. The function emits the response and returns
// false on failure; a repeated or concurrent use of the same proof
// surfaces through the same [dpop.WriteError] mapping the single-phase
// verifier produced.
func commitTokenDPoP(ctx context.Context, w http.ResponseWriter, deps Deps, out *dpopOutcome) bool {
	if out == nil || out.checked == nil {
		return true
	}
	if err := deps.DPoP.Commit(ctx, out.checked); err != nil {
		writeDPoPError(w, deps, err)
		return false
	}
	return true
}

// enforceDPoPRefreshBinding reconciles the post-exchange DPoP state for
// the refresh_token grant. Proof verification (signature, htu/htm, RFC
// 9449 §8 nonce challenge) ran upfront in [verifyTokenDPoP] so the
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
