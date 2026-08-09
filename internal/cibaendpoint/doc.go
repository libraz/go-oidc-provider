// Package cibaendpoint implements the HTTP handler for the
// /bc-authorize endpoint defined by OpenID Connect Client-Initiated
// Backchannel Authentication (CIBA) Core 1.0 §7. The handler
// authenticates the requesting client, classifies the inbound hint,
// resolves it to a stable subject via the embedder's
// [HintResolver], validates the requested scope and resource
// indicators, optionally records the DPoP / mTLS thumbprint the
// client committed to, mints an auth_req_id, persists the resulting
// record via [github.com/libraz/go-oidc-provider/op/store.CIBARequestStore],
// and returns the §7.3 JSON response.
//
// The package is the issuance side of the CIBA flow. The
// authentication-device interaction (Approve / Deny callbacks into
// the substore) is owned by the embedder; the token-endpoint poll
// side is implemented in
// [github.com/libraz/go-oidc-provider/internal/grants/ciba] alongside
// [github.com/libraz/go-oidc-provider/internal/ciba]'s pure
// validation and polling helpers.
//
// Posture choices the handler encodes:
//
//   - Sender-constraint binding is committed at issuance, not at
//     poll. When the request carries a DPoP proof or arrives over
//     mTLS, the thumbprint is stamped on the persisted record so
//     the eventual access token's cnf claim follows the
//     legitimate consuming-device's credential. The token endpoint
//     refuses to mint an unbound token from a bound record,
//     closing the "consuming device commits, attacker polls"
//     downgrade.
//
//   - FAPI 2.0 baseline / FAPI-CIBA reject unbound requests up
//     front. A deployment otherwise locked to sender-constrained
//     tokens could mint bearer tokens via CIBA poll mode if the
//     issuance side accepted unbound /bc-authorize requests; the
//     handler refuses such requests with invalid_request before a
//     record is persisted.
//
//   - RFC 8707 resource indicators are normalised at issuance.
//     The persisted record carries the canonical (lowercase
//     scheme + host, trailing-slash stripped) form so the token
//     endpoint compares audience claims byte-for-byte.
//
//   - id_token_hint is verified inside the OP, never by the
//     resolver. CIBA Core 1.0 §7.1 puts the check on the OP, and
//     for good reason: a resolver that reads sub straight out of
//     the payload would let any CIBA-registered client address the
//     ceremony to any subject. The handler verifies the signature
//     against the OP keyset, requires iss to be this issuer, and
//     requires the audience to identify the client that
//     authenticated on the same request; only the verified sub is
//     passed to [HintResolver].
//
//   - Expired id_tokens are accepted as hints. This is deliberate.
//     The consumption device in a CIBA flow — a POS terminal, a
//     call-centre console — holds an ID Token from a session that
//     has usually long since ended, and ID Tokens are short-lived,
//     so enforcing exp would reject nearly every genuine hint and
//     break the primary use case. Freshness adds nothing to the
//     security argument either: the requesting client authenticated
//     at the endpoint, and signature plus audience binding are what
//     identify it and prevent cross-OP and cross-client forgery.
//     [github.com/libraz/go-oidc-provider/internal/endsession]
//     documents the same choice, for the same reason, on
//     RP-Initiated Logout's id_token_hint.
//
//   - id_token_hint from a pairwise client is refused. A client
//     registered with subject_type=pairwise receives per-sector
//     pseudonyms (OIDC Core 1.0 §8.1) and the OP keeps no reverse
//     index for them, so the sub inside such a hint is not a value
//     any resolver can look up. The handler rejects the request
//     with invalid_request and names login_hint / login_hint_token
//     as the supported alternatives, rather than passing a
//     pseudonym along and letting the failure surface later as an
//     unexplained unknown_user_id.
package cibaendpoint
