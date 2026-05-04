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
package cibaendpoint
