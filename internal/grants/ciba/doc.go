// Package ciba implements the authorization layer of the
// urn:openid:params:grant-type:ciba grant from OpenID Connect
// Client-Initiated Backchannel Authentication Flow Core 1.0. The
// grant covers decoupled-device flows where the consuming device
// (kiosk, call-centre operator, retail point of sale) cannot host
// the user's authentication ceremony itself: the device requests an
// auth_req_id at /bc-authorize, the OP delegates the authentication
// ceremony to the user's authentication device (typically a phone),
// and the consuming device polls /token with the auth_req_id until
// the user approves on the auth device.
//
// The package is deliberately a policy-only authorizer: callers
// (the token endpoint) hand it the already-authenticated
// [op/store.Client], the resolved [op/store.CIBARequest] record
// (post-Approve), and the polling-channel cnf binding. The package
// validates the grant-type allowance, the cnf binding (DPoP / mTLS)
// the consuming device committed to at /bc-authorize, and the scope
// subset relationship; it returns the granted scope set alongside
// any typed sentinel the HTTP layer maps to an OAuth wire code.
// Token minting, refresh-token issuance, id_token shaping, and
// persistence stay where they already live in
// internal/tokenendpoint / internal/tokens /
// internal/grants/refresh so the decision logic on this grant can
// be inspected and tested in isolation.
//
// Posture choices the package encodes:
//
//   - cnf binding follows the consuming device. The access token's
//     cnf.jkt / cnf.x5t#S256 is rebound from the device's
//     /bc-authorize presentation, not from a polling-channel
//     downgrade. CIBA Core §11 explicitly treats the auth_req_id as
//     the polling-channel bearer; the issued token's binding remains
//     tied to the cryptographic credential the legitimate device
//     proved possession of when the flow began.
//
//   - No silent bearer downgrade. When the active profile set
//     requires sender-constrained tokens (FAPI 2.0 baseline / FAPI-
//     CIBA), the /bc-authorize handler refuses to mint an
//     auth_req_id whose eventual access token would be bearer; the
//     rejection surfaces as invalid_request before any record is
//     persisted.
//
//   - Poll mode only. v0.9.1 implements only the poll delivery
//     mode. Push and ping delivery modes are deferred; the grant's
//     token-endpoint contract assumes the consuming device discovers
//     state via repeated /token polls subject to the slow_down
//     ladder.
package ciba
