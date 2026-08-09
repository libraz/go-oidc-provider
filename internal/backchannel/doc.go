// Package backchannel implements OpenID Connect Back-Channel Logout
// 1.0 (https://openid.net/specs/openid-connect-backchannel-1_0.html).
//
// The OP sends a signed Logout Token to every relying party that
// registered a backchannel_logout_uri when the end-user's session
// terminates. The token is a JWS-signed JWT (typ "logout+jwt") that
// names the audience client and identifies the session by `sub`; the
// RP is expected to terminate any local session matching the claim.
// The coordinator does not emit `sid` until the grant model can retain
// and recover an RP-specific session lineage.
//
// Package layout:
//
//   - [LogoutClaims] / [SignLogoutToken] mint the token. Signing
//     reuses the OP's existing ES256 signing key; no new key material
//     is introduced.
//   - [Deliverer] is the HTTP transport seam. The default
//     [HTTPDeliverer] honours a per-RP timeout and refuses to follow
//     redirects (the spec mandates a direct POST to the registered
//     URI).
//   - [Coordinator] is the orchestrator: given an active session and
//     the OP's grant + client stores, it enumerates the audience
//     clients, mints a logout token per client, dispatches in
//     parallel, and emits audit records.
//
// The package is best-effort by design: a failed delivery does not
// roll back the OP-side session termination. The 1.0 spec does not
// require synchronous delivery, and the embedder can plug in a queue-
// backed [Deliverer] later when retry semantics are desired.
// For v1.0 the OP makes one synchronous attempt per
// RP and surfaces success / failure through audit events
// (`logout.back_channel.delivered`, `logout.back_channel.failed`).
package backchannel
