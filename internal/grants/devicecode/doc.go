// Package devicecode implements the authorization layer of the
// urn:ietf:params:oauth:grant-type:device_code grant from RFC 8628.
// The grant covers input-constrained or browserless devices (smart
// TVs, IoT appliances, terminal CLIs) that cannot run a full web
// authentication ceremony: the device requests a device_code at
// /device_authorization, displays a user-readable user_code with a
// verification_uri, and polls /token with the device_code until
// the user completes the verification ceremony on a secondary
// device.
//
// The package is deliberately a policy-only authorizer: callers
// (the token endpoint) hand it the already-authenticated
// [op/store.Client], the resolved [op/store.DeviceCode] record
// (post-Approve), and the requested scope set. The package
// validates the grant-type allowance, the cnf binding (DPoP /
// mTLS) the device committed to at /device_authorization, and the
// scope subset relationship; it returns the granted scope set
// alongside any typed sentinel the HTTP layer maps to an OAuth
// wire code. Token minting, refresh-token issuance, id_token
// shaping, and persistence stay where they already live in
// internal/tokenendpoint / internal/tokens /
// internal/grants/refresh so the decision logic on this grant
// can be inspected and tested in isolation.
//
// Posture choices the package encodes:
//
//   - cnf binding follows the device. The access token's
//     cnf.jkt / cnf.x5t#S256 is rebound from the device's
//     /device_authorization presentation, not from the polling
//     channel. RFC 8628 §3.5 explicitly accepts the device_code
//     as the polling-channel bearer; the issued token's binding
//     remains tied to the cryptographic credential the legitimate
//     device proved possession of when the flow began.
//
//   - No silent bearer downgrade. When the active profile set
//     requires sender-constrained tokens (FAPI 2.0 baseline), the
//     /device_authorization handler refuses to mint a device_code
//     whose eventual access token would be bearer; the rejection
//     surfaces as invalid_request before any record is persisted.
//
//   - Refresh-token issuance is opt-in per client. The grant
//     mints a refresh_token only when the granted scope contains
//     "openid" AND the client lists "refresh_token" in
//     [op/store.Client.GrantTypes], mirroring the authorization-
//     code path. Device flows are typically long-lived; embedders
//     opt in deliberately.
package devicecode
