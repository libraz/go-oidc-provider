// Package devicecodeendpoint implements the HTTP handler for the
// /oidc/device_authorization endpoint defined by RFC 8628 §3.1. The
// handler authenticates the requesting device's client credentials,
// validates the requested scope and resource indicators, optionally
// records the DPoP / mTLS thumbprint the device committed to, mints
// a device_code and user_code, persists the resulting record via
// [github.com/libraz/go-oidc-provider/op/store.DeviceCodeStore], and
// returns the §3.2 JSON response.
//
// The package is the issuance side of the device flow. The
// verification ceremony (the user-facing /device page) is owned by
// the embedder via [op.interaction.Driver]; the token-endpoint
// poll side is implemented in
// internal/grants/devicecode
// alongside internal/devicecode's
// pure helpers.
//
// Posture choices the handler encodes:
//
//   - Sender-constraint binding is committed at issuance, not at
//     poll. When the request carries a DPoP proof or arrives over
//     mTLS, the thumbprint is stamped on the persisted record so
//     the eventual access token's cnf claim follows the
//     legitimate device's credential. The token endpoint refuses
//     to mint an unbound token from a bound record, closing the
//     "device commits, attacker polls" downgrade.
//
//   - FAPI 2.0 baseline rejects unbound requests up front. A
//     deployment otherwise locked to sender-constrained tokens
//     could mint bearer tokens via device flow if the issuance
//     side accepted unbound device-authorization requests; the
//     handler refuses such requests with invalid_request before
//     a record is persisted.
//
//   - RFC 8707 resource indicators are normalised at issuance.
//     The persisted record carries the canonical (lowercase
//     scheme + host, trailing-slash stripped) form so the token
//     endpoint compares audience claims byte-for-byte.
package devicecodeendpoint
