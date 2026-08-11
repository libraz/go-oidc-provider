// Package devicecode implements the pure helpers the RFC 8628 device-
// authorization grant relies on: user_code generation and normalisation
// (Crockford Base32 with the visually-ambiguous alphabet collapsed),
// slow_down polling discipline (the RFC 8628 §3.5 back-off ladder), and the
// audit event names the OP emits across the device flow.
//
// The package owns no I/O surface and no HTTP handler: the endpoint
// handler at internal/devicecodeendpoint
// composes these helpers with the substore at
// [github.com/libraz/go-oidc-provider/op/store.DeviceCodeStore], and the
// token-endpoint grant at
// internal/grants/devicecode reuses
// the polling discipline at /token poll time.
//
// The package covers user_code generation and normalisation, the
// polling discipline (authorization_pending / slow_down back-off),
// sender-constrained token issuance, and the brute-force gate on
// user_code entry.
package devicecode
