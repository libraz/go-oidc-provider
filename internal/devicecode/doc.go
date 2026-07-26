// Package devicecode implements the pure helpers the RFC 8628 device-
// authorization grant relies on: user_code generation and normalisation
// (Crockford Base32 with the visually-ambiguous alphabet collapsed),
// slow_down polling discipline (RFC 8628 §3.5 doubling rule), and the
// audit event names the OP emits across the device flow.
//
// The package owns no I/O surface and no HTTP handler: the endpoint
// handler at [github.com/libraz/go-oidc-provider/internal/devicecodeendpoint]
// composes these helpers with the substore at
// [github.com/libraz/go-oidc-provider/op/store.DeviceCodeStore], and the
// token-endpoint grant at
// [github.com/libraz/go-oidc-provider/internal/grants/devicecode] reuses
// the polling discipline at /token poll time.
//
// The package targets the design contract (user_code), §Q3 (polling),
// §Q5 (sender-constraint) and §S.1 (brute- force gate).
package devicecode
