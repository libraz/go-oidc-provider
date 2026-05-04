// Package ciba implements the pure helpers the OpenID Connect CIBA
// Core 1.0 backchannel-authentication grant relies on: request
// validation (login_hint XOR id_token_hint XOR login_hint_token,
// scope must contain `openid`, binding_message length capped at 50
// runes, requested_expiry parsing and clamping), the poll-mode
// polling discipline (slow_down doubling ladder plus a poll-abuse
// strike counter that locks the record to access_denied once the cap
// is reached), and the audit event names the OP emits across the
// CIBA flow.
//
// The package owns no I/O surface and no HTTP handler: the endpoint
// handler at [github.com/libraz/go-oidc-provider/internal/cibaendpoint]
// composes these helpers with the substore at
// [github.com/libraz/go-oidc-provider/op/store.CIBARequestStore], and
// the token-endpoint grant at
// [github.com/libraz/go-oidc-provider/internal/grants/ciba] reuses the
// polling discipline at /token poll time.
//
// The package targets the design contract documented for the v0.x
// CIBA wave: poll mode only (push and ping notification modes are
// deferred to a later milestone), 256-bit auth_req_id values minted
// at the endpoint layer, default record expiry of 600 s, default
// poll interval of 5 s, and a hard cap of 5 poll violations before
// the record is locked to access_denied.
package ciba
