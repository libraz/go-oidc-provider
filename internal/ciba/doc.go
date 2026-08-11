// Package ciba implements the pure helpers the OpenID Connect CIBA
// Core 1.0 backchannel-authentication grant relies on: request
// validation (login_hint XOR id_token_hint XOR login_hint_token,
// scope must contain `openid`, binding_message length capped at 50
// runes, requested_expiry parsing and clamping), the poll-mode
// polling discipline (the slow_down back-off ladder plus a poll-abuse
// strike counter that locks the record to access_denied once the cap
// is reached), and the audit event names the OP emits across the
// CIBA flow.
//
// The package owns no I/O surface and no HTTP handler: the endpoint
// handler at internal/cibaendpoint
// composes these helpers with the substore at
// [github.com/libraz/go-oidc-provider/op/store.CIBARequestStore], and
// the token-endpoint grant at
// internal/grants/ciba reuses the
// polling discipline at /token poll time.
//
// The package implements poll mode only; the push and ping
// notification modes are not supported, so the OP does not advertise
// them in discovery. auth_req_id values are 256-bit and minted at the
// endpoint layer, records expire after 600 s by default, the default
// poll interval is 5 s, and a record locks to access_denied after 5
// poll violations.
package ciba
