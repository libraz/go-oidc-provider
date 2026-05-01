//go:build example

// Package seedkit bundles two demo-only helpers the example/* main.go
// files share when they need to walk a TOTP enrolment before serve:
//
//   - [QRTerm] renders an otpauth:// URI as a terminal-friendly Unicode
//     QR code so the operator can scan it with a phone authenticator
//     app without any external tooling.
//   - [Seed] materialises a complete demo user (subject, password
//     hash, optional confirmed TOTP record) inside an inmem.Store and
//     returns the otpauth URI / base32 / pre-rendered QR for the
//     caller to print.
//
// # Status
//
// seedkit is build-tag gated (`//go:build example`) and lives in its
// own sub-module so the QR rendering dependency (rsc.io/qr) stays out
// of the host module's go.sum. It is NOT a public API. Production
// embedders that ship a real TOTP enrolment screen drive [op/totpkit]
// directly through their own controller — render the QR in HTML, walk
// the user-confirms-the-code round-trip, and persist the resulting
// [store.TOTPRecord] under their own transaction. The seedkit fast-
// path skips the user-confirms step (it stamps ConfirmedAt and
// LastAcceptedStep at seed time) which is acceptable for a CLI demo
// but unsuitable for a real account.
//
// # Why a separate sub-module
//
// The host module deliberately does not depend on a QR rendering
// library: the OP itself returns the otpauth URI and leaves rendering
// to the embedder. Examples that want to print a QR to the terminal
// import seedkit, which carries the rsc.io/qr dependency in its own
// go.sum. Operators inspecting the host module's dependency graph
// see only the OIDC stack, not example-only tooling.
package seedkit
