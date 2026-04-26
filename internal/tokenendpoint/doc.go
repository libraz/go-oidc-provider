// Package tokenendpoint implements the OAuth 2.0 / OpenID Connect token
// endpoint (RFC 6749 §3.2, OpenID Connect Core 1.0 §3.1.3.3).
//
// The handler returned by [Handler] dispatches on the "grant_type" form
// parameter and supports the two grant types this library exposes in v1.0:
//
//   - authorization_code (RFC 6749 §4.1.3, OIDC Core §3.1.3.3) — PKCE is
//     mandatory per the product design's §A.12.3, so the handler rejects
//     any code exchange that arrives without a code_verifier.
//
//   - refresh_token (RFC 6749 §6) — every successful exchange rotates the
//     presented token (RFC 9700 §2.2.2). The id_token is re-issued only
//     when the originating grant carried the "openid" scope.
//
// All other grant types (client_credentials, urn:ietf:params:oauth:grant-
// type:device_code, etc.) surface "unsupported_grant_type" with HTTP 400.
//
// # Layering
//
// The handler is a thin orchestration over four collaborators:
//
//   - [internal/authn] for client authentication;
//   - [internal/grants/authcode] and [internal/grants/refresh] for the
//     state transitions;
//   - [internal/tokens] for JWS minting (id_token + access_token);
//   - [op/store] substores for persistence.
//
// The handler never reads the wall clock directly; the [Deps.Clock] field
// is threaded through to the grant exchangers and the token signer so
// tests can pin "now" deterministically.
//
// # Error envelope
//
// Errors are emitted in the RFC 6749 §5.2 shape:
//
//	{"error": "invalid_grant", "error_description": "..."}
//
// Cache-Control: no-store and Pragma: no-cache headers are stamped on
// every response (success + error) per RFC 6749 §5.1. The handler maps
// the sentinel errors exposed by the grant packages onto wire codes
// without leaking which sub-case triggered the rejection.
package tokenendpoint
