// Package parendpoint implements the OAuth 2.0 Pushed Authorization Requests
// endpoint defined by RFC 9126.
//
// A confidential or public client POSTs the authorization-request parameters
// to /par, authenticating with the same machinery the token endpoint uses.
// The handler validates the parameters against the registered client, persists
// the request as a one-time record keyed by an opaque request_uri, and
// responds with that URI plus its lifetime. The browser-driven /authorize
// step then references the URI instead of carrying the parameters in the
// query string.
//
// # Layering
//
// The package is a thin orchestration over four collaborators:
//
//   - [internal/authn] for client authentication (RFC 9126 §2.1 mandates
//     it, even for public clients);
//   - [internal/authorize] for parsing and validating the request (the
//     same checks /authorize runs);
//   - [op/store.PushedAuthRequestStore] for persistence;
//   - [internal/timex] (via the package-local Clock) for wall-clock reads.
//
// The handler never touches the wall clock directly; [Deps.Clock] is threaded
// through every state-changing operation so tests can pin "now"
// deterministically.
//
// # Error envelope
//
// Errors are emitted in the RFC 6749 §5.2 shape:
//
//	{"error": "invalid_request", "error_description": "..."}
//
// Cache-Control: no-store is stamped on every response (success + error). The
// handler maps the sentinels exposed by [internal/authn] and
// [internal/authorize] onto the wire codes without leaking which sub-case
// triggered the rejection.
//
// # Single-use semantics
//
// The endpoint is not idempotent: the same body posted twice produces two
// distinct request_uri values. The /authorize side consumes the URI through
// [op/store.PushedAuthRequestStore.Consume] which returns
// [op/store.ErrAlreadyConsumed] on replay; the library translates that into
// invalid_request_uri.
package parendpoint
