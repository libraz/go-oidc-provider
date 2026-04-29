// Package registrationendpoint implements the OAuth 2.0 Dynamic Client
// Registration endpoints defined by RFC 7591 (registration), RFC 7592
// (management), and OpenID Connect Dynamic Client Registration 1.0
// (OIDC profile fields).
//
// A client POSTs candidate metadata to /register either anonymously
// (when [Deps.Open] is true) or under an Initial Access Token bearer.
// The handler validates the metadata against the registered policy
// (allowed grant_types, allowed response_types, IAT-bound scopes, the
// optional [Deps.ValidateMetadata] hook), mints a fresh client_id and
// optional client_secret, allocates a registration_access_token, and
// persists the client through [op/store.ClientRegistry].
//
// The /register/{client_id} sub-routes implement RFC 7592: GET, PUT,
// and DELETE authenticated by the registration_access_token. PUT
// rotates the RAT on every successful update; DELETE revokes the
// client and its RAT.
//
// # Layering
//
// The package is a thin orchestration over four collaborators:
//
//   - [op/store.ClientRegistry] for client persistence;
//   - [op/store.InitialAccessTokenStore] for IAT verification and
//     consumption;
//   - [op/store.RegistrationAccessTokenStore] for RAT rotation and
//     verification;
//   - [internal/timex] (via the package-local Clock) for wall-clock
//     reads.
//
// The handler never touches the wall clock directly; [Deps.Clock] is
// threaded through every state-changing operation so tests can pin
// "now" deterministically.
//
// # Error envelope
//
// Errors are emitted in the RFC 7591 §3.2.2 / RFC 6749 §5.2 shape:
//
//	{"error": "invalid_client_metadata", "error_description": "..."}
//
// Cache-Control: no-store is stamped on every response (success and
// error). 401 responses additionally carry a WWW-Authenticate Bearer
// challenge per RFC 6750 §3 so RP libraries that follow the bearer
// state machine can react automatically.
//
// # Boundary discipline
//
// internal/* MUST NOT import the public op/ package. The
// [ClientMetadata] type declared here mirrors op.ClientMetadata; the
// op layer converts between the two through a thin shim. The
// [Deps.ValidateMetadata] hook receives the internal type; the op
// layer wraps caller-supplied op.ClientMetadata hooks through the
// same shim before threading them in.
package registrationendpoint
