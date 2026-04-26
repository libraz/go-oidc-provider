// Package authorizeendpoint hosts the HTTP handler that backs the OP's
// /authorize and /interaction/{uid} routes. It is the composition root that
// glues together the pure-validation layer in [internal/authorize] with the
// session manager in [internal/sessions], the consent / login UI bridge in
// [op/interaction], and the on-the-wire cookie codec in [internal/cookie].
//
// # Boundary
//
// The handler implements the authorization endpoint as defined by RFC 6749
// §4.1 / OpenID Connect Core 1.0 §3.1.2 plus the SPA interaction surface
// described in docs/plans/002-product-design.md §A.9 / §C.4. Only the Code
// flow is implemented in v1.0; Implicit and Hybrid response_types are
// rejected at parse time.
//
// # CSRF / Origin policy
//
// State-changing /interaction/{uid} requests must carry an Origin (or
// Referer) header that matches the configured allowlist. The allowlist is
// the union of the configured CORS origins and the issuer's own origin;
// per-client redirect-URI origins are not currently enumerated because the
// [op/store.ClientStore] contract is by-id only and walking the registry is
// not feasible at request time. Embedders that need richer per-client
// allowlisting can compose their own [csrf.Allowlist] and pass it via the
// [Deps] field.
//
// # State carriage
//
// The validated authorization request is persisted in
// [op/store.Interaction.RawState] using [internal/authorize.RequestState]
// and recovered on the matching POST. The browser-side binding is carried
// in the __Host-oidc_interaction cookie, which seals the interaction UID
// under the AAD "oidc-interaction"; tampering produces an opaque rejection.
package authorizeendpoint
