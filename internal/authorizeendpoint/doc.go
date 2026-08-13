// Package authorizeendpoint hosts the HTTP handler that backs the OP's
// /authorize and /interaction/{uid} routes. It is the composition root that
// glues together the pure-validation layer in internal/authorize with the
// session manager in internal/sessions, the consent / login UI bridge in
// [op/interaction], and the on-the-wire cookie codec in internal/cookie.
// # Boundary
// The handler implements the authorization endpoint as defined by RFC 6749
// §4.1 / OpenID Connect Core 1.0 §3.1.2 plus the OP's own SPA
// interaction surface (the /interaction/{uid} JSON API and the
// multi-account cookie layout). Only the Code
// flow is implemented in v1.0; Implicit and Hybrid response_types are
// rejected at parse time.
// # CSRF / Origin policy
// State-changing /interaction/{uid} requests must carry an Origin (or
// Referer) header that matches the configured allowlist. The allowlist is
// the union of the configured CORS origins and the issuer's own origin.
//
// Per-client redirect_uri origins are deliberately excluded, and the
// exclusion is a trust boundary rather than a lookup limitation: the CORS
// allowlist does carry them, so reusing it here would let an origin
// registered by one client post to another client's consent ceremony —
// exactly the cross-client forgery the ceremony exists to prevent.
// Widening this list to the redirect_uri origins therefore erases the
// boundary; nothing derived from a client registration belongs in it.
//
// The interaction UI is served by the OP itself, so the issuer's origin
// covers the default deployment. An embedder that hosts that UI on a
// separate origin names it through [op.WithCORSOrigins], which is an
// explicit act rather than a side effect of registering a client. That
// option is the only supported way to widen the list: [Deps] belongs to
// this internal package and is not reachable from the public API.
// # State carriage
// The validated authorization request is persisted in
// [op/store.Interaction.RawState] using internal/authorize.RequestState
// and recovered on the matching POST. The browser-side binding is carried
// in the __Host-oidc_interaction cookie, which seals the interaction UID
// under the AAD "oidc-interaction"; tampering produces an opaque rejection.
package authorizeendpoint
