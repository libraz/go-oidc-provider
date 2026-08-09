// Package endsession implements the OpenID Connect RP-Initiated Logout 1.0
// endpoint mounted at /end_session. The handler accepts GET or POST,
// validates the request, terminates the active browser session, and
// either redirects the browser to a preregistered
// post_logout_redirect_uri or renders a minimal logout-confirmation
// page.
// # Spec reference
// OpenID Connect RP-Initiated Logout 1.0 (final). Section 2 enumerates
// the request parameters; Section 3 covers redirection back to the RP.
// The OP-side validation rules below mirror that text.
// # Request parameters
//   - id_token_hint (RECOMMENDED): an id_token previously issued by
//     the OP. Signature is verified; the "aud" claim identifies the
//     requesting client and the "sub" claim identifies the session the
//     RP is asking to end.
//   - client_id (OPTIONAL): the requesting client. When both
//     id_token_hint and client_id are present they MUST agree (the
//     "aud" of the id_token contains the client_id).
//   - post_logout_redirect_uri (OPTIONAL): the URI the browser is
//     redirected to after logout. MUST be exact-match preregistered
//     for the resolved client through
//     [op/store.Client.PostLogoutRedirectURIs].
//   - state (OPTIONAL): opaque string echoed in the redirect query
//     string when post_logout_redirect_uri is present.
//   - logout_hint (OPTIONAL, IGNORED): a hint about the user the spec
//     allows the OP to consume to render a chooser. The OP has no
//     chooser UX surface here, so the parameter is parsed and
//     discarded.
//   - ui_locales (OPTIONAL, IGNORED): locale preference for the
//     confirmation prompt. The confirmation is a small static page
//     that does not localise, so the parameter is parsed and
//     discarded.
//
// # Validation policy
// The handler short-circuits to a 400 page (NOT a redirect) on any
// failure that prevents the OP from identifying a registered client:
//   - id_token_hint that does not parse, carries an unknown kid, or
//     fails signature verification.
//   - client_id parameter that disagrees with the id_token_hint's
//     "aud" claim.
//   - post_logout_redirect_uri that is not in the resolved client's
//     [op/store.Client.PostLogoutRedirectURIs] allowlist.
//   - post_logout_redirect_uri without a resolvable client (no
//     id_token_hint, no client_id).
//
// The error response is a small static text/html body with a strict
// Content-Security-Policy header. The OP never redirects to an
// unvetted URI on the error path.
// # User-visible policy choices
// The implementation makes four choices that diverge from a purely
// permissive reading of the spec; each is intentional and documented
// here so future regressions surface in code review.
//   - Expired id_tokens are accepted. The user wants to log out from
//     a stale tab; the spec does not require freshness for
//     id_token_hint and enforcing exp would degrade the UX without
//     improving security (signature plus aud is sufficient to
//     identify the requesting client and prevent cross-OP forgery).
//   - The error path does NOT clear the session cookie. A malformed
//     /end_session request is hostile or buggy; rewarding it with a
//     side-effect on the active session would let an attacker who
//     can trigger a malformed GET (CSRF-style) terminate the user's
//     session by accident. The success and "no redirect URI" paths
//     do clear the cookie because the request validated.
//   - An interactive confirmation prompt is rendered unless the
//     request proves intent for the session at hand. The spec says
//     the OP SHOULD ask the user to confirm; the OP skips the prompt
//     only when id_token_hint carries the subject the session cookie
//     authenticates (or when no session resolves at all, where there
//     is nothing to terminate). Every other shape — no hint, or a
//     hint minted for a different subject — gets the interstitial on
//     GET and a double-submit CSRF check on POST, because a bare hint
//     proves possession of someone's token, not the identity of the
//     browser presenting it. Embedders that need a richer prompt
//     mount their own handler in front of /end_session; the library
//     exposes the /end_session URL through discovery either way so
//     the wire posture stays uniform.
//   - post_logout_redirect_uri is rejected when no client can be
//     resolved. Validating the URI without a client would require
//     either trusting the parameter (a redirect oracle) or accepting
//     the URL but refusing to redirect (a CSRF gadget); the chosen
//     behaviour is the only safe option.
//
// # Layering
// The handler depends on:
//   - [internal/sessions.Manager] — Resolve / Logout the active session.
//   - [internal/cookie.Profile] / [internal/cookie.Build] /
//     [internal/cookie.Clear] — produce the Set-Cookie headers that
//     install [internal/cookie.LogoutCSRFProfile] and retire
//     [internal/cookie.SessionProfile].
//   - [internal/csrf] — mint the double-submit token, compare its two
//     halves, and decide whether the confirmation POST's provenance
//     headers admit it. The decision logic is shared with the
//     /interaction endpoint so both HTML-facing gates admit the same
//     request shapes.
//   - [internal/keys.Set] — verify the id_token_hint's signature
//     against the OP's active and retiring keys.
//   - [op/store.ClientStore] — resolve the requesting client when
//     only client_id is supplied.
//
// The package never imports op/, never reads the wall clock directly
// (it ferries an [op.Clock]-shaped interface through [Deps]), and
// never mutates its inputs.
package endsession
