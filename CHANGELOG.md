# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches v1.0.0. During the pre-v1.0 period, breaking changes may occur
in any minor release.

## [Unreleased]

### Added

- Initial repository scaffold (Apache-2.0 license, contribution guide, security
  policy, baseline `op` package skeleton).
- Per-client scope registry (`op.Scope`, `op.WithScope`). Scopes carry
  visibility (`Public` vs `AllowedClients`), descriptions, and consent
  hints; the registry is consulted by `/authorize`, `/token`, and the
  discovery document so scope listings agree across surfaces.
- RFC 9126 Pushed Authorization Requests. Enabled via
  `op.WithFeature(feature.PAR)`. The `/par` endpoint authenticates the
  client, persists the request through `store.PushedAuthRequestStore`,
  and returns a 60s-lifetime `request_uri`
  (`urn:ietf:params:oauth:request_uri:<32-byte-b64url>`); `/authorize`
  consumes it one-time and rehydrates the original request. Discovery
  advertises `pushed_authorization_request_endpoint`.
- RFC 9449 DPoP (Demonstrating Proof of Possession). Enabled via
  `op.WithFeature(feature.DPoP)`. The token endpoint binds issued
  access and refresh tokens to the proof's JWK thumbprint (`cnf.jkt`),
  the userinfo endpoint enforces the binding, and refresh requests
  must present a matching proof. Replay protection is wired through
  the existing `store.ConsumedJTIStore`. Discovery advertises the
  accepted proof signing algorithms via
  `dpop_signing_alg_values_supported` (ES256, EdDSA).
- RFC 8705 mTLS certificate-bound access tokens. Enabled via
  `op.WithFeature(feature.MTLS)`. When a client presents a TLS
  certificate at the token endpoint, the issued access token carries
  `cnf.x5t#S256` (SHA-256 thumbprint of the leaf cert DER bytes),
  the persisted refresh token records the same thumbprint, and the
  userinfo endpoint enforces the binding on every call. Discovery
  advertises `tls_client_certificate_bound_access_tokens: true` and
  appends `tls_client_auth` / `self_signed_tls_client_auth` to the
  supported auth-method list. The §2 client-authentication paths
  (matching cert subject DN / SAN against client metadata, or
  matching against a registered JWK) are exposed as
  `internal/mtls.VerifyTLSClientAuth` /
  `internal/mtls.VerifySelfSignedTLSClientAuth`; full wiring at the
  token endpoint is deferred to a follow-up that lands the
  `TLSClientAuth*` fields on `op/store.Client`.
- JARM (JWT Authorization Response Mode). Enabled via
  `op.WithFeature(feature.JARM)`. The `/authorize` endpoint emits the
  authorization response as a single signed JWT in the
  `query.jwt` / `fragment.jwt` / `form_post.jwt` / `jwt` response
  modes; error responses follow the same path so they are tamper-proof.
  The form-post variant ships with a strict CSP whose `script-src`
  hash is derived from the inline auto-submit script at package init
  so the header cannot drift from the body. Discovery advertises
  `response_modes_supported` and
  `authorization_signing_alg_values_supported: ["ES256"]`.
- RFC 7591 / RFC 7592 Dynamic Client Registration. Enabled via
  `op.WithDynamicRegistration(...)` plus
  `op.WithFeature(feature.DynamicRegistration)`. The `/register`
  endpoint accepts Initial Access Tokens minted via
  `op.Provider.IssueInitialAccessToken`; registered clients receive a
  `registration_access_token` for self-managed reads, updates, and
  deletes through the `/register/{client_id}` management endpoint.
  The store contract grew `InitialAccessTokens()` and
  `RegistrationAccessTokens()` substores plus a write-side
  `ClientRegistry` interface; the `inmem` adapter implements all three.
- RFC 9101 JWT-Secured Authorization Requests (JAR). Enabled via
  `op.WithFeature(feature.JAR)`. Both `/authorize` and `/par` accept a
  `request=<JWT>` parameter; `/authorize` additionally accepts
  preregistered `request_uri` references via `Client.RequestURIs`. The
  verifier enforces the alg allow-list, JWS signature against the
  client's `JWKs` / `JWKsURI`, RFC 9101 §6.1 claim checks
  (`iss == client_id`, `aud == issuer`, `exp` / `nbf` / `iat` skew),
  and the §6.1 merge rule (request-object claims override wire
  parameters except `client_id`; nested `request` / `request_uri`
  rejected). The JWKS fetcher caps response size at 256 KiB, denies
  private-network URLs, respects `ETag` / `Cache-Control max-age`, and
  caches by URL with a 5-minute default TTL. Discovery advertises
  `request_parameter_supported`, `request_uri_parameter_supported`,
  `require_request_uri_registration: true`, and
  `request_object_signing_alg_values_supported`.
- Authenticator chain. Public `op.Authenticator` interface with
  `op.WithAuthenticators(...)` plus a chain-runner orchestrator
  (`internal/authn`) that drives factors through `BeforeAuthn` →
  `Authn` → `AfterAuthn` → `Done` phases, ferries per-step UI state
  through an orchestrator-private `Step.Scratch` byte slice, and
  persists progress as a JSON `authn.State` blob in
  `store.InteractionStore`. `acr` / `amr` / AAL aggregation across
  factors is centralised in `internal/authn/aggregate` so the issued
  ID token reflects every factor that ran in order.
- RFC 6238 TOTP authenticator (`internal/authn/totp`). Secrets are
  generated via `crypto/rand`, stored AES-256-GCM-sealed at rest
  (`store.TOTPStore`), and verified with the canonical 30-second step
  plus a configurable `±N`-step skew window. The
  `op.NewTOTPAuthenticator` adapter exposes the factor as
  `Type=FactorTOTP`, `AAL=AAL2`, `AMR="otp"`.
- Recovery codes authenticator (`internal/authn/recovery`). Codes are
  minted in batches of 10, displayed once, hashed at rest with
  Argon2id, and consumed single-use via `store.RecoveryCodeStore`. The
  `op.NewRecoveryAuthenticator` adapter exposes the factor as
  `Type=FactorRecovery`, `AAL=AAL1`, `AMR="rc"`.
- WebAuthn passkey authenticator (`internal/authn/passkey`). Wraps
  `go-webauthn/webauthn` for both registration (attestation) and
  assertion (authentication) ceremonies. The
  `op.NewPasskeyAuthenticator` adapter drives the assertion ceremony
  with the orchestrator-private scratch channel carrying the
  per-ceremony `webauthn.SessionData`; factor metadata is
  `Type=FactorPasskey`, `AAL=AAL2`, `AMR="hwk"` (RFC 8176, conservative
  reading of NIST SP 800-63B §5.1.7).
- Built-in consent screen (`internal/authn/consent`). Auto-registered
  by `op.New`, runs after authentication, and projects
  `op.WithScope(...)` registry entries through
  `interaction.ConsentScopePromptData` so the SPA / driver receives
  human-readable scope metadata. Approvals submitted via the
  `approved_scopes` form field are validated against the requested
  scope set, required scopes are enforced, and the resulting subset
  flows back through the orchestrator into the persisted
  `store.Grant`. When the existing grant already covers the requested
  scope set, the consent step is skipped automatically.
- Orchestrator-driven `/interaction` HTTP layer
  (`internal/authn/orchestrator` + `internal/authorizeendpoint`).
  Replaces the prior thin `interaction.Driver` shape: every prompt /
  submission round-trip is mediated by the orchestrator, the encrypted
  state-ref envelope is HMAC-bound, and the driver only renders the
  `interaction.Step` payload. `op/testkit` ships
  `IsConsentPrompt` / `PostConsentApproval` helpers so embedders can
  drive the consent screen from end-to-end tests.
- `internal/clientauth` package. Centralised client authentication
  (client_secret_basic / client_secret_post / private_key_jwt /
  client_secret_jwt / mTLS) extracted from the token endpoint so PAR,
  introspection, revocation, and DCR all share one verifier with one
  set of error semantics.
- RFC 7662 OAuth 2.0 Token Introspection. Enabled via
  `op.WithFeature(feature.Introspect)`. The `/introspect` endpoint
  authenticates the calling client through `internal/clientauth`,
  detects whether the supplied `token` is a JWT-shaped access token
  (RFC 9068) or an opaque refresh token, and projects the verified
  record onto the canonical RFC 7662 §2.2 JSON shape. Same-client-only
  authorization (a token belonging to a different client surfaces as
  `{"active": false}`); RFC 7662 §2.3 / §4 caching and content-type
  rules are enforced. `token_type_hint` is honoured but the handler
  always falls through on miss per §2.1. Discovery advertises
  `introspection_endpoint` and
  `introspection_endpoint_auth_methods_supported`.
- RFC 9701 JWT Response for OAuth 2.0 Token Introspection. The
  `/introspect` endpoint now negotiates the response format: if the
  request's `Accept` header prefers `application/token-introspection+jwt`,
  or the introspecting client preregistered `introspection_signed_response_alg`
  via `op/store.Client.IntrospectionSignedResponseAlg`, the response is
  a compact-serialised JWS carrying `iss` / `aud` (= client_id) / `iat`
  with the RFC 7662 body nested under `token_introspection`. The JWS
  uses the OP's active signing key and stamps `typ: token-introspection+jwt`.
  Discovery advertises `introspection_signing_alg_values_supported: ["ES256"]`
  whenever the Introspect feature is enabled.
- RFC 7009 OAuth 2.0 Token Revocation. Enabled via
  `op.WithFeature(feature.Revoke)`. The `/revoke` endpoint authenticates
  the calling client through `internal/clientauth`, dispatches on token
  shape (JWT-shaped → access-token verifier; opaque → refresh-token
  store), enforces same-client-only authorization, and walks the
  refresh-token rotation chain to its root before calling
  `RefreshTokens.RevokeChain`. Per RFC 7009 §2.2 the response is always
  HTTP 200 with an empty body — the server intentionally hides whether
  the token was found, valid, or already revoked. JWT access-token
  revocation is a no-op (the OP does not maintain a denylist in v1.0;
  the token expires naturally). Discovery advertises
  `revocation_endpoint` and
  `revocation_endpoint_auth_methods_supported`.
- RFC 6749 §4.4 client_credentials grant. Enabled by adding
  `grant.ClientCredentials` to `op.WithGrants(...)`. The
  `/token` endpoint authenticates the client through
  `internal/clientauth`, validates that the client is confidential
  and registered for the grant, intersects the requested scope
  against `Client.Scopes`, rejects the OIDC `openid` scope (no
  end-user), and mints a JWT access token whose `sub` claim equals
  the `client_id`. Refresh tokens and id_tokens are never issued
  on this grant. DPoP and mTLS bindings flow through the existing
  `tokenBinding` plumbing so a client_credentials access token
  inherits sender constraints exactly like an authorization_code
  one.
- OpenID Connect RP-Initiated Logout 1.0. The `/end_session`
  endpoint accepts GET or POST, validates the optional
  `id_token_hint` (signature only — expired tokens are accepted so a
  user can log out from a stale tab), resolves the requesting client
  via the token's `aud` claim or the `client_id` parameter, and
  validates `post_logout_redirect_uri` against
  `op/store.Client.PostLogoutRedirectURIs` (exact byte match). On a
  valid request the handler clears the `__Host-oidc_session` cookie,
  deletes the underlying session record, and either redirects 302
  to the post-logout URI (with `state` echoed) or renders a minimal
  static HTML confirmation page. The error path returns 400 without
  clearing the cookie so a malformed request cannot terminate a
  session by accident. Discovery already advertised
  `end_session_endpoint`; this release wires the handler.
- Logging redaction (`internal/redact`). The package wraps any
  `slog.Handler` so attributes named after the canonical OAuth/OIDC
  secrets — `access_token`, `refresh_token`, `id_token`, `code`,
  `code_verifier`, `client_secret`, `password`, `state`, `nonce`,
  `dpop` / `dpop_proof`, `authorization`, `cookie`, `set-cookie`,
  `registration_access_token`, `initial_access_token`, `request`,
  `assertion`, `client_assertion` — are replaced with the sentinel
  `[REDACTED]` before they reach the underlying handler. Matching is
  case-insensitive and treats hyphens / underscores as equivalent so
  `Set-Cookie`, `set_cookie`, and `set-cookie` all resolve to the
  same entry. `op.WithLogger` now wraps the supplied logger's
  handler automatically; the wrap is idempotent. A free-form
  `redact.Mask(string)` helper rewrites `key=value` pairs (URL
  queries, Cookie headers) for the rare callsite that logs an
  unparsed string.
