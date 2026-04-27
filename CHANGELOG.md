# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches v1.0.0. During the pre-v1.0 period, breaking changes may occur
in any minor release.

## [Unreleased]

### Added

- `op.WithAccessTokenTTL(time.Duration)` option overrides the
  lifetime of issued access tokens. Zero opts into the new public
  default `op.DefaultAccessTokenTTL` (5 minutes); negative values
  are rejected at the option site so the misconfiguration surfaces
  at startup. When a FAPI 2.0 profile is also active, the
  embedder's TTL must stay at or below the profile's bound: FAPI
  2.0 §3.1.9 caps access tokens at 10 minutes, encoded as
  `profile.MaxAccessTokenTTL`. Stricter-than-profile values
  remain accepted; a value above the bound fails `op.New`. The
  bound flows through to `tokenendpoint.Deps.AccessTokenTTL` so
  authorization_code, refresh_token, and client_credentials grants
  all honour it.
- Conformance harness scaffolding under `conformance/` plus the
  driver script `scripts/conformance.sh` and Makefile targets
  `conformance-certs`, `conformance-op-up`, `conformance-op-down`,
  `conformance-op-status`. The `certs` target generates a 30-day
  ECDSA P-256 self-signed cert covering `localhost`,
  `host.docker.internal`, `127.0.0.1`, and `::1` so the OFCS
  container can reach op-demo across the Docker network boundary.
  The `op-up` target builds the op-demo binary once (avoiding the
  `go run` parent-child PID layering that leaks listeners) and
  starts it on `https://127.0.0.1:9443`, seeded with the three
  per-plan callback URIs. Three OFCS plan templates ship under
  `conformance/plans/`: `oidcc-basic.json`, `fapi2-baseline.json`,
  `fapi2-message-signing.json`. OFCS itself is not bundled — the
  README documents the canonical clone-and-build of
  `openid/conformance-suite`. Headless plan submission via OFCS
  REST API is deferred to the green-out wave because the API
  surface is not version-stable across releases.
- `cmd/op-demo` `-redirect-uri` flag now accepts a comma-separated
  list. A multi-plan OFCS run targets one alias per plan
  (`/test/a/<alias>/callback`), so seeding every alias in a single
  invocation lets one op-demo serve every plan without restart
  between runs. Whitespace and stray trailing commas are trimmed.
- `cmd/op-demo` runnable demo OP binary suitable for manual flows and
  the OpenID Foundation Conformance Suite. Generates ephemeral ES256
  signing and cookie keys, seeds an inmem store with a single demo
  client, and shuts down cleanly on SIGINT / SIGTERM via
  `signal.NotifyContext`. CLI flags expose `-listen`, `-issuer`,
  `-mount`, `-client-id`, `-redirect-uri`, plus `-tls-cert` /
  `-tls-key` for HTTPS — the OFCS requires `https://` issuers, so the
  TLS branch is the harness path. The two TLS flags are validated as
  a pair (one without the other is a config error so a half-set
  invocation cannot silently degrade to plain HTTP). Not for
  production — the binary is dev-only and persists every record in
  process memory.
- `examples/minimal` shows the smallest embedder boilerplate that
  constructs a Provider and mounts it on an `http.ServeMux`. Gated by
  the `//go:build example` tag so the example does not enter the main
  module build (`go run -tags example ./examples/minimal`).
- `op.WithProfile` now enforces the profile's MUST clauses against the
  rest of the configuration: `profile.FAPI2Baseline` rejects `op.New`
  unless `feature.PAR`, `feature.JAR`, and at least one of
  `feature.DPoP` / `feature.MTLS` are also enabled (FAPI 2.0 §3.1.1 /
  §3.1.4 / §3.1.11); `profile.FAPI2MessageSigning` additionally
  requires `feature.JARM` (Message Signing §5). Stricter-than-profile
  configurations remain accepted; the rule is one-directional, so a
  profile cannot be relaxed by a later option. The constraint table
  itself lives in `op/profile.RequiredFeatures` /
  `op/profile.RequiredAnyOf` so embedders can introspect or mirror the
  same checks in their own boot harness.
- Email-OTP authenticator (`op.NewEmailOTPAuthenticator`) implementing
  the two-screen send / verify factor per design 002 §E.2 / §E.3. The
  factor maps to `FactorEmailOTP`, contributes AAL2, and reports RFC
  8176 amr `"otp"`. Construction takes a `Mailer` SPI hook (the
  embedder's transport — SMTP, SES, or a queue producer), the new
  `store.EmailOTPStore` substore that persists pending challenges as
  SHA-256(salt || subject || code) hashes, and a `store.UserStore` so
  the authenticator can resolve the subject's bound `email` claim.
  Codes are 6 decimal digits drawn from `crypto/rand`, single-use, and
  expire after `DefaultEmailOTPCodeTTL` (5 minutes). The verify step
  shares the brute-force counter shape with TOTP (30 wrong codes →
  1-hour lock; 90 wrong codes → 24-hour lock + reset-required). The
  prompt shape is constant whether or not the user-typed address
  matches the bound claim — on mismatch the authenticator persists a
  no-`SentAt` sentinel record so verify deterministically fails
  without leaking enumeration information through prompt or timing.
  In-memory reference store: `inmem.Store.EmailOTPs()`.
- OpenID Connect Back-Channel Logout 1.0. The OP signs a Logout Token
  (`typ=logout+jwt`, ES256, with `iss`/`aud`/`iat`/`exp`/`jti`/`sub`/`sid`/`events`)
  and POSTs it to every relying party that registered a
  `backchannel_logout_uri` when `/end_session` succeeds. Audience is
  resolved via the new `store.GrantStore.ListBySubject` method; storage
  backends MUST implement it (the in-memory adapter is updated). The
  fan-out is best-effort: per-RP failures surface as
  `logout.back_channel.failed` audit events rather than rolling back
  the user-visible logout. Two new options tune the transport:
  `op.WithBackchannelLogoutHTTPClient` injects a shared `*http.Client`
  (the package default refuses 3xx redirects per the spec posture) and
  `op.WithBackchannelLogoutTimeout` overrides the per-RP request budget
  (default 5 seconds). Discovery now advertises
  `backchannel_logout_supported` and `backchannel_logout_session_supported`.
  `op/store.Client` gains `BackchannelLogoutURI` and
  `BackchannelLogoutSessionRequired`; the latter forces the OP to emit
  `sid` and skips the RP when no session id is available.
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
- Locale resolver (`internal/i18n`) and the public
  `op.WithDefaultLocale` / `op.WithLocale` options. The resolver
  walks the priority chain from design 002 §L.2:
  `UserStore.PreferredLocale(sub)` → `ui_locales` authorize
  parameter → `__Host-oidc_locale` cookie → `Accept-Language` HTTP
  header → `WithDefaultLocale` (defaults to `LocaleEnglish`). An
  exact tag match wins; failing that, the language subtag is tried
  so `ja-JP` hits the `ja` bundle. The library ships seed
  catalogues for `en` / `ja` covering the consent screen, login
  screen, logout screen, and the canonical
  `invalid_request` / `access_denied` / `server_error` error pages;
  embedders override individual entries through `op.WithLocale`
  and add new locales the same way. The catalogue format is a flat
  dotted-key JSON object with `{var}` placeholders for runtime
  substitution; ICU MessageFormat support is deferred. The
  `WithDefaultLocale` value is validated at construction so a
  default that is not registered fails closed instead of silently
  falling back.
- Audit-event sink (`internal/audit`) and the public
  `op.WithAuditLogger(*slog.Logger)` option. Audit records carry the
  slog attribute `audit="true"` so log shippers can route them to
  long-retention storage without parsing the event name; the
  remaining canonical fields (`event` / `actor_id` / `client_id` /
  `session_id` / `request_id` / `ip` / `user_agent` / `tag`) ride
  as top-level attributes and event-specific data lives under the
  `extras` group. The supplied logger's handler is wrapped through
  `internal/redact` so a regression that drops a token into an
  `Event.Extras` map cannot escape the wire posture. The closed
  catalogue of event names ships as `op.AuditEvent` constants
  (login / mfa / consent / code / token / session / logout / dcr /
  defensive). When `WithAuditLogger` is absent the emitter falls
  back to the operational logger from `WithLogger`; when neither is
  set audit records are dropped silently. The
  `internal/registrationendpoint` handler is migrated onto the
  lifted package; previous private `auditLogger` / `auditEvent`
  shapes are removed.
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
