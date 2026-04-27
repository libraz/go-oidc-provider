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
  `introspection_endpoint_auth_methods_supported`. JWT introspection
  for FAPI Message Signing is a follow-up.
