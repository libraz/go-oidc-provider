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
