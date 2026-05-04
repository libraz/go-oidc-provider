# Changelog

`v0.9.0` is the initial public release of go-oidc-provider. Notable changes
in subsequent releases are tracked here in
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format.

The project follows strict [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
from `v1.0.0` onwards; pre-v1.0 minor releases (including the `v0.9.x`
series) may carry breaking changes — see the `Changed` / `Removed`
sections of each release for the migration notes.

The main module and the storage-adapter sub-modules
(`op/storeadapter/sql`, `op/storeadapter/redis`) share the same release
tag. Embedders pull each sub-module independently:

```
go get github.com/libraz/go-oidc-provider@v0.9.0
go get github.com/libraz/go-oidc-provider/op/storeadapter/sql@v0.9.0
go get github.com/libraz/go-oidc-provider/op/storeadapter/redis@v0.9.0
```

## [Unreleased]

### Added

- CIBA poll mode (Wave N2). The OP now exposes the
  Client-Initiated Backchannel Authentication endpoint
  (`/oidc/bc-authorize`) and accepts
  `urn:openid:params:grant-type:ciba` at the token endpoint.
  Push and ping delivery modes are deferred to v2+; only poll
  mode ships in v0.9.1. Public surface:
  - `op.WithCIBA(...)` registers the CIBA substore, the
    `HintResolver` seam (login_hint / login_hint_token / id_token_hint
    → internal subject), and the `AuthDevice` seam (out-of-band
    push to the authentication device). The option is required to
    enable CIBA; the endpoint and grant_type stay off by default.
  - `op.CIBARequestStore` is a new substore in the public store
    interface; the in-memory adapter ships, SQL / Redis adapters
    follow in v0.9.2.
  - Discovery now publishes
    `backchannel_authentication_endpoint`,
    `backchannel_token_delivery_modes_supported=["poll"]`,
    `backchannel_user_code_parameter_supported=false`, and
    `backchannel_authentication_request_signing_alg_values_supported`.
  - `profile.FAPICIBA` graduates from placeholder to enforced:
    `RequiredFeatures=[JAR]`, `RequiredAnyOf=[[DPoP, MTLS]]`,
    `MaxAccessTokenTTL=10min`, the FAPI 2.0 client-authentication
    set (`private_key_jwt` / `tls_client_auth` /
    `self_signed_tls_client_auth`), and
    `RequiresAccessTokenRevocation=true`. JAR enforcement on the
    /bc-authorize side requires `iss` / `aud` / `exp` / `nbf` and
    caps the request-object lifetime at 60 seconds.
  - `examples/31-ciba-pos/` ships a paired OP+RP demo (POS terminal
    initiates `/bc-authorize`, the staff phone approves,
    end-to-end in roughly one second).
- v0.9.1 example backfill — paired OP+RP demos for the four Waves
  whose example slot was reserved in `008` §5.0 but unfilled:
  - `examples/19-custom-grant/` (Wave N0) — embedder defines
    `urn:example:libraz:service-token-exchange`, the OP routes it via
    `op.WithCustomGrant`, and the handler returns a `BoundAccessToken`
    so the dispatcher mints a JWT access token bound to the
    request's DPoP / mTLS confirmation.
  - `examples/30-device-code-cli/` (Wave N1) — terminal CLI drives the
    RFC 8628 device-authorization grant against the OP, prints the
    boxed user_code panel + `verification_uri_complete` shortcut,
    and polls `/token` honoring `slow_down` and
    `authorization_pending`.
  - `examples/32-token-exchange-delegation/` (Wave N3) — frontend →
    service-a → service-b cross-client impersonation triggers the
    OP-side `act` claim chain (ADR 0028); service-b's RS-side
    verifier walks `act.sub` and accepts only delegated tokens.
  - `examples/33-pairwise-saas/` (Wave O1) — `WithPairwiseSubject`
    salt with two tenants in distinct sectors observes `A != B`
    (different sector → different sub) and `A1 == A2` (same
    sector + same user → identical sub), satisfying both the
    privacy and determinism properties of OIDC Core §8.1.
- JWE encryption (Wave T1, ADR 0030). The OP now decrypts JWE-shaped
  request objects (JAR / PAR) and wraps outbound `id_token`,
  `userinfo` (JWT-shape), JARM authorization responses, and
  RFC 9701 JWT introspection responses in a JWE addressed to the
  client's `use=enc` JWK whenever client metadata registers
  `*_encrypted_response_alg` / `_enc`. Public surface:
  - `op.WithEncryptionKeyset(keys ...op.EncryptionKey)` registers the
    OP's `use=enc` keyset; keys are published on the JWKS document
    alongside the existing `use=sig` material (RFC 7517 §4.2).
  - `op.WithSupportedEncryptionAlgs(algs []string, encs []string)`
    narrows the OP-advertised algorithm set below the v0.9.1 default
    allowlist (`RSA-OAEP-{256,384,512}` / `ECDH-ES{,+A128KW,+A256KW}`
    × `A{128,256}GCM`). `RSA1_5` is intentionally not shipped
    (CVE-2017-11424 padding oracle); `dir` and symmetric-only `A*KW`
    are reserved for v2+.
  - Discovery now publishes `id_token_encryption_alg_values_supported`
    / `_enc_values_supported`, the userinfo / request_object /
    authorization (JARM) / introspection counterparts, and gates each
    on the corresponding feature flag (JAR / JARM / Introspect).
  - `userinfo_signing_alg_values_supported` is now published
    unconditionally (`ES256`); the JWT-shape userinfo path is
    always available via `Accept: application/jwt`.
  - `examples/34-encrypted-id-token` ships a paired OP+RP demo of
    RSA-OAEP-256 / A256GCM id_token encryption (client metadata +
    JWKS distribution + RP-side decrypt).
- RFC 8693 token-exchange grant_type via `op.RegisterTokenExchange`.
  The provider verifies subject_token / actor_token, normalises the
  requested audience (RFC 8707 §2), enforces scope and audience
  subset rules, caps the issued TTL by the minimum of (handler
  request, subject_token remaining, global ceiling), builds the
  act-claim chain on the OP side (mandatory whenever the actor
  differs from the subject), and rebinds the issued token's cnf to
  the request's verified DPoP / mTLS credential. The
  `TokenExchangePolicy` seam is required at op.New; deployments
  without it cannot exchange.
- `op.WithInteractionDriver` replaces `op.WithInteraction` (driver
  registration). The new name disambiguates the single-driver option
  from `op.WithInteractions` (Step list).
- `op.Error` now exposes `newConfigurationError` factory pattern; the
  doc on `op.Error` directs new option-side error sites at the
  factory for consistency.
- `op/example_test.go` ships three `ExampleNew_*` runnable examples
  (minimal / FAPI 2.0 / JSON interaction driver) so godoc on
  pkg.go.dev renders working snippets.
- `internal/log.DiscardHandler` is the single shared `slog.Handler`
  used as the no-op default; `op.discardHandler`,
  `internal/redact.discardHandler`, and
  `internal/authn/orchestrator.discardHandler` now delegate.
- `internal/clone.Int64Ptr` consolidates the `cloneInt64Ptr` helper
  previously duplicated between `op/op.go` and
  `internal/registrationendpoint/metadata.go`.
- `internal/endpointsupport` extracts the client-authentication +
  bearer-extraction + audit-emission + error-response helpers shared
  by /introspect, /revoke, /register, /userinfo (~180 lines of
  duplication eliminated).
- `op/storeadapter/patterns` exposes `IsExpiredStrict`,
  `IsExpiredInclusive`, `MapSQLNotFound`, `MapRedisNotFound`,
  `DedupBatch`, `Paginate` so adapters share TTL / NotFound /
  pagination semantics.
- `op/store/contract` adds `AssertConcurrentRotate`,
  `AssertExpiredSessionReturnsNotFound`,
  `AssertSessionNotFoundOnMissing`, `AssertSessionBatchListMatches`
  so every adapter exercises the same `SessionStore` contract.
- `internal/authn/risk` and `internal/authn/audit` sub-packages carry
  the orchestrator's risk-evaluation and observation surfaces; the
  orchestrator delegates to them through narrow adapters.
- `internal/testutil/httptest` exposes `PostForm`,
  `PostFormWithAccept`, `GetWithBearer`, `DecodeJSON` so endpoint
  fixture setup stays consistent across test packages.
- `examples/internal/opkit` ships `DefaultLoginFlow`, `WithTOTP`,
  `WithMFARules` so example boilerplate around `op.New` shrinks.
  Examples 01 / 20 / 21 use the helpers.
- `op.WithPreferredLocaleStore` registers an embedder hook the locale
  resolver consults at the head of the §L.2 priority chain (before
  ui_locales / cookie / Accept-Language / default).
- `op.Provider.LocaleResolver()` exposes the configured resolver so
  embedders can render emails, server-rendered admin pages, or other
  out-of-band surfaces in the same locale the OP picks for /authorize
  prompts.
- `interaction.Prompt` now carries `Locale` (OP-resolved tag),
  `UILocalesHint` (RP's raw `ui_locales` list), and
  `LocalesAvailable` (registered locales). The orchestrator stamps
  these fields before `Driver.Render`; SPAs read them on
  /oidc/interaction/{uid} to set `<html lang>` and build language
  pickers without re-running the chain or re-fetching discovery.

### Changed

- **Breaking**: `op.WithInteraction` was renamed to
  `op.WithInteractionDriver` so the single-driver option no longer
  collides with `op.WithInteractions` (Step list).
- **Breaking**: `op.WithCookieKey` (single-key wrapper) was removed;
  pass keys to `op.WithCookieKeys(keys ...[]byte)` directly.
- **Breaking**: `op.WithMFAEncryptionKey` (single-key wrapper) was
  removed; pass keys to `op.WithMFAEncryptionKeys(keys ...[]byte)`
  directly. The TOTP step error message references the new name.
- `op.WithMTLSProxy` graduates from "Experimental — partial wiring"
  to wired-end-to-end. `op.New` now threads the recorded
  `mtls.ProxyConfig` into the verifier so the reverse-proxy header
  path works for every request.
- JAR `AllowMissingJTI` is forced to `false` whenever any FAPI
  profile (FAPI2Baseline / FAPI2MessageSigning / FAPICIBA) is
  active; the strict RFC 9101 §10.8 posture is no longer
  embedder-overridable in profile-active deployments.
- `internal/cookie/build.go` validate now rejects
  `SameSite=None` + `Secure=false` combinations at construction
  time. The default profiles already set Secure=true; the guard
  protects custom profiles.
- `internal/proxy/proxy.go` `walkForwardedFor` normalises bracketed
  / port-suffixed IPv6 tokens via `SplitHostPort`, matching the
  RemoteAddr path so the trust gate behaves identically across
  X-Forwarded-For shapes.
- `op/store.SessionStore` godoc + `internal/sessions.Manager.Rotate`
  comment now spell out the non-atomic Save→Delete contract;
  every adapter exercises the same `AssertConcurrentRotate`
  contract assertion.
- `internal/authn/orchestrator.go` shrank from 1,210 to ~492 lines;
  Phase / Risk / Audit responsibilities moved into
  `internal/authn/{phases.go, risk_*, audit_*}` and the new
  `internal/authn/{risk,audit}` sub-packages.
- `op/options.go` (3,268 → 2,374 lines) and `op/op.go` (2,073 → 992
  lines) split into themed companion files
  (`options_validate.go`, `options_defaults.go`,
  `op_builders.go`, `op_router.go`).
- `internal/tokenendpoint/authcode.go` shrank to 769 lines after
  factoring out `authcode_enforce.go` and `binding.go`.
- `internal/userinfo/handler.go` shrank to 713 lines after factoring
  out the opaque-format service path into `serve_opaque.go`.
- `internal/registrationendpoint/metadata.go` (759 → 185 lines) split
  into `metadata_validate.go` and `metadata_schemes.go`.
- `internal/authorize/request.go` (703 → 157 lines) split into
  `parsing.go`, `validation.go`, `normalization.go`.
- `op/storeadapter/inmem/inmem.go` (1,310 → 1,097 lines): client and
  authorization-code substores plus the hash / constant-time-match
  helpers moved into dedicated files.
- `op/options_test.go` (2,193 → 456 lines) split into theme files
  (keyset / features / authn / clients / discovery).
- The authorize handler now consults the configured locale resolver on
  every interaction tick. The chain reads `__Host-oidc_locale` cookie
  / Accept-Language / authorize ui_locales for layers 2–4; the cookie
  write endpoint (`POST /oidc/session/locale`) remains unimplemented
  and is scheduled for a follow-up plan.
- Example 16-i18n-locale now runs an in-process self-verify probe
  before the listener starts so `go run -tags example` prints a
  PASS / FAIL summary for each row of the §L.2 chain.
- Example 10-react-login's SPA stamps the OP-resolved locale onto
  `document.documentElement.lang` on every prompt render.
- Example 04-custom-interaction now ships a thin locale-aware Driver
  wrapper that copies `Prompt.Locale` into the `Content-Language`
  response header, demonstrating the embedder pattern.
- Examples 04 / 05 / 06 now carry the standard `PRODUCTION CAVEATS`
  block (signing-key persistence, store durability, secret-source
  guidance) so the example tree's safety posture is uniform.
- `op.WithDPoPNonceSource` and `internal/authn/totp.Verifier.Verify`
  godoc spell out the multi-replica deployment expectation
  (distributed nonce / TOTP store required when running > 1 OP
  process).

### Fixed

- `op/testkit.ensureTrust` now triggers `http.DefaultTransport`'s
  internal `nextProtoOnce` before mutating `TLSClientConfig`. The
  prior path raced with `httptest.Server.Close` (which calls
  `http.DefaultTransport.CloseIdleConnections`, internally invoking
  `http2configureTransports` to write `TLSClientConfig.NextProtos`)
  whenever both ran in parallel test goroutines.
- `op/storeadapter/sql/grant_revocation_test` now opens the SQLite
  test DB through a `file:` URL under `t.TempDir` instead of
  `:memory:`. Per-connection in-memory DBs were creating disjoint
  state across the parallel subtests' connection pool, so revocation
  rows written by one connection were not visible from another.

### Removed

- `op.WithInteraction` (renamed to `op.WithInteractionDriver`).
- `op.WithCookieKey` (single-key wrapper; use `op.WithCookieKeys`).
- `op.WithMFAEncryptionKey` (single-key wrapper; use
  `op.WithMFAEncryptionKeys`).
- `op.WithPasskeyAttestation` (was a no-op stub awaiting wiring;
  removed so the v1.0 surface does not freeze a non-functional
  option).

## [v0.9.0] — initial public release

[Unreleased]: https://github.com/libraz/go-oidc-provider/compare/v0.9.0...HEAD
[v0.9.0]: https://github.com/libraz/go-oidc-provider/releases/tag/v0.9.0
