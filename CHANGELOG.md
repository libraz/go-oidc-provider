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
# v0.9.1 (latest)
go get github.com/libraz/go-oidc-provider@v0.9.1
go get github.com/libraz/go-oidc-provider/op/storeadapter/sql@v0.9.1
go get github.com/libraz/go-oidc-provider/op/storeadapter/redis@v0.9.1

# v0.9.0 (initial public release)
go get github.com/libraz/go-oidc-provider@v0.9.0
go get github.com/libraz/go-oidc-provider/op/storeadapter/sql@v0.9.0
go get github.com/libraz/go-oidc-provider/op/storeadapter/redis@v0.9.0
```

## [v0.9.1] — 2026-05-07

### Highlights

- CIBA poll mode (OpenID Connect Client-Initiated Backchannel
  Authentication Core 1.0): `/oidc/bc-authorize` endpoint, the
  `urn:openid:params:grant-type:ciba` token grant, and a new
  `op.CIBARequestStore` substore. Push and ping delivery modes are
  deferred to v2+.
- RFC 8693 token-exchange grant_type via `op.RegisterTokenExchange`
  with audience normalisation (RFC 8707 §2), act-claim chain assembly,
  and DPoP / mTLS cnf rebinding on the issued token.
- RFC 8628 device-authorization grant via `op.WithDeviceCode(...)`,
  plus the new `op/devicecodekit` sub-package for embedder-side
  user_code verification with a per-record brute-force lockout.
- OIDC Core §8 pairwise subject derivation
  (`op.WithPairwiseSubject(salt)` / `op.WithSubjectGenerator(...)`)
  with hardened `sector_identifier_uri` resolution and
  mid-life-strategy switching rejected at `op.New`.
- RFC 7516 JWE encryption for inbound JAR / PAR request objects and
  outbound `id_token`, JWT-shape `userinfo`, JARM authorization
  responses, and RFC 9701 introspection responses, advertised via the
  five matching `*_encryption_alg_values_supported` discovery fields.
- Stable custom-grant dispatcher: `op.WithCustomGrant(...)` graduates
  out of its experimental marker, with a documented cnf-binding
  contract and a `BoundAccessToken` helper for DPoP / mTLS-bound
  handler responses.
- `profile.FAPICIBA` graduates from placeholder to enforced
  (JAR + DPoP-or-MTLS, 10-minute access-token cap, FAPI 2.0
  client-authentication set, mandatory access-token revocation).
- New first-party auto-consent path
  (`op.WithFirstPartyClients` + the `consent.granted.first_party`
  audit event), a profile-level `RequiredAnyOf` auto-default that
  lets `WithProfile(FAPI2Baseline)` activate DPoP with no further
  wiring, automatic CORS allowlisting of static-client redirect URI
  origins, locale-resolver fallback for
  `ui_locales_supported`, and a
  `WithAllowInsecureBackchannelLogoutForDev` dev opt-in for
  loopback http back-channel logout.
- Breaking option renames (`op.WithInteraction` →
  `op.WithInteractionDriver`) and removal of the
  single-key wrappers (`op.WithCookieKey`, `op.WithMFAEncryptionKey`)
  and the no-op `op.WithPasskeyAttestation` stub.

### Added

- `op.WithCustomGrant(...)` (ADR 0027) graduates from the
  experimental marker introduced in v0.9.0 to a stable surface:
  `CustomGrantHandler` interface (`Name` / `ParamPolicy` / `Handle`)
  + `BoundAccessToken` helper that mints a cnf-bound `at+jwt` access
  token signed with the OP's keyset. The handler-owned cnf binding
  contract is documented on the public type — the dispatcher writes
  `resp.AccessToken` verbatim and the handler is responsible for
  embedding `cnf` when the request carries DPoP / mTLS proof.
  Openid-scoped custom grants emit an id_token signed from
  `ExtraClaims` after reserved-claim filtering.
- `op.WithDeviceCode(...)` (RFC 8628) wires the OP for
  device-authorization grant: `/device_authorization` endpoint,
  token-endpoint dispatcher honoring `authorization_pending` /
  `slow_down` / `access_denied` / `expired_token`, and discovery
  advertise of `device_authorization_endpoint` +
  `urn:ietf:params:oauth:grant-type:device_code` in
  `grant_types_supported`. The `DeviceCodeStore` substore ships in
  the in-memory adapter; `op/storeadapter/{sql,redis}` follow in
  v0.9.2.
- `op/devicecodekit` (new public sub-package) ships two embedder
  helpers around the RFC 8628 verification page that the OP itself
  never invokes (the verification UI lives in the embedder per
  `op/interaction`):
  - `devicecodekit.VerifyUserCode(ctx, deps, deviceCodeID,
    submittedUserCode)` runs the per-record brute-force gate: it
    canonicalises the submitted code, constant-time-compares it
    against the stored `UserCode`, increments the strike counter on
    mismatch, and transitions the record to Denied with reason
    `"user_code_lockout"` after `devicecodekit.MaxUserCodeStrikes`
    submissions (5). `op.AuditDeviceCodeUserCodeBruteForce` fires on
    every strike; `op.AuditDeviceCodeVerificationDenied` fires on the
    lockout transition. Submissions to a non-Pending record return
    `ErrAlreadyDecided` without further side effects.
  - `devicecodekit.Revoke(ctx, deps, deviceCodeID, reason)` wraps
    `store.DeviceCodeStore.Deny` with the new
    `op.AuditDeviceCodeRevoked` audit event. The wire-shape change is
    a no-op (the existing `Deny` already transitions Pending →
    Denied, and the next `/token` poll already returns
    `access_denied`); the audit signal is the new piece. Embedders
    who hold the user-trust posture "when a device authorization is
    revoked, every access token issued from that device_code is
    revoked alongside the row" subscribe to
    `AuditDeviceCodeRevoked`, read the `device_code_id` extra, and
    call `store.AccessTokenRegistry.RevokeByGrant(deviceCodeID)`
    (the device_code's ID is stamped verbatim onto the GrantID
    column of every issued access token at `Consume` time, so the
    existing per-grant cascade is sufficient). v0.9.1 ships the
    audit signal only; the library-side cascade walk (an
    `IssuedAccessTokens(deviceCodeID) []string` substore extension
    + an OP-side `RevokeByGrant` driver) is a v0.9.2 design task
    tracked alongside the SQL / Redis substore wiring deferred from
    v0.9.0.
- `op.WithPairwiseSubject(salt)` and `op.WithSubjectGenerator(...)`
  (ADR 0029) add OIDC Core §8 pairwise subject derivation
  and an extensible generator seam. `internal/sector` resolves
  `sector_identifier_uri` with HTTPS-only enforcement, RFC 1918 /
  loopback / link-local rejection, redirect-target re-validation,
  body-size + timeout caps, and a 24 h success cache. Mid-life
  switching of the subject strategy is rejected at `op.New` to
  prevent silently re-keying issued grants. Discovery now publishes
  `["public", "pairwise"]` in `subject_types_supported` whenever
  `WithPairwiseSubject` is active, and the subject projector
  dispatches per-client on `Client.SubjectType` so public-typed
  clients keep their UUIDv7 sub when the OP is mixed-mode.
- `mtls_endpoint_aliases` is now published under the MTLS feature so
  embedders running mTLS behind a reverse proxy can advertise the
  alias set defined in RFC 8705 §5.
- `acr_values_supported` is now publishable via
  `op.WithACRValuesSupported(values ...string)` so deployments that
  honor explicit ACR values (FAPI, eIDAS, NIST 800-63) advertise
  them in discovery without overriding the full document.
- `op.WithDiscoveryMetadata(map[string]any)` lets embedders extend
  the discovery document with non-OIDC keys (federation, custom
  registration metadata) at op.New time.
- DCR mount accepts `post_logout_redirect_uris` in inbound RFC 7591
  client metadata; the values flow into the seeded
  `Client.PostLogoutRedirectURIs` and are echoed back by the
  registration response and management endpoint.
- `audit.client_authn.failure` event fires from `/token` and `/par`
  whenever client authentication rejects (wrong secret, expired
  assertion, alg mismatch, missing `private_key_jwt`). Mirrors the
  existing introspection / revocation auth-failure events.
- `audit.introspection.error` event fires when an inbound token
  introspection request fails client authentication, completing the
  cross-endpoint authn-failure audit surface.
- `op.PtrBool(v bool) *bool` is a small generic helper for the
  pointer-to-bool opt-in pattern the public API uses for
  unambiguously-tri-state fields (e.g. `TokenExchangeDecision.IssueRefreshToken`
  defaults to nil = no refresh token, must be `op.PtrBool(true)` to
  opt in).
- `op.AuditTokenExchangeSubjectTokenRegistryError` event fires when
  the in-tree RFC 8693 handler observed a non-NotFound fault from
  `store.AccessTokenRegistry` while looking up subject_token /
  actor_token. The wire response stays `invalid_grant`; this event
  splits transient registry outages from real revocations so SOC
  tooling can react separately.
- CIBA poll mode. The OP now exposes the
  Client-Initiated Backchannel Authentication endpoint
  (`/oidc/bc-authorize`) and accepts
  `urn:openid:params:grant-type:ciba` at the token endpoint.
  Push and ping delivery modes are deferred to v2+; only poll
  mode ships in v0.9.1. Public surface:
  - `op.WithCIBA(...)` registers the CIBA substore and the
    `HintResolver` seam (login_hint / login_hint_token / id_token_hint
    → internal subject). The option is required to enable CIBA; the
    endpoint and grant_type stay off by default. Authentication-device
    response (approve / deny) is delivered out-of-band by the
    embedder calling `store.CIBARequestStore.Approve` /
    `Deny` directly from the authentication device's callback handler;
    the OP never pushes to the authentication device itself
    (`examples/32-ciba-pos/` shows the substore-direct shape).
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
  - `examples/32-ciba-pos/` ships a paired OP+RP demo (POS terminal
    initiates `/bc-authorize`, the staff phone approves,
    end-to-end in roughly one second).
- New paired OP+RP example demos covering the new grants and
  subject mode:
  - `examples/30-custom-grant/` — embedder defines
    `urn:example:libraz:service-token-exchange`, the OP routes it via
    `op.WithCustomGrant`, and the handler returns a `BoundAccessToken`
    so the dispatcher mints a JWT access token bound to the
    request's DPoP / mTLS confirmation.
  - `examples/31-device-code-cli/` — terminal CLI drives the
    RFC 8628 device-authorization grant against the OP, prints the
    boxed user_code panel + `verification_uri_complete` shortcut,
    and polls `/token` honoring `slow_down` and
    `authorization_pending`.
  - `examples/33-token-exchange-delegation/` — frontend →
    service-a → service-b cross-client impersonation triggers the
    OP-side `act` claim chain (ADR 0028); service-b's RS-side
    verifier walks `act.sub` and accepts only delegated tokens.
  - `examples/34-pairwise-saas/` — `WithPairwiseSubject`
    salt with two tenants in distinct sectors observes `A != B`
    (different sector → different sub) and `A1 == A2` (same
    sector + same user → identical sub), satisfying both the
    privacy and determinism properties of OIDC Core §8.1.
- JWE encryption (ADR 0030). The OP now decrypts JWE-shaped
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
    allowlist (`RSA-OAEP-256` / `ECDH-ES{,+A128KW,+A256KW}` ×
    `A{128,256}GCM`). `RSA-OAEP-384` / `RSA-OAEP-512` are deferred
    (go-jose v4.1.x exposes no constants for them; ADR 0030 amended
    2026-05-04). `RSA1_5` is intentionally not shipped
    (CVE-2017-11424 padding oracle); `dir` and symmetric-only `A*KW`
    are reserved for v2+.
  - Discovery now publishes `id_token_encryption_alg_values_supported`
    / `_enc_values_supported`, the userinfo / request_object /
    authorization (JARM) / introspection counterparts, and gates each
    on the corresponding feature flag (JAR / JARM / Introspect).
  - `userinfo_signing_alg_values_supported` is now published
    unconditionally (`ES256`); the JWT-shape userinfo path is
    always available via `Accept: application/jwt`.
  - `examples/35-encrypted-id-token` ships a paired OP+RP demo of
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
  resolver consults at the head of the priority chain (before
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
- `op.WithAllowInsecureBackchannelLogoutForDev(true)` is a new
  dev / CI-only opt-in that admits plain-http URLs whose host is a
  loopback identity (`127.0.0.1`, `[::1]`, `localhost`) for the
  `backchannel_logout_uri` client-metadata field. The default posture
  continues to enforce the OIDC Back-Channel Logout 1.0 §2.2
  https-only rule for every other host. `op.New` emits a loud
  audit-stream warning when the flag is set so the opt-in cannot
  silently survive a promotion to production. Both the static-client
  validator and the DCR registration path honour the carve-out.
- First-party clients registered via `op.WithFirstPartyClients(...)`
  now skip the consent prompt automatically when an active session
  exists and the request did not carry `prompt=consent`. The OP mints
  the authorization code silently, upserts the consent grant on the
  user's behalf, and emits the new
  `op.AuditConsentGrantedFirstParty` audit event
  (`"consent.granted.first_party"`) so SOC tooling can correlate
  every auto-grant with the matching code mint. Dynamic-client
  registrations are excluded; the gate also respects
  `prompt=consent` as a per-request override that forces the
  prompt regardless of the first-party list.
- Discovery's `ui_locales_supported` now falls back to every locale
  the runtime resolver knows (seed bundles + `WithLocale(...)`) when
  `DiscoveryMetadata.UILocalesSupported` is empty. Embedders who ship
  internal-only locales still hide them via `WithDiscoveryMetadata`.

### Changed

- **Breaking**: `store.DeviceCodeStore.RecordPoll` now takes
  `nextInterval time.Duration` and persists it atomically alongside
  `LastPolledAt`. The token endpoint passes the doubled value on a
  slow_down decision so the substore row reflects the elevated bar
  the next poll's gate compares against (RFC 8628 §3.5: "If the
  interval is more than 5 seconds, the client MUST honor the new
  value"). Out-of-tree adapters MUST update to honor the slow_down
  ladder; otherwise a malicious device can keep polling at the
  original cadence indefinitely. The reference inmem adapter is
  updated; SQL / Redis adapters land in v0.9.2 and pick up the
  new contract there.
- DCR (RFC 7591) JWE alg/enc validation across all five
  encrypted-response client metadata families (id_token / userinfo /
  request_object / authorization / introspection) now routes through
  `internal/jose.ParseJWEAlg` / `ParseJWEEnc` instead of a hard-coded
  local list. Future allowlist edits to the JOSE wrapper propagate
  automatically; out-of-tree DCR drivers that bypass the validator
  now share the same source of truth.
- DCR registration also rejects half-pair alg/enc submissions
  (e.g. `id_token_encrypted_response_alg=RSA-OAEP-256` without
  `_enc`) with `invalid_client_metadata` instead of admitting at
  registration and failing the first encrypted response at runtime.
  Both-empty still admits (the client opts out of encryption for
  that response type).
- CIBA `/bc-authorize` hardening:
  - Under `profile.FAPICIBA` a `requested_expiry > 600s` is now a
    hard `invalid_request` (FAPI-CIBA-ID1 §5 / FAPI 2.0 §3.1.9
    ten-minute cap). Vanilla CIBA keeps the existing silent-clamp
    posture.
  - The endpoint now validates each requested `acr_values` entry
    against the OP's published `acr_values_supported` list whenever
    the list is non-empty (`op.WithACRValuesSupported(...)`). An
    empty advertised list keeps the legacy permissive posture.
  - The endpoint now rejects a non-empty `user_code` parameter when
    discovery advertises `backchannel_user_code_parameter_supported=false`
    (the v0.9.1 default). Closes the silent admit-then-stamp gap.
- Custom-grant dispatcher (`op.WithCustomGrant(...)`) now rejects a
  non-empty `CustomGrantResponse.RefreshToken` with `server_error`.
  Lineage-tracked persistence + rotation for handler-issued refresh
  tokens needs design work that doesn't fit v0.9.1; until then the
  field SHOULD be left empty. The in-tree token-exchange handler is
  exempt — its grant_type URN is checked before the gate fires.
- Pairwise mid-life subject-strategy gate now also probes a new
  `__op_init` sentinel in the metadata substore so a re-used store
  whose subject-mode marker was wiped (manual cleanup, truncate)
  still rejects a non-public switch on the next `op.New` call. The
  sentinel is written on every successful construction so
  truly-fresh installs are unaffected.
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
- JAR `AllowMissingJTI` stays at `true` for every profile, FAPI
  profiles included (ADR 0032 amends ADR 0016). RFC 9101 §6.1 marks
  `jti` OPTIONAL on the wire and FAPI 2.0 Security Profile / FAPI 2.0
  Message Signing do not promote it to MUST; the §10.8 replay-defence
  floor is preserved through the JTIs store, which the verifier still
  consumes for every `jti` it does see. An embedder that needs the
  strict reading can still construct the verifier directly with
  `AllowMissingJTI=false`.
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
  authentication-flow, risk-evaluation, and audit-emission
  responsibilities moved into
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
- Example 04-i18n-locale now runs an in-process self-verify probe
  before the listener starts so `go run -tags example` prints a
  PASS / FAIL summary for each row of the locale-resolver chain.
- Example 10-react-login's SPA stamps the OP-resolved locale onto
  `document.documentElement.lang` on every prompt render.
- Example 15-custom-interaction now ships a thin locale-aware Driver
  wrapper that copies `Prompt.Locale` into the `Content-Language`
  response header, demonstrating the embedder pattern.
- Examples 04 / 05 / 06 now carry the standard `PRODUCTION CAVEATS`
  block (signing-key persistence, store durability, secret-source
  guidance) so the example tree's safety posture is uniform.
- `op.WithDPoPNonceSource` and `internal/authn/totp.Verifier.Verify`
  godoc spell out the multi-replica deployment expectation
  (distributed nonce / TOTP store required when running > 1 OP
  process).
- `profile.RequiredAnyOf` now documents and pins an order contract:
  the first element of each disjunctive set is the canonical default
  the option layer auto-enables when no member of the set is already
  configured. For the FAPI 2.0 family this means
  `WithProfile(FAPI2Baseline)` alone now activates DPoP without
  further wiring; an embedder who picks mTLS via
  `WithFeature(feature.MTLS)` keeps DPoP suppressed regardless of
  whether mTLS is layered before or after `WithProfile`. The
  defaulting pass runs after every option has been applied so the
  ordering between `WithProfile` and `WithFeature` is observably
  irrelevant.
- The CORS origin allowlist now admits the canonical origin of every
  static-client `redirect_uri` automatically, so a SPA that POSTs to
  `/token` from its callback page no longer needs to repeat the
  origin in `WithCORSOrigins`. Non-web schemes (custom-scheme
  native-app callbacks) are skipped silently. Dynamic-client
  registrations continue to flow through `WithCORSOrigins` only.

### Fixed

- Refresh-token rotation now preserves the original authorization-time
  `nonce` across every chained id_token issuance. OIDC Core §12 makes
  the nonce echo mandatory on refresh-issued id_tokens; the prior path
  dropped the value during the rotation copy.
- `client_secret_basic` credentials sent on `/token` and `/par` are now
  form-url-decoded per RFC 6749 §2.3.1 / Appendix B before constant-time
  comparison. Clients whose `client_id` or `client_secret` contained
  reserved characters (`:`, `+`, percent-escapes) previously rejected
  with `invalid_client` despite presenting the correct credential.
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

[Unreleased]: https://github.com/libraz/go-oidc-provider/compare/v0.9.1...HEAD
[v0.9.1]: https://github.com/libraz/go-oidc-provider/compare/v0.9.0...v0.9.1
[v0.9.0]: https://github.com/libraz/go-oidc-provider/releases/tag/v0.9.0
