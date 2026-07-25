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
# v1.0.0 (latest)
go get github.com/libraz/go-oidc-provider@v1.0.0
go get github.com/libraz/go-oidc-provider/op/storeadapter/sql@v1.0.0
go get github.com/libraz/go-oidc-provider/op/storeadapter/redis@v1.0.0

# v0.9.5
go get github.com/libraz/go-oidc-provider@v0.9.5
go get github.com/libraz/go-oidc-provider/op/storeadapter/sql@v0.9.5
go get github.com/libraz/go-oidc-provider/op/storeadapter/redis@v0.9.5

# v0.9.4
go get github.com/libraz/go-oidc-provider@v0.9.4
go get github.com/libraz/go-oidc-provider/op/storeadapter/sql@v0.9.4
go get github.com/libraz/go-oidc-provider/op/storeadapter/redis@v0.9.4

# v0.9.3
go get github.com/libraz/go-oidc-provider@v0.9.3
go get github.com/libraz/go-oidc-provider/op/storeadapter/sql@v0.9.3
go get github.com/libraz/go-oidc-provider/op/storeadapter/redis@v0.9.3

# v0.9.2
go get github.com/libraz/go-oidc-provider@v0.9.2
go get github.com/libraz/go-oidc-provider/op/storeadapter/sql@v0.9.2
go get github.com/libraz/go-oidc-provider/op/storeadapter/redis@v0.9.2

# v0.9.1
go get github.com/libraz/go-oidc-provider@v0.9.1
go get github.com/libraz/go-oidc-provider/op/storeadapter/sql@v0.9.1
go get github.com/libraz/go-oidc-provider/op/storeadapter/redis@v0.9.1

# v0.9.0 (initial public release)
go get github.com/libraz/go-oidc-provider@v0.9.0
go get github.com/libraz/go-oidc-provider/op/storeadapter/sql@v0.9.0
go get github.com/libraz/go-oidc-provider/op/storeadapter/redis@v0.9.0
```

## [v1.0.0] — 2026-07-25

The first release under strict Semantic Versioning. From here the public `op`
surface changes only on a major version, with one stated exception: symbols
carrying an experimental stability marker, which are listed in the API surface
manifest and gated mechanically so the exemption cannot grow silently.

The release itself is a hardening and durability pass across the token
endpoint, the storage layer, and construction-time validation. The
authorization-code, refresh, CIBA, and device-code flows stage their fallible
work behind transactions and single-use compare-and-swaps, so an approved
ceremony survives a signing or persistence fault; back-channel logout fans out
through keyset-paginated grant lookups; and `op.New` rejects a far wider class
of misconfiguration up front. No new protocol surface.

Several store-interface and construction changes are breaking for custom store
implementations — see `Changed` for the migration notes. They are the last such
changes that can land outside a major version.

Signing is ES256 only, permanently for the 1.x line, and the reasoning is
documented rather than left as a gap. Deployments needing RS256 or PS256 should
not adopt this release.

### Added

- `Provider.LocaleResolver().Message(...)` exposes read-only lookup of the
  merged message catalogue for custom server-rendered pages and out-of-band
  UI. Missing keys fall back to the configured default locale; the returned
  string is plain text, so non-HTML callers retain control of output encoding.
- `op.AuditEventCatalog`, a copy-safe public inventory of every stable audit
  event and its optional Prometheus projection. The same typed registry now
  drives in-tree emitters and the metrics bridge. Logout persistence failures,
  back-channel resolution/overflow, DCR cascade failures, device poll
  observation faults, and custom-grant outcomes are included in the catalog
  and counters.
- `store.StaticClientReconciler`; `WithStaticClients` now applies the entire
  configured set as one atomic, idempotent batch (insert missing, no-op on
  equivalent records, `ErrConflict` on divergent or non-static rows). The
  reconciliation runs only after every other fallible build step, so a failed
  `op.New` never leaves partial client records behind. Implemented in the SQL
  and in-memory adapters.
- `store.DeviceCodeStore.Revoke` and the public `devicecodekit.Revoke` helper.
  `Revoke` atomically transitions pending and approved device-code records to
  denied so a later `/token` poll cannot issue credentials, while the helper
  cascade-revokes every credential surface sharing the device grant lineage
  per the configured `RevocationStrategy` and emits an `AuditDeviceCodeRevoked`
  event. Implemented in the in-memory and SQL adapters.
- `store.RefreshRetryResponseStore` persists an already-sealed refresh response
  against its consumed predecessor so the OP can re-emit the exact response on
  the RFC 9700 grace path instead of branching the token chain; the SQL adapter
  stores it in a new `retry_response` column written atomically with the
  successor.
- `RevokeByClient` cascade on the access-token and opaque-access-token
  substores (with the matching SQL queries), so a client-scoped revocation
  reaches every issued token.
- Redis `store.SessionStore` — session state backed by the Redis adapter and
  bound to the Redis TTL (compose it with a durable backend for grants and
  credentials).
- A strict OFCS release verifier, separate from the historical regression
  diff. It rejects persistent non-PASS results, empty results, module-catalog
  drift, and stale or expired exceptions; the only accepted exceptions are
  exact entries in a clean, checked-in owner/reason/expiry manifest.
- `api/experimental.txt`, the machine-generated inventory of every symbol
  carrying an `Experimental:` marker. The marked set is the SemVer exemption
  list and everything else is stable by default, so the report is regenerated
  and diffed by `make verify`: a change to the exempt surface now arrives as a
  reviewable diff next to the code that caused it. A marker without a
  rationale, or a symbol claiming both `Experimental:` and `Stable since`, is
  rejected rather than resolved silently toward exempt.
- `sample/`, a reference application covering the arc the single-concept
  examples skip: registration owned by the application, Argon2id password
  storage, login and consent through a `interaction.Driver` the application
  implements itself, TOTP enrolment from account settings, and a relying party
  completing the round-trip — on MySQL plus Redis joined by
  `op/storeadapter/composite`, under one `docker compose up`. Its consent page
  is a worked example of granular per-scope consent, which the bundled HTML
  driver declines to offer. It is a demonstration, not a deployment: the schema
  is one embedder's model rather than a recommendation, and the application is
  not meant to be hosted.
- `cmd/op-demo` accepts `-store=composite` with MySQL and Redis DSNs, so an
  OFCS baseline can be captured against the storage shape a deployment runs
  rather than against memory. It became its own Go module in the process, which
  keeps both drivers out of every library consumer's dependency graph.

### Changed

- **BREAKING — `op.New` now rejects a configuration where the `refresh_token`
  grant is enabled and cookie keys are set but `Store.RefreshTokens()` does not
  implement `store.RefreshRetryResponseStore`.** The rotation path seals a
  durable retry response whenever it holds encryption keys, and those keys are
  the cookie keys the `authorization_code` grant already makes mandatory, so a
  bring-your-own refresh store without the extension compiled, passed `op.New`,
  served authorization requests, and then failed every rotation at request
  time. *Migration:* implement `RefreshRetryResponseStore`; the bundled
  adapters already do, so only external backends are affected — and those were
  already failing rotation. The store package now states the capability
  placement rule normatively and publishes the requirement matrix it implies,
  covering both the extensions `op.New` demands and the ones that degrade
  silently.
- ES256 is the only supported token-signing algorithm, and that is now a stated
  permanent policy for the 1.x line rather than an unfilled gap. The discovery
  document, the conformance exclusion manifest, and the documentation all say
  so; RS256 and PS256 are not planned.
- **BREAKING — authorization-code stores must now implement
  `store.Transactional`, and their interaction substore must implement
  `store.InteractionStoreCAS` (`CompareAndSwap` and `DeleteIfUnchanged`).**
  Authorization completion persists an immutable retry intent, commits
  Grant / PAR / authorization-code mutations together, establishes the Session
  idempotently, and deletes the interaction last; silent and first-party
  auto-consent mints use the same transaction boundary. *Migration:* BYO stores
  that enable `grant.AuthorizationCode` must add a real `BeginTx`
  implementation and atomic expected-`RawState` interaction transitions; the
  SQL, in-memory, and `examples/26-byo-store-from-scratch` implementations are
  references. Transaction-bound Grant reads must lock rows, use serializable
  isolation, or surface an equivalent optimistic conflict before Save so
  concurrent scope/RAR merges cannot lose updates.
- **BREAKING — `store.GrantStore` now requires
  `ListClientIDsBySubject(ctx, subject, cursor, limit)`.** Back-channel logout
  uses this distinct, keyset-paginated view to bound both grant query results
  and client-registry lookups before target resolution, pulling one bounded
  page per notice and emitting an overflow event with the next cursor instead
  of scanning every grant row; it advertises
  `backchannel_logout_session_supported: false` since grant-based fan-out
  retains no RP-specific session lineage. `ListClientIDsBySubject` lives on a
  new optional `store.GrantClientLister` extension, so machine-to-machine
  backends that never mount the browser `authorize` / `end_session` endpoints
  need not implement it; `op.New` rejects an interactive configuration whose
  `GrantStore` lacks it. *Migration:* implement a stable ascending client-ID
  query returning at most `limit` IDs plus `NextCursor` when another page
  exists — do not delegate to `ListBySubject` and slice its full result. The
  in-memory, SQL, and `examples/26-byo-store-from-scratch` adapters show the
  required semantics.
- **BREAKING — trusted-proxy mTLS certificate headers now accept exactly one
  field containing one raw or percent-encoded `CERTIFICATE` PEM block.**
  Duplicate fields, PEM chains, and trailing non-whitespace data are rejected
  as `ErrCertMalformed` instead of silently selecting the first certificate.
  The forwarded certificate is no longer compared with the handshake leaf: on
  dual-mTLS / mesh hops the handshake leaf identifies the proxy transport, so a
  mismatch is the normal topology, not an attack. *Migration:* configure the
  TLS terminator to strip the inbound header and forward only the verified
  OAuth client leaf.
- **BREAKING — account-lockout state moves to a versioned
  `AuthnLockoutStore.CompareAndSwap` contract keyed on an opaque
  backend-managed `Version`,** replacing the earlier `StampLock` extension.
  Failure increment, window rollover, lock stamping, and success reset apply as
  one transition recomputed from the latest record until it commits, so
  parallel failures across factors cannot lose updates and a concurrently
  committed failure is never erased by a stale reset. *Migration:* BYO lockout
  stores must implement `CompareAndSwap`; the in-memory reference and the
  reusable adapter contract show the semantics.
- **BREAKING — passkey stores must now implement
  `store.PasskeyStore.UpdateAssertion` (`PasskeyAssertionUpdate`),** which
  commits sign-count, clone-flag, and last-used fields as one atomic write
  instead of a whole-record `Put` that could rewind security state. *Migration:*
  BYO passkey stores add `UpdateAssertion`; the in-memory reference implements
  it.
- **BREAKING** — an `EncryptionKey`'s `NotAfter` is now a hard retirement
  deadline: on or after it the OP refuses to decrypt for that `kid` and drops
  the public half from the published JWKS, so RPs are never directed to a
  recipient the OP can no longer decrypt for.
- The zero-configuration `interaction.HTMLDriver` now consumes the same locale
  resolver as `/authorize`: `WithLocale` additions and overlays are reflected
  in password-page titles, labels, and submit buttons; untranslated keys retain
  the built-in English fallback, and all translated output is HTML-escaped at
  emission.
- **BREAKING** — the token-endpoint transaction view (`Tx`) gains
  `AccessTokens`, `OpaqueAccessTokens`, and `GrantRevocations`, and the TOTP
  and email-OTP substores gain `CompareAndSwap` (with an in-memory
  implementation); BYO stores backing these surfaces must implement the new
  members.
- The lax OIDC Core 1.0 §11 reading of `offline_access` (an `openid`-only grant
  may refresh) is the default and is now applied consistently to the
  authorization-code issuance path as well as the refresh exchange;
  `offline_access` is required only under `op.WithStrictOfflineAccess`.
- Endpoints now mount under the issuer URL path: an issuer like
  `https://idp.example.com/tenant` serves the token endpoint at
  `/tenant/oidc/token` and matching paths for every protocol handler, with the
  `.well-known` suffix placed before the issuer path per OpenID Connect
  Discovery 1.0 so advertised and mounted URLs agree. `Endpoints` overrides are
  validated as clean absolute paths at construction (query strings, fragments,
  duplicate slashes, percent-encoding, and wildcard syntax are rejected).
- Back-channel logout deliveries dispatch through a bounded worker pool
  (`DefaultMaxConcurrentDeliveries`) with the deduplicated audience capped at
  `DefaultMaxTargets`; the HTTP deliverer adopts only an embedder client's
  `Transport`, keeping redirect, timeout, and dial-time SSRF policy mandatory.

### Security

- Passkey `AAGUIDAllowlist` is enforced against an authenticated AAGUID.
  Previously `PrimaryPasskey` requested no attestation at all, so the AAGUID the
  allowlist compared was a plain field of the registration response rather than
  something the hardware proved — a software authenticator could register by
  naming an approved model. Configuring an allowlist now switches the ceremony
  to `direct` conveyance, and a registration whose attestation does not identify
  the model (self-attested or unattested) is refused instead of being matched
  against the list. **BREAKING** at the `passkey.Config` level: pairing
  `AAGUIDAllowlist` with any conveyance other than `direct` is now a
  construction error. Embedders using `op.PrimaryPasskey` need no change beyond
  expecting a user-agent attestation prompt during registration; leave
  `AAGUIDAllowlist` empty to keep the previous prompt-free ceremony.
- mTLS proxy header: a payload carrying more than one PEM block is rejected by
  counting block markers before decoding, rather than by checking what the PEM
  decoder reports as remaining input. The decoder skips a block whose base64
  body does not decode and returns the following block with an empty remainder,
  so a chain whose leading certificate was unparseable resolved to the trailing
  one — and a decoding step could produce that state on its own, because form
  decoding rewrites `+`, a base64 alphabet character, to a space and the PEM
  decoder strips spaces out of the body. Whoever composed the header could
  therefore choose which leaf the OP bound. Percent-decoding is now attempted
  before form-decoding so an unescaped payload is not rewritten at all.
- JAR: every URL-indexed JWKS cache is bounded with LRU-style eviction and
  expired-entry pruning, and a document carrying more keys than the parse cap is
  rejected, so hostile client registrations cannot grow process memory without
  bound.
- The remote client-resolver caches (client encryption JWKS and the
  sector-identifier resolver) share one size-bounded TTL/LRU primitive with
  per-key singleflight and negative caching, giving URLs controlled by clients a
  bounded entry count and a negative TTL.
- DPoP: the replay-protection record is namespaced by proof thumbprint
  (`dpop:<jkt>:<jti>`) so two distinct proof keys reusing one `jti` no longer
  collide, while a replay by the same key still surfaces as a replayed proof.
  The thumbprint is computed before the record is marked, preserving the
  malformed-proof-never-advances property.
- Authenticators: TOTP and email-OTP verification uses a `CompareAndSwap` retry
  loop so concurrent wrong-code attempts each advance the brute-force counter
  instead of a stale writer clobbering the winning state; email-OTP resend
  reserves its challenge before invoking the mailer so a racing resend cannot
  reuse a stale rate-limit snapshot.
- Sender-constraint (DPoP / mTLS) checks and revocation checks now run ahead of
  the single-use `Consume` on the refresh exchange and are fail-closed before a
  fresh access token is minted.
- Token exchange enforces the OIDC Core required claim set (`iss`, `sub`, `aud`,
  `exp`, `iat`) with time bounds when a `subject_token` is an ID token — so the
  mandatory source-token TTL cap always has a live `exp` — and decodes `aud` in
  both RFC 7519 shapes, rejecting missing, empty, or malformed values as an
  invalid token.
- Redact MySQL and Redis connection credentials from the storage examples'
  startup diagnostics. The Redis adapter now also returns a generic parse error
  for malformed DSNs, so an invalid percent-encoded credential cannot be copied
  into an error message; `oidcredis.RedactedDSN` provides the same structural,
  fail-closed representation for embedder logs.
- Harden `op.LoadPublicJWKS` into a public-member allowlist normalizer:
  symmetric `oct` and unsupported key types are rejected, while RSA, EC, and
  OKP inputs retain only their key-type public parameters and standard public
  JWK metadata. Private and unknown extension members can no longer survive by
  falling outside a private-parameter denylist.

### Fixed

- Refresh exchange (RFC 9700 grace path): post-preflight mutations are staged
  behind a transaction and the buffered response is forwarded only after commit,
  so a signing, JWE, cache, or write failure rolls `Consume` back instead of
  stranding the predecessor token. With a retry-response cache configured, a
  bearer grace retry re-emits the exact sealed response from the original
  rotation. A sender-constrained (DPoP / mTLS) grace retry re-mints the access
  token bound to the key the retry presents — a confidential client may rotate
  its DPoP key across refreshes (RFC 9449 §5), and replaying the originally
  bound token would hand back one the client can no longer use, failing every
  resource call with a `cnf` thumbprint mismatch — while re-emitting the
  original successor refresh token, so the chain is never rotated twice.
- CIBA and device-code polls assemble the fallible token bundle (signing plus
  opaque/refresh persistence) before the single-use `Consume` CAS; a poll that
  loses the CAS discards its pre-persisted credentials, so an approved ceremony
  is no longer lost to a signing or persistence fault while single-use is
  preserved.
- Preflight RFC 9396 `authorization_details` against the live Grant before the
  refresh `Exchange` consumes the predecessor token (the token snapshot stays
  the fallback for missing or sparse grants), sharing one transactional view
  with the later `Consume` so a concurrent grant-management update cannot turn a
  valid request into a rejection that strands the predecessor.
- Project the originating `GrantID` from opaque access-token records into the
  synthetic `/userinfo` claims so pairwise subject configurations recover the
  OP-internal subject; a legacy opaque record without a `GrantID` is rejected
  under pairwise projection instead of serving a wrong subject.
- Client registration rejects a `redirect_uris` or `post_logout_redirect_uris`
  entry carrying a bare trailing `#`. RFC 6749 §3.1.2 forbids a fragment
  component and an empty one is still a fragment; testing the parsed fragment
  admitted it, leaving a registered value a user agent truncates before the OP
  ever sees it, so the stored URI could never equal the one presented at
  `/authorize`. Registrations using that shape now fail with
  `invalid_redirect_uri` instead of succeeding into an unusable state.
- Dynamic client registration: map an explicit JSON `null` in optional metadata
  to the same empty value as an omitted property (RFC 7592 deletion) so
  `jwks: null` never reaches the JWK parser as a malformed set, reject
  `backchannel_logout_session_required` since the grant model retains no
  client-specific session lineage, and emit typed audit events when a
  delete-cascade revocation probe fails instead of dropping the fault.
- Passkey assertion state (sign-count, clone-flag, last-used) commits as one
  atomic write stamped from the exact record the signature was verified
  against, so concurrent assertions keep counters monotonic instead of a
  whole-record `Put` rewinding security state.
- Reject typed-nil login-flow, authentication, interaction, clock, and JWE
  private-key dependencies during `op.New` validation, distinguishing an absent
  nil interface (documented default) from an explicitly supplied typed nil, and
  validate configured endpoint paths for route collisions — configuration
  errors now surface before metrics registration, route construction, store
  writes, or an `http.ServeMux` panic.
- Bound in-memory refresh-token revocation by client or grant to the matching
  token set via client-ID and grant-ID secondary indexes under the refresh
  store's existing lock and transaction boundary, avoiding full token-map scans
  during DCR deletion and grant revocation without changing retained-record or
  replay semantics.
- The end-session handler records session-destroy, token-revoke, and
  back-channel resolution failures as distinct audit events while keeping the
  browser response non-blocking; `RevokeJWTAccessTokensByGrant` now returns
  store errors and the grant-management revoke path treats them fail-closed.
- Origin canonicalisation re-brackets a literal IPv6 host. `url.URL.Hostname`
  strips the brackets, so an issuer or configured origin using an IPv6 literal
  canonicalised to `http://::1:8080` — a form no browser sends — and never
  matched the incoming `Origin` header, rejecting every state-changing
  same-origin request and the CORS allowlist derived from the same value.
- Redis adapter: `WithKeyPrefix` and `WithMaxValueBytes` now surface an option
  error at construction instead of being silently dropped.
- Corrected the public `grant.RefreshToken` and `ScopeNameOfflineAccess`
  documentation to match the historical issuance default: `openid` plus the
  client's `refresh_token` grant is sufficient, while requiring `offline_access`
  is an explicit `op.WithStrictOfflineAccess` opt-in. Runtime behaviour is
  unchanged.

## [v0.9.5] — 2026-07-13

A security-hardening release: no new protocol surface, but a broad sweep of
abuse-resistance and correctness fixes across PKCE enforcement,
`private_key_jwt` key selection, DPoP token binding, the authenticator chain,
PAR consume semantics, and session-cookie handling, plus a round of dependency
updates. One new option (`WithPARLifetime`) is added and one behaviour change is
breaking (PKCE is now mandatory for public and native clients).

### Added

- `op.WithPARLifetime` — override the lifetime of a `request_uri` issued by the
  PAR endpoint (RFC 9126 §2.2; default 60 seconds). Zero selects the default; a
  negative value is rejected at construction. The lifetime bounds only the
  presentation window at `/authorize` — the `request_uri` stays single-use at
  code emission, so an interactive login that outlives the lifetime still
  completes.
- A runnable durable SQL-backed `store.TOTPStore` example
  (`examples/27-durable-mfa-store`) as a copy-and-adapt template for the
  embedder-owned authentication-factor persistence gap, covered by contract and
  durability tests. Authentication-factor stores (TOTP, passkey, recovery codes,
  email OTP, lockout) are the embedder's responsibility; only the in-memory
  reference ships an implementation.

### Changed

- **BREAKING — PKCE (`code_challenge`) is now mandatory for public and native
  clients at `/authorize`, independent of the active profile.** A public or
  native client that omits `code_challenge` receives `invalid_request` at the
  authorization endpoint and no authorization code is issued; the OP never issues
  a non-PKCE code to these clients. *Migration:* register public and native
  clients with PKCE (S256). The token-endpoint PKCE downgrade guard remains as
  defense in depth.
- The `private_key_jwt` assertion verification key is selected by JWS `kid`
  (RFC 7515 §4.1.4), and trial verifications are capped whether or not a `kid` is
  present. `kid` uniqueness is unenforced, so a client serving many keys —
  including same-`kid`, same-`alg` duplicates — can no longer force one signature
  verify per key, bounding a DoS-amplification vector.
- Dependency updates: `go-webauthn/webauthn` v0.13.4 → v0.17.4,
  `golang-jwt/jwt/v5` v5.2.3 → v5.3.1, `golang.org/x/crypto` v0.53 → v0.54, and
  the SQL drivers (`go-sql-driver/mysql` v1.10.0, `jackc/pgx/v5` v5.10.0,
  `modernc.org/sqlite` v1.53). The unmaintained `mitchellh/mapstructure`
  dependency is replaced by the maintained `go-viper/mapstructure/v2` fork.

### Fixed

- Re-show the email-OTP verify prompt on a wrong code — preserving the delivered
  code — instead of restarting at the send screen, while still yielding to a
  pending captcha challenge.
- Honour the RFC 8252 loopback any-port allowance for `post_logout_redirect_uri`
  on native and public clients, matching `redirect_uri`.
- Surface a retryable, audit-visible error on TOTP and recovery
  compare-and-swap loss instead of silently re-prompting.
- Align the transactional in-memory PAR `Consume` — and the
  byo-store-from-scratch reference store — with the `PushedAuthRequestStore`
  contract: `Consume` enforces single-use only, and expiry is gated at
  presentation by `Find`, so an interactive login that outlives the `request_uri`
  lifetime still redeems exactly once. Pinned with a new transactional contract
  case so the implementations cannot drift.
- Equalise the `private_key_jwt` no-keys rejection timing with the
  wrong-signature path, and memoize the per-request client-store lookup during
  assertion verification (collapsing 2–4 `GetClient` calls into one).

### Security

- Reject DPoP-bound access tokens presented under the `Bearer` scheme at
  `/userinfo`; RFC 9449 §7.1 requires the `DPoP` scheme for sender-constrained
  tokens.
- Clear a tampered or undecodable session cookie at the authorization endpoint
  instead of carrying it forward.
- Reject private and symmetric keys during JWKS parsing; the prior type assertion
  was a no-op that let non-public key material through.
- Revoke the persisted opaque access-token row on every post-mint `server_error`
  path (id_token mint/encrypt failure, refresh-issuance failure, and the
  grant-tombstone mint refusal) via a shared helper, so no orphaned still-valid
  token lingers until TTL or GC.
- Raise the pinned Go toolchain to `go1.26.5` across the root module, the
  storage-adapter sub-modules, and CI to pick up the `crypto/tls` fix for
  GO-2026-5856 (Encrypted Client Hello privacy leak); the previously pinned
  `go1.26.4` is affected.

## [v0.9.4] — 2026-07-02

A security-hardening release: no new protocol surface, but a broad sweep of
correctness and abuse-resistance fixes across token exchange, mTLS binding,
the authenticator chain, refresh-token rotation, and the storage adapters.
Two device-grant options are added and the device-code lifetime is decoupled
from the access-token TTL (see Changed).

### Added

- `op.WithDeviceCodeExpiry` and `op.WithDeviceCodePollInterval` — the
  device-code lifetime and poll interval are now independent, configurable
  options defaulting to the device-grant defaults, instead of being derived
  from the access-token TTL.

### Changed

- **BREAKING — the device-code lifetime is decoupled from the access-token
  TTL.** The device flow previously derived its code lifetime and poll interval
  from the access-token TTL, so a short access-token lifetime made the device
  flow unusable. They now default to the device-grant defaults and are set
  independently via `WithDeviceCodeExpiry` / `WithDeviceCodePollInterval`.
  *Migration:* deployments that relied on a custom access-token TTL to size the
  device-code window must set the new options explicitly.
- **BREAKING — a non-zero refresh grace period is rejected under a FAPI 2.0
  profile at construction.** `op.New` now fails fast instead of silently
  allowing a refresh-token replay window that the FAPI 2.0 contract forbids.
  *Migration:* remove the refresh grace-period option from FAPI-profiled
  providers.
- The CIBA `binding_message` is validated (trim, length bound, control-character
  rejection) and persisted raw instead of HTML-escaped, so the authentication
  device shows the value the consumption device sent; the transaction-confirmation
  interlock is no longer broken for messages containing `& < > " '`.
- Strict-CORS responses now expose `DPoP-Nonce`, `WWW-Authenticate`, and
  `x-fapi-interaction-id` so a browser SPA can complete the DPoP nonce-retry loop.
- The unused `SubjectProjector` field on the authorize endpoint is removed;
  subject projection stays wired at the token, userinfo, and introspection
  endpoints.
- The Go toolchain is pinned to `go1.26.4` across the root module, the
  storeadapter sub-modules, and the examples, and the `golang.org/x/*`
  dependencies (`crypto`, `sync`, `sys`, `mod`, `net`, `text`, `tools`,
  `telemetry`) are bumped to their current patched releases.

### Fixed

- **Refresh replay-revocation race.** A rotation save can no longer outrun a
  concurrent chain revocation: the SQL adapter re-checks the parent under a row
  lock inside the rotation transaction, and the in-memory adapter performs the
  parent-still-alive check inside the same critical section as the insert. A
  replayed stolen refresh token's rotated descendant is now reliably revoked.
- Expired refresh tokens read as not-found on the SQL adapter, matching the
  in-memory adapter, so an expired-token replay no longer produces a false
  `replay_detected` audit and chain-revoke cascade.
- **mTLS token-binding collapse.** With a client-certificate forwarding header
  configured and a trusted proxy peer, the forwarded header certificate is
  authoritative for the `cnf` binding and a handshake/header thumbprint mismatch
  is rejected (`ErrCertSourceConflict`, 400 `invalid_request`) rather than
  silently binding the proxy's own certificate. `writeMTLSError` now maps
  `ErrCertUntrusted` to 401 `invalid_client` instead of falling through to 500.
- **`MinAAL` step-up enforcement** on the legacy authenticator chain:
  `RiskOutcome.MinAAL` is threaded from the risk assessor through the pre-factor
  consult into candidate selection, excluding authenticators below the required
  assurance level.
- The account-chooser (`select_account`) re-entry path seeds `acr` / `amr` /
  auth time from the selected session, so a chooser-only grant no longer
  downgrades to empty `acr` / nil `amr` in the id_token.
- The sector-identifier resolver evicts a stale entry on a content-hash change
  (a legitimately updated sector document recovers without an OP restart) and
  rejects a document with trailing bytes after the JSON array; pairwise
  sector-host derivation uses the URL hostname (port independent).
- The Redis chooser-group index key is given a TTL so abandoned sets no longer
  accumulate and evict live session keys under a volatile `maxmemory` policy.
- SQL table-name overrides are validated to be pairwise-distinct and
  non-colliding at construction, and the schema rewrite uses a single-pass
  exact-name substitution.
- `ConfidentialClient.TokenEndpointAuthSigningAlg` is now persisted by `seed()`;
  `WithMTLSProxy` config is stored on the provider config instead of a
  package-global map (no leak on hot-reload); the custom-grant clock access is
  nil-safe; and the kid-present JWE decrypt path gains the same alg/key-shape
  pre-check as its siblings.
- **RP key rotation for `private_key_jwt` clients that register a `jwks_uri`.**
  When a client-assertion is signed with a key whose `kid` is absent from the
  OP's cached copy of the client's `jwks_uri` keyset — the signal that the RP
  rotated its keys — the OP now performs a single cache-bypassing refetch and
  retries verification, instead of rejecting the assertion until the cache TTL
  lapses. The refetch is throttled per URL so an assertion replayed with random
  unknown `kid`s cannot amplify into unbounded outbound fetches.

### Security

- **Token-exchange down-scope invariant (RFC 8693).** The policy decision is
  re-verified after it is applied: the granted scope must remain a subset of the
  requested (subject-token-bounded) scope and the granted audience a subset of
  the requested audience. A broadening decision is rejected with `invalid_scope`
  / `invalid_target` plus an audit event, closing a privilege-escalation path
  where a policy bug could mint tokens for scopes or audiences the
  `subject_token` never carried. Subject-token audiences are normalised to the
  RFC 8707 canonical form before comparison.
- **2FA brute-force visibility.** TOTP, email-OTP, and recovery wrong-code
  branches route through the shared retry path, so a failure increments the
  counter and fires the observer, letting the captcha gate engage; the email-OTP
  delivery-failure branch is padded to stay constant-time.
- Audit events record a non-reversible fingerprint of the authorization code and
  refresh token instead of the raw secret.

## [v0.9.3] — 2026-06-14

### Highlights

- RFC 9396 Rich Authorization Requests, OAuth 2.0 Grant Management, and
  RFC 9728 protected-resource metadata land together: `authorization_details`
  is validated, persisted on the grant, and echoed on JWT access tokens and
  introspection; grants can be queried and revoked; and each registered
  resource advertises its protecting authorization servers.
- The SQL adapter now implements the device-code and CIBA substores, so
  `WithDeviceCodeGrant` / `WithCIBA` run on mysql / postgres / sqlite —
  previously these grants only worked on the inmem reference store.
- Refresh-token rotation now preserves the original authentication context
  (`auth_time`, `acr`, `amr`, `authorization_details`, and more), so
  refresh-derived id_tokens and JWT access tokens reproduce it faithfully.
- Client-supplied verification keys (`client_assertion` and JAR request
  objects) are now held to the OP key-shape floor — a breaking tightening
  for clients still signing with sub-floor keys (see Changed).

### Added

- **RFC 9396 Rich Authorization Requests.** `authorization_details` is
  accepted and validated against the `op.WithAuthorizationDetailTypes`
  registry at `/authorize`, `/par`, and `/token`, persisted on the grant,
  and echoed on JWT access tokens (RFC 9068 §2.2.3) and introspection
  (RFC 9396 §5, §10). Gated by the `RAR` feature flag; oversize requests are
  rejected as `invalid_request`, other malformed shapes as
  `invalid_authorization_details`.
- **OAuth 2.0 Grant Management** via `op.WithGrantManagement`: the
  `grant_management_action` / `grant_id` authorization parameters, the query
  and revoke endpoint, PAR push-time validation, and discovery advertisement.
- **RFC 9728 protected-resource metadata** via `op.WithProtectedResources`,
  served at the OP root well-known location per registered resource with the
  issuer stamped into `authorization_servers`.
- `op.StepUpChallenge` — builds the value of an RFC 9470 §3
  `WWW-Authenticate: Bearer` challenge (`error="insufficient_user_authentication"`
  plus `realm` / `acr_values` / `max_age`) for an embedder's resource server
  to return. The OP itself never emits the header; it honours the advertised
  `acr_values` / `max_age` when the client re-authorizes.
- `op/storeadapter/sql` device-code and CIBA substores, with new
  `oidc_device_codes` / `oidc_ciba_requests` tables across the three dialects,
  table-name overrides, and contract-harness coverage.
- `AuthnLockoutStamper` optional store extension (`StampLock`) — stamps
  `LockedUntil` atomically without a whole-row `Put`, closing the cross-factor
  lockout lost-update race. Stores that omit it fall back to `Get`+`Put`; the
  inmem reference implements it.
- `RefreshChainResolver` optional store extension — resolves hashed
  refresh-token pointers for the internal replay-cascade chain walk while the
  public `Find` / `Consume` lookups stay hash-only and constant-time.
- `jose.AssertJWEAlgKeyShape` and `jose.ParseJWKSet`, holding outbound JWE to
  the OP RSA floor and EC curve allow-list before encryption.
- `examples/25-byo-table-names` (remap every SQL adapter table to
  embedder-owned names) and `examples/26-byo-store-from-scratch` (implement
  the `Store` interface end to end without the bundled SQL adapter), both
  wired into the apiverify / browserverify harnesses.

### Changed

- **BREAKING — client verification keys held to the OP key-shape floor.**
  `client_assertion` keys (`internal/clientauth`) and JAR request-object keys
  (`internal/jar`) are now gated through `jose.AssertAlgKeyShape`
  (RFC 7518 §3.3 / RFC 8725 §3.2): RSA must be ≥ 2048 bits and the EC curve
  must match the declared `alg`. A sub-floor or curve-mismatched key is
  rejected as `ErrSigInvalid` rather than passed to go-jose under a laxer
  check. *Migration:* clients signing `client_assertion` or request objects
  with sub-2048-bit RSA or a mismatched EC curve must rotate to compliant keys.
- **BREAKING — `RefreshTokenStore.Consume` is now an atomic compare-and-set.**
  It must return the consumed record on `ErrAlreadyConsumed` so a replay
  cascade can revoke the whole chain (RFC 6749 §10.4); a
  `refresh.replay_detected` audit event is emitted before the best-effort
  revoke. *Migration:* custom `RefreshTokenStore` implementations must make
  `Consume` a CAS that yields the prior record on replay.
- **BREAKING — `store.RefreshToken` carries the authentication context.**
  New fields (`auth_time`, `acr`, `amr`, `authorization_details`,
  `subject_public`, `origin`, `access_token_extra`) and `RefreshTokenOrigin`
  thread through the inmem / sql / composite adapters with new
  `oidc_refresh_tokens` columns. *Migration:* SQL-backed stores must apply the
  new column migrations; custom stores must persist the new fields. Rows
  written before the `origin` field stay refreshable (empty origin).
- **BREAKING — static client seeds are validated against the active profile's
  allowed `token_endpoint_auth_method` set at construction.** Under a FAPI
  profile (`FAPI2Baseline` / `FAPI2MessageSigning` / `FAPICIBA`), whose
  conformant methods are `private_key_jwt` / `tls_client_auth` /
  `self_signed_tls_client_auth`, `op.New` now rejects a `WithStaticClients`
  seed that uses `none` or `client_secret_*` instead of accepting it. *Migration:*
  a FAPI deployment must seed only `private_key_jwt` / mTLS clients; move any
  public or `client_secret_*` clients out of the FAPI-profiled provider.
- **BREAKING — refresh-token `id` / `parent_id` are hashed at rest.** Public
  `RefreshTokenStore.Find` / `Consume` are now hash-only constant-time lookups;
  the internal chain walk resolves stored handles through the new optional
  `RefreshChainResolver`, and SQL schema validation rejects legacy (unhashed)
  refresh table shapes. *Migration:* SQL-backed stores must adopt the hashed
  refresh schema; custom stores must persist hashed ids and implement
  `RefreshChainResolver` for replay-cascade revocation.
- **BREAKING — one-time auth factors are single-use via atomic compare-and-set.**
  `emailotp` Consume, `totp` Accept, and `recovery` Consume now return
  `ErrAlreadyConsumed` on replay so a code cannot be accepted twice under
  concurrency. *Migration:* custom factor stores must make these CAS operations
  (the inmem reference shows the shape).
- **BREAKING — terminal factor failures now render HTTP 400, not 500.** Expired
  or consumed one-time codes, lockout, required reset, and too-many-resends are
  wrapped in the new `authn.ErrFactorAbort` sentinel, which the authorize
  endpoint maps to `400`. *Migration:* embedders keying off the prior `500` for
  these cases must handle `400`.
- `op.New` now rejects a nil `SessionStore` at construction when the grant set
  mounts the browser authorize endpoint, using the same predicate the runtime
  enforces (`validateStoreCapabilities`).
- Pre-issuance client authentication is consolidated into `endpointsupport`,
  matching the HTTP Basic scheme case-insensitively per RFC 7617.

### Fixed

- SQL table-name overrides now rename the metadata table in `rewriteSchema`.
  The rename pair was present in `applyOverrides` and `knownNamingKeys` but
  missing from the schema rewrite, so the query builder targeted the renamed
  table while `Migrate` created `op_metadata` under its default name — booting
  an override-configured store broken at the first query.
- Save-time garbage collection for the SQL and inmem device-code / CIBA
  substores, with zero-expiry preservation guards.
- Grant `ListBySubject` no longer collapses distinct rows that share a
  `(subject, client_id)` pair.

### Security

- One-time auth factors (email-OTP, TOTP, recovery codes) can no longer be
  accepted twice under concurrency: single-use is enforced by an atomic store
  compare-and-set returning `ErrAlreadyConsumed` on replay (race tests added).
- Closed a cross-factor account-lockout lost-update race via the atomic
  `StampLock` path, so concurrent failed factors cannot overwrite each other's
  `LockedUntil`.
- Refresh-token `id` / `parent_id` are hashed at rest and looked up in constant
  time, hardening against store-disclosure and timing side channels.
- Hardened the account-chooser add-account path with PAR-aware URL stamping and
  a forgery-resistant marker check.
- Bump `github.com/go-jose/go-jose/v4` to v4.1.4, fixing a JWE-decryption
  panic (GO-2026-4945) reachable wherever the OP decrypts JWE input.

## [v0.9.2] — 2026-05-24

### Highlights

- Refresh-token issuance for custom grants and RFC 8693 token-exchange
  is now wired into the OP's own refresh-token lineage. A handler sets
  `CustomGrantResponse.IssueRefreshToken` (or a `TokenExchangePolicy`
  returns `IssueRefreshToken`); the OP — not the handler — mints and
  persists the token through its `RefreshTokenStore`, sharing the access
  token's grant identity so the credential rides the standard rotation,
  single-use replay-cascade (RFC 9700 §2.2.2), and DPoP / mTLS
  `cnf`-binding machinery.
- Device-authorization revocation now cascades inside the library:
  `devicecodekit.Revoke` revokes every access token issued from the
  revoked `device_code` (its ID is the `GrantID` stamped on each token)
  via `AccessTokenRegistry.RevokeByGrant` when the new
  `devicecodekit.Deps.AccessTokens` registry is wired.
- A broad security-hardening sweep across DPoP, JAR / JARM, JOSE, mTLS,
  refresh rotation, client authentication, i18n input, metrics
  cardinality, and the authorize / userinfo / introspection / end-session
  endpoints (see Fixed).
- Default-driver browser login is unblocked: the interaction HTML pages
  no longer emit the two headers (`Referrer-Policy: no-referrer`,
  CSP `form-action 'self'`) that made a real browser's credential POST
  and post-consent redirect fail.

### Added

- `op.CustomGrantResponse.IssueRefreshToken bool` asks the OP to mint
  and persist a refresh token bound to the issued access token's grant
  identity. The OP owns the credential (RFC 6749 §6); issuance is gated
  on the client being registered for the `refresh_token` grant, and a
  request for refresh on an ineligible grant is honoured (200) with the
  refresh token dropped and a `custom_grant.refresh_dropped` audit event.
- `op.devicecodekit.Deps.AccessTokens` (optional
  `store.AccessTokenRegistry`) enables the `Revoke` cascade described in
  Highlights. The `device_code.revoked` audit event carries the
  `revoked_access_tokens` count when the registry is wired; a nil
  registry skips the cascade for JWT-stateless or out-of-band
  deployments.
- `op.WithDeviceCode(...)` records now lock after repeated poll abuse:
  a device-code that is polled past the slow-down ladder is denied,
  closing a polling-DoS vector.
- `op.WithDiscoveryMetadata(...)` validates that embedder-supplied
  endpoint URLs are well-formed absolute https URLs at `op.New` time
  rather than emitting a malformed discovery document at runtime.
- The example tree gains two automated verification harnesses under
  `examples/internal/` (build-tagged, separate sub-modules):
  `browserverify` (headless-Chrome end-to-end login across the
  default-HTML-driver and SPA examples) and `apiverify` (stdlib-only
  HTTP / boot smoke and grant-level checks for the API-only examples).

### Changed

- **Breaking**: `op.CustomGrantResponse.RefreshToken string` (a reserved
  field that was always rejected) is removed in favour of
  `IssueRefreshToken bool`. The string field let a handler supply a
  refresh-token *value*, which contradicts the RFC 6749 §6 model in
  which the authorization server issues the credential; the flag lets
  the handler signal intent while the OP retains ownership of the value
  and its lineage. No existing call site loses behaviour because the
  string field never produced a usable refresh token.
- `op.New` now enforces per-client scope and projects pairwise subjects
  at token mint (not only at the authorize step), so a client cannot
  widen its scope or observe a non-pairwise `sub` through the token
  endpoint.
- First-party auto-consent is additionally gated on the `Sec-Fetch-Site`
  request header and an `offline_access`-aware check, narrowing the
  silent-consent path to genuine first-party top-level navigations.
- The JARM form-post response now scopes its CSP `form-action` to the
  request's redirect-target origin instead of a broad value.
- The JWKS document's default `Cache-Control` max-age is shortened to one
  hour so key rotation propagates faster.
- `op-demo` defaults its listen address to loopback, and advertises the
  CIBA and refresh-token grants in its FAPI-CIBA profile.

### Fixed

- **DPoP**: the `jti` replay window is widened to twice the `iat`
  acceptance window (closing a gap where a proof replayed near the window
  edge could slip through), the `htu` comparison normalises a trailing
  dot, and the `jti` store expiry is anchored to `iat`.
- **JAR**: the request-object `jti` replay-cache expiry is floored and
  its scope is made type-safe. A request object that declares a `typ`
  header must name the `oauth-authz-req+jwt` media type (matched
  case-insensitively per RFC 2045 §5.1); a request object that omits
  `typ` is accepted, since RFC 9101 §10.8 makes the media type
  RECOMMENDED rather than REQUIRED.
- **JOSE**: kid-less JWE trial decryption is bounded by algorithm and key
  count so a crafted token cannot force unbounded trial work.
- **mTLS**: client certificates are verified against an optional
  `RootCAs` set and multi-valued RDNs are preserved in subject matching.
- **Refresh rotation**: the rotation chain is preserved on a grace-window
  fault, and a refresh token presented with a parent from a different
  client is rejected. `authorization_code` replay errors now surface the
  `GrantID`.
- **token-exchange**: a dual `cnf` (DPoP and mTLS) must AND-match, and
  the issued `id_token` audience is pinned.
- **Client authentication**: the Argon2id parameter floor follows the
  OWASP minimum, the `client_assertion` signing algorithm is pinned per
  client, and the `client_assertion` audience is scoped per endpoint —
  each endpoint accepts its own URL plus the issuer, and PAR / the
  backchannel endpoint additionally accept the token-endpoint URL (the
  canonical client_assertion audience per RFC 7523 §3 / OIDC Core §9).
- **userinfo / introspection / token**: `invalid_token` reasons are
  genericised and a pairwise `gid` is required on userinfo; opaque-token
  and JWT access-token subjects are projected through the configured
  `SubjectProjector` on egress; userinfo and end-session accept `HEAD`.
- **end-session**: the logout confirmation POST requires an `Origin` or
  `Referer` header and the logout page CSP is tightened.
- **CIBA**: a `client_notification_token` is rejected in poll-mode
  requests.
- **i18n**: `Accept-Language` entries and locale-tag length are capped,
  and the locale cookie's shape and length are validated before use.
- **Metrics**: events are forwarded before the internal counter update
  and a panicking sink is recovered; event-name labels are allow-listed
  to bound cardinality.
- **Storage adapters**: the in-memory adapter amortises PAR / JTI garbage
  collection and skips already-expired `Save`s; the Redis adapter floors
  the `jti` TTL at 60 s on `Save`.
- The interaction HTML pages relax `Referrer-Policy` to `same-origin` and
  stop pinning CSP `form-action`, fixing browser login (the prior
  `no-referrer` forced the credential POST's `Origin` to `null`, and
  `form-action 'self'` blocked the post-consent cross-origin redirect).

### Removed

- `op.CustomGrantResponse.RefreshToken` (replaced by the
  `IssueRefreshToken` flag; see Changed).

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

- `op.WithCustomGrant(...)` graduates from the
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
  add OIDC Core §8 pairwise subject derivation
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
    OP-side `act` claim chain; service-b's RS-side
    verifier walks `act.sub` and accepts only delegated tokens.
  - `examples/34-pairwise-saas/` — `WithPairwiseSubject`
    salt with two tenants in distinct sectors observes `A != B`
    (different sector → different sub) and `A1 == A2` (same
    sector + same user → identical sub), satisfying both the
    privacy and determinism properties of OIDC Core §8.1.
- JWE encryption. The OP now decrypts JWE-shaped
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
    (go-jose v4.1.x exposes no constants for them). `RSA1_5` is
    intentionally not shipped
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
  profiles included. RFC 9101 §6.1 marks
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

[Unreleased]: https://github.com/libraz/go-oidc-provider/compare/v1.0.0...HEAD
[v1.0.0]: https://github.com/libraz/go-oidc-provider/compare/v0.9.5...v1.0.0
[v0.9.5]: https://github.com/libraz/go-oidc-provider/compare/v0.9.4...v0.9.5
[v0.9.4]: https://github.com/libraz/go-oidc-provider/compare/v0.9.3...v0.9.4
[v0.9.3]: https://github.com/libraz/go-oidc-provider/compare/v0.9.2...v0.9.3
[v0.9.2]: https://github.com/libraz/go-oidc-provider/compare/v0.9.1...v0.9.2
[v0.9.1]: https://github.com/libraz/go-oidc-provider/compare/v0.9.0...v0.9.1
[v0.9.0]: https://github.com/libraz/go-oidc-provider/releases/tag/v0.9.0
