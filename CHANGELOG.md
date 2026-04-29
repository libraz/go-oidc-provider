# Changelog

This project has not yet had a tagged release. The first entry will be
added with `v0.1.0`; until then, the public API may change at any time
on `main` and a changelog would only mislead.

Once releases begin, notable changes will be tracked here in
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format. The
project will follow strict [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
from `v1.0.0` onwards; pre-v1.0 minor releases may carry breaking
changes.

## Unreleased

### Breaking (protocol audit fixes)

- `/end_session` GET requests without an `id_token_hint` now render an
  interstitial confirmation page (HTTP 200, double-submit `__Host-`
  CSRF cookie) instead of terminating the session immediately. Only a
  follow-up POST that carries both halves of the token plus a
  same-origin `Origin` / `Referer` header actually logs the user out.
  The hint-bearing branch (the typical OIDC RP-Initiated Logout flow)
  is unchanged. Embedders that drove the previous behaviour through a
  cross-site `<img src=...>` tag MUST migrate to a same-origin POST.
  See OIDC RP-Initiated Logout 1.0 §5. (H-PROTO-3)
- The back-channel logout deliverer now refuses to POST a signed
  `logout_token` to a `backchannel_logout_uri` whose URL host resolves
  to a loopback / link-local / RFC 1918 / IPv6 ULA address. Embedders
  fronting their RPs with private DNS opt out via the new
  `op.WithBackchannelAllowPrivateNetwork(true)` option. (H-PROTO-1)
- `id_token_hint` verification at `/end_session` now requires the
  payload's `iss` claim to equal the OP issuer, and (when present)
  the `azp` claim to appear among `aud`. A token forged by a different
  OP whose `kid` happens to match an OP key is no longer admitted.
  (M-PROTO-2)
- Dynamic Client Registration rejects `redirect_uris` whose scheme is
  `http` unless the host is a loopback literal (`127.0.0.1`, `[::1]`,
  or `localhost`). The previous behaviour admitted any non-loopback
  http target, violating RFC 8252 §7.3. Embedders who registered such
  URIs MUST switch to https or use a loopback literal. (M-PROTO-9)

### Added (protocol audit fixes)

- `op.WithBackchannelAllowPrivateNetwork(bool)` (new in
  `op/options_protocol.go`) toggles the SSRF deny-list described
  above. Default `false`.
- `discovery.ValidateIssuer` enforces the OIDC Discovery 1.0 §3 /
  FAPI 2.0 §5.4 issuer shape (https, no trailing slash, no query /
  fragment; loopback hosts exempted from https) as a defense-in-depth
  seam over `op.WithIssuer`. (M-PROTO-6)

### Security (protocol audit fixes)

- `/end_session` no longer emits an unparseable
  `post_logout_redirect_uri` as a `Location` header even when the
  string passed the registered-URI exact-match check; the handler
  falls onto the static confirmation page instead, closing a latent
  open-redirect surface against any future regression that loosened
  validatePostLogout. (L-PROTO-4)

### Breaking

- `internal/dpop`: the `htm` claim is compared byte-equal by default
  (RFC 9449 §4.3 strict). `VerifierConfig.AllowLooseMethodCase`
  restores the previous ASCII case-folded comparison for embedders
  facing non-conforming RP libraries (closes M-FAPI-2). Proofs whose
  `htm` casing differs from the request method now fail
  `ErrProofHTMMismatch` unless the new flag is set.
- `internal/jar`: `Verifier` rejects request objects without `nbf`
  by default (closes L-JAR-NBF). The new
  `VerifierConfig.AllowMissingNbf` opt-out restores the previous
  back-compat stance for embedders who must admit legacy RPs that
  predate the FAPI 2.0 Message Signing §5.6 mandate. Callers that
  previously relied on the default silently admitting nbf-less
  request objects must either include `nbf` (recommended) or set
  `AllowMissingNbf: true`.
- `internal/mtls`: `ProxyConfig.HeaderName` now requires a non-empty
  `ProxyConfig.TrustedProxies` allow-list; an embedder who configures
  the cert header without listing the upstream proxy CIDRs no longer
  silently honours spoofed `X-Client-Cert` values from direct
  attacker connections (closes H-FAPI-1). New helper
  `mtls.ParseTrustedProxies` projects a string CIDR slice onto the
  required `[]netip.Prefix` shape.
- JWT-shaped access tokens now carry the JOSE header `typ=at+jwt` per
  RFC 9068 §2.1 (previously `typ=JWT`, shared with ID tokens).
  Resource servers that strict-checked the typ value against the
  literal `JWT` string MUST update their verifier to accept `at+jwt`
  (the canonical and case-insensitive `application/at+jwt` per
  RFC 9068 §2.1). ID tokens continue to use `typ=JWT`. Splitting the
  two values structurally prevents an attacker from substituting an
  ID token for an access token (RFC 9068 §5).
- `op.NewInMemoryDPoPNonceSource` now accepts a variadic
  `op.InMemoryDPoPNonceOption` parameter so a logger / entropy source
  can be threaded into the rotation goroutine. Existing call sites
  that passed `(ctx, rotate)` continue to compile because the new
  parameter is variadic.
- `op.Provider.RevokeInitialAccessToken` is now idempotent: a missing
  token returns `nil` instead of `store.ErrNotFound`. Embedders that
  branched on `errors.Is(err, store.ErrNotFound)` to decide whether
  the token actually existed must move that check to a prior
  `InitialAccessTokens().GetByHash` lookup; the post-condition the
  function reports ("the token does not exist") holds either way.
- `internal/scoperegistry`: `Registry.Allows` now fail-closes on an
  unknown scope (audit finding F-5). Callers that relied on the
  previous "unknown scope means allow" semantics must consult
  `IsRegistered` first and run their own decision; in the typical
  pipeline higher layers (op-layer client.Scopes intersection,
  refresh-token scope widening) reject unknown scopes before
  `Allows` is consulted, so the change closes the structural hole
  rather than the everyday path. `scoperegistry.New` also panics
  when an entry's `Name` has surrounding whitespace (audit finding
  F-6); padded names cannot survive the OAuth wire format
  (RFC 6749 §3.3) so storing them silently is a programmer error.
- `internal/clientauth`: `Argon2id.Verify` rejects stored hashes
  whose Argon2id parameters fall below the OWASP 2024 floor
  (`Argon2idMinMemory` = 19 MiB, `Argon2idMinIterations` = 2)
  (audit finding L-STORE-F10). Embedders that previously used
  sub-floor parameters in tests must raise the work factor or use
  the new constants.

### Added

- `op.WithMTLSProxy(headerName, trustedCIDRs)` option in
  `op/options_fapi_proxy.go` validates the reverse-proxy header path
  configuration at startup and pairs the header name with a
  required-to-be-non-empty CIDR allow-list. `op.MTLSProxyConfig(p)`
  returns the recorded `mtls.ProxyConfig` so embedders can build
  their `mtls.Verifier` directly while the runtime wiring layer is
  staged.
- `internal/jarm`: response objects now carry `nbf` set equal to
  `iat` (closes L-JARM-NBF). Strict consumers running under FAPI 2.0
  Message Signing §5.6 can apply a uniform nbf-or-fail rule on JARM
  responses; relaxed consumers ignore the additional claim.
- `op.WithInMemoryDPoPNonceLogger` functional option threads a
  `*slog.Logger` into `op.NewInMemoryDPoPNonceSource` so a
  `crypto/rand.Reader` failure during the rotation goroutine emits a
  WARN line tagged with the running failure counter.
- `op.InMemoryDPoPNonceSource.RotationFailures()` exposes a monotonic
  atomic counter of rotation ticks that could not mint a fresh nonce,
  so embedders can wire the helper's degradation into their metrics
  surface alongside the new logger.
- `op.AuditDenyReasonKey` constant pins the slog attribute key
  (`"audit.deny.reason"`) under which `op.Deny.Reason` flows into the
  audit stream. The redaction allow-list installed by `op.WithLogger`
  and `op.WithAuditLogger` keys off this constant, so a misbehaving
  `op.Decider` cannot leak credentials or PII through the audit sink.

### Security

- `internal/jarm`: the JARM signer now derives the JWS `alg` header
  from the supplied key shape and rejects unsupported keys at
  `jarm.NewSigner` construction time (closes H-FAPI-2). v0.x mirrors
  the [internal/keys.NewSet] policy and accepts ECDSA P-256 only
  (ES256); RSA, Ed25519, and non-P-256 ECDSA keys surface as
  `ErrEncode` at startup rather than failing later with a josev4
  wrapping error at the first response.
- `internal/dpop`: `Verifier.Verify` marks the proof's `jti` claim
  immediately after the optional nonce gate succeeds and before any
  further computation. The reorder closes the M-FAPI-1 vector where
  an attacker could observe a stale-nonce proof and resubmit the
  same `jti` with a fresh nonce.
- `op.InMemoryDPoPNonceSource.Validate` switched from `==` string
  comparison to `crypto/subtle.ConstantTimeCompare`, with the
  current/previous compares combined without an early return so the
  matched slot is not observable through timing.
- `op.LoadPublicJWKS` now identifies the offending file by its base
  name (via `filepath.Base`) in returned error descriptions instead
  of the absolute filesystem path, so error_description and audit log
  consumers cannot map the host's directory layout.
- `op.Deny.Reason` godoc now documents the `"audit.deny.reason"` slog
  attribute key and the redaction guarantee the library applies to
  it; a sentinel test in `op` pins the constant against drift.
- `internal/cookie`: Add `cookie.Set` / `cookie.Clear` host-locked cookie
  builder. The helpers force `Secure`, `HttpOnly`, `Path=/`, empty `Domain`,
  and reject names lacking the `__Host-` prefix so a forgetful caller cannot
  emit a cookie that bypasses the §F.1 attribute set.
- `internal/sessions`: Add `Manager.Rotate` for session-fixation defence on
  re-authentication. The rotation reissues a fresh session ID under the same
  chooser group while preserving `CreatedAt` so the absolute-TTL clock is
  not reset by a rotation.
- `internal/sessions`: Add `Config.AbsoluteTTL` (default 30 days). `Touch`
  expires and deletes any session whose `CreatedAt` is older than the cap;
  pass a negative value to disable the cap explicitly.
- `internal/csrf`: `CanonicalOrigin` now rejects userinfo, opaque URLs, and
  schemes other than `http`/`https`. Closes the
  `https://evil.example/?@trusted.example` parser-confusion class.
- `internal/csrf`: Token MAC now covers a length-prefixed canonical encoding
  (`uint32be(len)||value`) of `(sessionID, nonce, iat, scope)` and a new
  `IssueScoped` / `VerifyScoped` pair binds tokens to a per-request scope.
  Tokens minted by previous releases will fail to verify because the MAC
  framing changed; tokens are short-lived so the rotation is observable as
  one "please reload" event during the upgrade window.
- `internal/cors`: Strict preflight now intersects
  `Access-Control-Request-Headers` with the static allowlist; unsupported
  headers (e.g. `Cookie`, `X-Pwn`) are silently dropped from the echo so a
  preflight cannot be coerced into permitting a header the OP does not read.
- `internal/proxy`: Add `proxy.NewTrustWithHosts` for an
  `X-Forwarded-Host` allowlist. When configured, `Resolve` ignores any XFH
  value outside the allowlist even if the request originates from a trusted
  proxy. The legacy `NewTrust` keeps the existing passthrough behaviour.
- `internal/proxy`: `walkForwardedFor` now skips malformed XFF tokens
  instead of aborting the walk, so a hostile proxy cannot hide a valid
  client IP behind a single bad entry.
- `internal/httpx`: `WriteJSON` now stamps `X-Content-Type-Options: nosniff`
  on every response (including the `server_error` fallback).
- `internal/httpx`: `escapeQuoted` now drops bytes below `0x20` and `0x7F`,
  eliminating CRLF-injection routes through OAuth bearer challenges.
- `internal/httpx`: `readBounded` now closes the request body on return
  best-effort, so connection reuse is not impacted by callers that forget
  to close.
- `op/store`: `AuthorizationCodeStore`, `RefreshTokenStore`, and
  `PushedAuthRequestStore` now declare a hash-on-store contract:
  backends MUST hash the presented bearer secret (SHA-256 with a
  server-side pepper recommended) before persisting, MUST hash the
  presented value before lookup, and SHOULD compare against the
  stored digest in constant time. The reference
  `op/storeadapter/inmem` implementation hashes via SHA-256 (no
  pepper, intentionally) so a heap dump or debugger inspection
  reveals only digests; the `RefreshToken.ParentID` pointer is
  hashed identically so chain walks never see the raw bearer
  values (audit finding M-STORE-1).
- `op/storeadapter/inmem`: `iatStore.GetByHash` is now a single
  map lookup keyed on the presented digest (previously a linear
  scan), with `subtle.ConstantTimeCompare` retained as a structural
  belt-and-braces guard (audit finding M-STORE-2). The new
  `byHash` index stays in sync with `Put` / `Delete` so a deleted
  IAT cannot be resurrected through the GetByHash side.
- `internal/redact`: `IsSensitive` adds a substring-match catalogue
  (`secret`, `token`, `password`, `assertion`, `bearer`,
  `private_key`, `pwd`, `passcode`) so naming variants the exact
  list could not enumerate (`password_hash`, `new_refresh_token`,
  `client_secret_jwt`, `bearer_token`) ship as `[REDACTED]`
  (audit finding M-REDACT). False-positives that name only a
  category (`token_type`, `keypair_kid`, `secret_type`,
  `id_token_signed_response_alg`, ...) are exempted via a small
  allowlist.
- `internal/audit`: `slogEmitter.Emit` masks Extras values whose
  key trips `redact.IsSensitive` before handing them to
  `slog.Any`, so an embedder that wires a plain `slog.Handler`
  (without `redact.WrapHandler`) still cannot leak refresh
  tokens or client secrets that flowed through the audit
  pipeline (audit finding M-AUDIT).
- `internal/clientauth`: `runDummyVerify` now performs a
  fixed-cost ECDSA P-256 verify on the `MethodPrivateKeyJWT`
  branch, matching the work factor a real
  `AssertionVerifier` would burn on signature verification. The
  shim closes the timing oracle that previously distinguished
  "unknown client_id" from "wrong signature" on
  `private_key_jwt` requests (audit finding M-CLIENTAUTH).
- `op/storeadapter/inmem`: `Tx.Rollback` now clears every staged
  add / update / delete map entry before releasing the tx mutex,
  so freed staging slots are eligible for GC immediately and a
  buggy caller that retains a pointer into rolled-back staging
  cannot corrupt the next transaction (audit finding F-11).
- Refresh-token grace window shortened from 60s to 30s by default
  (`internal/grants/refresh.GraceTTLDefault`). The window is still
  negative-disable-able via `op.WithRefreshGracePeriod(-1)` for
  FAPI 2.0 strict-mode posture; the FAPI 2.0 profile already forces
  grace=0 when active, so the change has no effect on FAPI 2.0
  deployments.
- Refresh-token rotation cascade now revokes the chain explicitly
  when a credential mismatch (client_id / scope widening) is observed
  inside the grace window, before falling through to the post-grace
  replay handler. Previously the cascade still ran via the post-grace
  path; the explicit anchor at the validation point provides defence
  in depth and survives future refactoring (RFC 9700 §2.2.2).
- Token endpoint now refuses an authorization_code exchange when a
  public client redeems a code that was issued without a PKCE
  challenge, regardless of the active profile. This is a defence-in-
  depth check (RFC 9700 §2.1.1); the authorize-side gate remains
  profile-conditional.

### Notes

- RFC 8707 (Resource Indicators) audience narrowing is tracked as a
  v1.x milestone. Today the access-token `aud` claim defaults to
  the OP issuer URL.
