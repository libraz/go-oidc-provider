# go-oidc-provider

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/libraz/go-oidc-provider/op.svg)](https://pkg.go.dev/github.com/libraz/go-oidc-provider/op)

OpenID Connect Provider (Authorization Server) library for Go.

> **Status: pre-v1.0.** Public API may change in any minor release until v1.0.0.

## Install

```sh
go get github.com/libraz/go-oidc-provider/op@latest
```

## Quickstart

`op.New` requires four options at minimum — Issuer, Store, Keyset, and a
32-byte CookieKey. The constructor returns an error rather than booting
in an unsafe configuration, so partial setups fail fast.

```go
handler, err := op.New(
    op.WithIssuer("https://idp.example.com"),
    op.WithStore(inmem.New()),
    op.WithKeyset(op.Keyset{{KeyID: "k1", Signer: priv}}),
    op.WithCookieKey(cookieKey), // 32 bytes, AES-256-GCM
)
if err != nil {
    log.Fatal(err)
}
log.Fatal(http.ListenAndServe(":8080", handler))
```

`op.New` returns a standard `http.Handler` and is framework-agnostic.
Mount it on any router (`net/http`, `chi`, `gin`, …) at the path of
your choice.

For runnable end-to-end startup code (key generation, store wiring,
graceful shutdown), see [`examples/`](#examples) below.

## Examples

All examples are built behind the `example` build tag so they are
excluded from `go test ./...` and from production go.sum.

### I want to…

| Goal                                                  | Start with                                                                                |
|-------------------------------------------------------|-------------------------------------------------------------------------------------------|
| stand up the smallest possible OP                     | [`01-minimal`](examples/01-minimal/main.go)                                               |
| see every option a typical embedder reaches for       | [`02-bundle`](examples/02-bundle/main.go)                                                 |
| run a FAPI 2.0 Baseline OP (PAR + JAR + DPoP)         | [`03-fapi2`](examples/03-fapi2/main.go)                                                   |
| issue tokens to backend services (no end-user)        | [`05-client-credentials`](examples/05-client-credentials/main.go)                         |
| persist on a real database (SQLite / MySQL)           | [`06-sql-store`](examples/06-sql-store/main.go), [`07-mysql-store`](examples/07-mysql-store/main.go) |
| split hot volatile state from durable state           | [`08-composite-hot-cold`](examples/08-composite-hot-cold/main.go), [`09-redis-volatile`](examples/09-redis-volatile/main.go) |
| drive login / consent / logout from a SPA             | [`10-react-login`](examples/10-react-login/main.go)                                       |
| customise the consent screen                          | [`11-custom-consent-ui`](examples/11-custom-consent-ui/main.go)                           |
| swap the default HTML driver for JSON                 | [`04-custom-interaction`](examples/04-custom-interaction/main.go)                         |
| serve a SPA from a different origin (CORS)            | [`14-cors-spa`](examples/14-cors-spa/main.go)                                             |
| translate prompts (i18n)                              | [`16-i18n-locale`](examples/16-i18n-locale/main.go)                                       |
| split public-discoverable from internal-only scopes   | [`12-scopes-public-private`](examples/12-scopes-public-private/main.go)                   |
| honour the OIDC §5.5 `claims` request parameter       | [`17-claims-request`](examples/17-claims-request/main.go)                                 |
| require TOTP / risk-based MFA / captcha / step-up     | [`20-mfa-totp`](examples/20-mfa-totp/main.go), [`21-risk-based-mfa`](examples/21-risk-based-mfa/main.go), [`22-login-captcha`](examples/22-login-captcha/main.go), [`23-step-up`](examples/23-step-up/main.go) |
| skip consent for first-party clients                  | [`40-first-party-skip-consent`](examples/40-first-party-skip-consent/main.go)             |
| let RPs register themselves (Dynamic Client Registration) | [`41-dynamic-registration`](examples/41-dynamic-registration/main.go)                 |
| notify RPs when a session ends (Back-Channel Logout)  | [`42-back-channel-logout`](examples/42-back-channel-logout/main.go)                       |
| terminate the OP behind FAPI-grade TLS                | [`50-fapi-tls-jwks`](examples/50-fapi-tls-jwks/main.go)                                   |
| run the RFC 9449 §8 DPoP nonce flow                   | [`51-dpop-nonce`](examples/51-dpop-nonce/main.go)                                         |
| expose Prometheus metrics                             | [`52-prometheus-metrics`](examples/52-prometheus-metrics/main.go)                         |

### Numeric inventory

Numbers group examples by topic — bands without entries today are
reserved for in-flight or v1.x work and will fill in as the
corresponding features land:

| Band  | Topic                                                          |
|-------|----------------------------------------------------------------|
| 00–09 | bootstrap, grant variants, storage adapters                    |
| 10–19 | UI, scopes, SPA, locale, claims request, CORS                  |
| 20–29 | MFA and authentication rules (TOTP / risk / captcha / step-up) |
| 30–39 | identity federation (reserved — v1.x Wave M)                   |
| 40–49 | governance: first-party, DCR, back-channel logout              |
| 50–59 | operations: FAPI helpers, metrics, tracing, DPoP nonce         |
| 60–69 | compliance (reserved — v1.x late)                              |

| Path | Demonstrates |
|---|---|
| [`examples/01-minimal`](examples/01-minimal/main.go) | Smallest boot: `op.New` with the four required options. |
| [`examples/02-bundle`](examples/02-bundle/main.go) | Comprehensive wiring: LoginFlow + clients + scopes + first-party. |
| [`examples/03-fapi2`](examples/03-fapi2/main.go) | FAPI 2.0 Baseline profile: PAR / JAR / DPoP, `private_key_jwt` client. |
| [`examples/04-custom-interaction`](examples/04-custom-interaction/main.go) | Swap to `interaction.JSONDriver` instead of the default HTML driver. |
| [`examples/05-client-credentials`](examples/05-client-credentials/main.go) | Machine-to-machine `grant_type=client_credentials` (RFC 6749 §4.4). |
| [`examples/06-sql-store`](examples/06-sql-store/main.go) | `op/storeadapter/sql` against SQLite for a CGO-free quickstart. |
| [`examples/07-mysql-store`](examples/07-mysql-store/main.go) | `op/storeadapter/sql` against MySQL with production-shaped pool / DSN. |
| [`examples/08-composite-hot-cold`](examples/08-composite-hot-cold/main.go) | `op/storeadapter/composite` hot/cold split: SQL durable + inmem volatile (stand-in for Redis). |
| [`examples/09-redis-volatile`](examples/09-redis-volatile/main.go) | Production-shaped composite: MySQL durable + `op/storeadapter/redis` volatile (Interactions, ConsumedJTIs). |
| [`examples/10-react-login`](examples/10-react-login/main.go) | Delegate login / consent / logout screens to a SPA via `op.WithReactUI`. |
| [`examples/11-custom-consent-ui`](examples/11-custom-consent-ui/main.go) | Custom consent template via `op.WithConsentUI`. |
| [`examples/12-scopes-public-private`](examples/12-scopes-public-private/main.go) | `op.PublicScope` / `op.InternalScope` — discovery vs admin-only scopes. |
| [`examples/14-cors-spa`](examples/14-cors-spa/main.go) | `op.WithCORSOrigins` + redirect-uri-derived allowlist for an SPA. |
| [`examples/16-i18n-locale`](examples/16-i18n-locale/main.go) | Locale negotiation via `op.WithLocale` / `op.WithDefaultLocale`. |
| [`examples/17-claims-request`](examples/17-claims-request/main.go) | OIDC §5.5 claims request parameter via `op.WithClaimsParameterSupported`. |
| [`examples/20-mfa-totp`](examples/20-mfa-totp/main.go) | Password + always-TOTP via `op.LoginFlow` + `op.RuleAlways`. |
| [`examples/21-risk-based-mfa`](examples/21-risk-based-mfa/main.go) | Risk-driven step-up via `op.RuleRisk` and a custom `RiskAssessor`. |
| [`examples/22-login-captcha`](examples/22-login-captcha/main.go) | Captcha after N failed attempts via `op.RuleAfterFailedAttempts`. |
| [`examples/23-step-up`](examples/23-step-up/main.go) | RFC 9470 ACR step-up via `op.RuleACR`. |
| [`examples/40-first-party-skip-consent`](examples/40-first-party-skip-consent/main.go) | Skip the consent prompt for first-party clients via `op.WithFirstPartyClients`. |
| [`examples/41-dynamic-registration`](examples/41-dynamic-registration/main.go) | RFC 7591 / 7592 Dynamic Client Registration via `op.WithDynamicRegistration`. |
| [`examples/42-back-channel-logout`](examples/42-back-channel-logout/main.go) | OIDC Back-Channel Logout 1.0: per-client `BackchannelLogoutURI` + RP stub. |
| [`examples/50-fapi-tls-jwks`](examples/50-fapi-tls-jwks/main.go) | FAPI helpers: `op.FAPITLSConfig` + `op.LoadPublicJWKS`. |
| [`examples/51-dpop-nonce`](examples/51-dpop-nonce/main.go) | RFC 9449 §8 server-supplied DPoP nonce flow via `op.WithDPoPNonceSource`. |
| [`examples/52-prometheus-metrics`](examples/52-prometheus-metrics/main.go) | Curated counter set via `op.WithPrometheus(reg)` + embedder-mounted `/metrics`. |

Run any of them with the build tag, e.g.:

```sh
go run -tags example ./examples/01-minimal
```

## Standards

- OpenID Connect Core 1.0
- OAuth 2.0 (RFC 6749) and the Security Best Current Practices (RFC 9700)
- PKCE (RFC 7636), DPoP (RFC 9449), PAR (RFC 9126), JAR (RFC 9101), JARM, mTLS
- FAPI 2.0 Baseline / Message Signing (target for v1.0)

A full design, threat model, and roadmap are tracked privately while the
project is pre-v1.0; the README is updated as decisions stabilise.

## Storage

Bring your own backend by implementing the small interfaces in
`github.com/libraz/go-oidc-provider/op/store`. The repository ships:

- `op/storeadapter/inmem` — reference implementation (the test suite
  in [`op/store/contract`](op/store/contract) runs against this).
- `op/storeadapter/composite` — hot/cold splitter; routes durable
  substores to one backend and volatile substores to another while
  enforcing the transactional-cluster invariant.
- `op/storeadapter/sql` — `database/sql` adapter for SQLite, MySQL 8.0+,
  and PostgreSQL 14+. Published as a sub-module so the driver
  dependencies stay out of the host module's `go.sum`. The contract
  harness exercises every substore against a real engine via
  testcontainers (`go test -tags=testcontainers`).
- `op/storeadapter/redis` — Redis adapter for the volatile,
  non-transactional substores (`InteractionStore`, `ConsumedJTIStore`).
  Pair with the SQL adapter through `op/storeadapter/composite` for the
  canonical hot/cold deployment shape. Refuses to start without TLS
  (`rediss://`) and AUTH unless the explicit
  `WithDevModeAllowPlaintext` escape hatch is supplied. Also published
  as a sub-module.

A DynamoDB adapter is planned for v1.x as an additional sub-module.

## Community

- [SECURITY.md](SECURITY.md) — vulnerability reporting policy and
  supported versions.
- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution mechanics,
  Conventional Commits scopes, test layering expectations.
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — Contributor Covenant 2.1
  and the project's reporting channel.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
Third-party dependency licenses are tracked in
[`THIRD_PARTY.md`](THIRD_PARTY.md), regenerated from `go.mod` by
`make licenses`.
