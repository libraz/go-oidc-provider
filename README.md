# go-oidc-provider

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/libraz/go-oidc-provider/op.svg)](https://pkg.go.dev/github.com/libraz/go-oidc-provider/op)

OpenID Connect Provider (Authorization Server) library for Go. `op.New(...)`
returns a standard `http.Handler` you mount on `net/http`, `chi`, `gin`, or any
router — no framework lock-in, no global state. Targets FAPI 2.0 Baseline /
Message Signing.

> **Documentation:** [go-oidc-provider.libraz.net](https://go-oidc-provider.libraz.net)
> — concepts, use cases, security posture, conformance results, and the full
> options reference live there. This README is the source-tree map and the
> example inventory.

> **Status: pre-v1.0.** Public API may change in any minor release until
> v1.0.0. The project has not yet had a tagged release;
> [`CHANGELOG.md`](CHANGELOG.md) starts tracking notable changes from the
> first release (`v0.1.0`) onwards.

## Install

```sh
go get github.com/libraz/go-oidc-provider/op@latest
```

Go 1.23+ (matches `go.mod`). Storage adapters that pull DB / Redis drivers are
published as sub-modules so their dependencies stay out of your `go.sum` until
you opt in.

## Quickstart

`op.New` requires four options at minimum — `Issuer`, `Store`, `Keyset`, and a
32-byte `CookieKey`. The constructor returns an error rather than booting in an
unsafe configuration, so partial setups fail fast.

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

End-to-end startup (key generation, store wiring, graceful shutdown) lives in
[`examples/01-minimal`](examples/01-minimal/main.go); see also
[Quick Start](https://go-oidc-provider.libraz.net/getting-started/install) and
[Required options](https://go-oidc-provider.libraz.net/getting-started/required-options).

### FAPI 2.0 Baseline in one switch

```go
op.WithProfile(profile.FAPI2Baseline) // PAR + JAR + DPoP, ES256, alg lock
```

The constructor refuses to start if the declared profile and the rest of the
options conflict. See
[Use case: FAPI 2.0 Baseline](https://go-oidc-provider.libraz.net/use-cases/fapi2-baseline).

## What this library is — and is not

- **Embeds as `http.Handler`**: framework-agnostic, mountable at any prefix.
- **BYO user model and storage**: small `store.*` substore interfaces; the
  library never touches your `users` table directly.
- **Headless interaction driver**: drive login / consent / logout from a SPA
  via `op.WithReactUI`, or supply your own templates with `op.WithConsentUI`.
- **Audit-first observability**: business events go through `audit.Emitter`
  and `op.WithPrometheus(reg)` registers a curated counter set on your
  registry. The library does **not** mount `/metrics`, install request-duration
  middleware, or wrap your router — that's the embedder's job.

Out of scope on purpose: it is not an IdP (no user table, no password hashing,
no email delivery), not a generic OAuth2 framework (opinionated toward OIDC),
and not a UI kit (the default HTML driver exists so the OP boots without
configuration). Detail in
[Why this library](https://go-oidc-provider.libraz.net/why).

## Standards

OpenID Connect Core 1.0; OAuth 2.0 (RFC 6749) and the Security Best Current
Practices (RFC 9700); PKCE (RFC 7636), DPoP (RFC 9449), PAR (RFC 9126), JAR
(RFC 9101), JARM, mTLS (RFC 8705); FAPI 2.0 Baseline / Message Signing.

Each release is regressed against the OpenID Foundation conformance suite —
the live scoreboard is on
[the docs site](https://go-oidc-provider.libraz.net/compliance/ofcs). A
per-RFC matrix is at
[Compliance — RFC matrix](https://go-oidc-provider.libraz.net/compliance/rfc-matrix).

## Storage

Bring your own backend by implementing the substore interfaces in
[`op/store`](op/store). The repository ships:

| Adapter | Module path | Purpose |
|---|---|---|
| `inmem` | `op/storeadapter/inmem` | Reference / dev / test store. The contract harness in [`op/store/contract`](op/store/contract) runs against it. |
| `sql` | `op/storeadapter/sql` | `database/sql` adapter for SQLite, MySQL 8.0+, PostgreSQL 14+. **Sub-module.** Contract harness exercises every substore against a real engine via testcontainers (`go test -tags=testcontainers`). |
| `redis` | `op/storeadapter/redis` | Volatile substores (`InteractionStore`, `ConsumedJTIStore`). **Sub-module.** Refuses to start without TLS (`rediss://`) and AUTH unless `WithDevModeAllowPlaintext` is set explicitly. |
| `composite` | `op/storeadapter/composite` | Hot/cold splitter — durable substores to one backend, volatile to another, while enforcing the transactional-cluster invariant. |

DynamoDB is planned for v1.x as an additional sub-module. Background:
[Operations — multi-instance](https://go-oidc-provider.libraz.net/operations/multi-instance).

## Examples

All examples build behind the `example` build tag, so they are excluded from
`go test ./...` and from production `go.sum`:

```sh
go run -tags example ./examples/01-minimal
```

### I want to…

| Goal | Start with |
|---|---|
| stand up the smallest possible OP | [`01-minimal`](examples/01-minimal/main.go) |
| see every option a typical embedder reaches for | [`02-bundle`](examples/02-bundle/main.go) |
| run a FAPI 2.0 Baseline OP (PAR + JAR + DPoP) | [`03-fapi2`](examples/03-fapi2/main.go), [`50-fapi-tls-jwks`](examples/50-fapi-tls-jwks/main.go) |
| issue tokens to backend services (no end user) | [`05-client-credentials`](examples/05-client-credentials/main.go) |
| serve plain OAuth 2.0 alongside OIDC | [`15-oauth2-only`](examples/15-oauth2-only/main.go) |
| persist on a real database (SQLite / MySQL) | [`06-sql-store`](examples/06-sql-store/main.go), [`07-mysql-store`](examples/07-mysql-store/main.go) |
| split hot volatile state from durable state | [`08-composite-hot-cold`](examples/08-composite-hot-cold/main.go), [`09-redis-volatile`](examples/09-redis-volatile/main.go) |
| swap the default HTML driver for JSON | [`04-custom-interaction`](examples/04-custom-interaction/main.go) |
| drive login / consent / logout from a SPA | [`10-react-login`](examples/10-react-login/main.go) |
| customise the consent screen | [`11-custom-consent-ui`](examples/11-custom-consent-ui/main.go) |
| support `prompt=select_account` (multi-account) | [`13-multi-account`](examples/13-multi-account/main.go) |
| serve a SPA from a different origin (CORS) | [`14-cors-spa`](examples/14-cors-spa/main.go) |
| translate prompts (i18n) | [`16-i18n-locale`](examples/16-i18n-locale/main.go) |
| split public-discoverable from internal-only scopes | [`12-scopes-public-private`](examples/12-scopes-public-private/main.go) |
| honour the OIDC §5.5 `claims` request parameter | [`17-claims-request`](examples/17-claims-request/main.go) |
| require TOTP / risk-based MFA / captcha / step-up | [`20-mfa-totp`](examples/20-mfa-totp/main.go), [`21-risk-based-mfa`](examples/21-risk-based-mfa/main.go), [`22-login-captcha`](examples/22-login-captcha/main.go), [`23-step-up`](examples/23-step-up/main.go) |
| skip consent for first-party clients | [`40-first-party-skip-consent`](examples/40-first-party-skip-consent/main.go) |
| let RPs register themselves (Dynamic Client Registration) | [`41-dynamic-registration`](examples/41-dynamic-registration/main.go) |
| notify RPs when a session ends (Back-Channel Logout) | [`42-back-channel-logout`](examples/42-back-channel-logout/main.go) |
| run the RFC 9449 §8 DPoP nonce flow | [`51-dpop-nonce`](examples/51-dpop-nonce/main.go) |
| expose Prometheus metrics | [`52-prometheus-metrics`](examples/52-prometheus-metrics/main.go) |

Each row maps to a use-case page on the docs site under
[/use-cases](https://go-oidc-provider.libraz.net/use-cases/) with a
production-shaped narrative around the example file.

### Numeric inventory

Numbers group examples by topic — bands without entries today are reserved for
in-flight or v1.x work:

| Band  | Topic                                                          |
|-------|----------------------------------------------------------------|
| 00–09 | bootstrap, grant variants, storage adapters                    |
| 10–19 | UI, scopes, SPA, locale, claims request, CORS                  |
| 20–29 | MFA and authentication rules (TOTP / risk / captcha / step-up) |
| 30–39 | identity federation (reserved — v1.x)                          |
| 40–49 | governance: first-party, DCR, back-channel logout              |
| 50–59 | operations: FAPI helpers, metrics, tracing, DPoP nonce         |
| 60–69 | compliance (reserved — v1.x late)                              |

## Community

- [SECURITY.md](SECURITY.md) — vulnerability reporting policy and supported
  versions.
- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution mechanics, Conventional
  Commits scopes, test layering expectations.
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — Contributor Covenant 2.1 and the
  project's reporting channel.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Third-party dependency
licenses are tracked in [`THIRD_PARTY.md`](THIRD_PARTY.md), regenerated from
`go.mod` by `make licenses`.
