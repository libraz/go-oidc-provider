# go-oidc-provider

[![CI](https://img.shields.io/github/actions/workflow/status/libraz/go-oidc-provider/ci.yml?branch=main&label=CI)](https://github.com/libraz/go-oidc-provider/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/libraz/go-oidc-provider/branch/main/graph/badge.svg)](https://codecov.io/gh/libraz/go-oidc-provider)
[![Release](https://img.shields.io/github/v/release/libraz/go-oidc-provider?include_prereleases&sort=semver&display_name=tag&label=release)](https://github.com/libraz/go-oidc-provider/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/libraz/go-oidc-provider/op.svg)](https://pkg.go.dev/github.com/libraz/go-oidc-provider/op)
[![Go Report Card](https://goreportcard.com/badge/github.com/libraz/go-oidc-provider)](https://goreportcard.com/report/github.com/libraz/go-oidc-provider)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-libraz.net-blue?logo=readthedocs&logoColor=white)](https://go-oidc-provider.libraz.net)

OpenID Connect Provider (Authorization Server) library for Go. `op.New(...)`
returns a standard `http.Handler` you mount on `net/http`, `chi`, `gin`, or any
router — no framework lock-in, no global state. Targets FAPI 2.0 Baseline /
Message Signing.

> 📘 **[Documentation site](https://go-oidc-provider.libraz.net)** — concepts,
> use cases, security posture, conformance scoreboard, and the full options
> reference live there. This README is the source-tree map and example
> inventory.

> **Status: pre-v1.0.** `v0.9.0` is the initial public release; the public API
> may change in any minor release until `v1.0.0`.
> [`CHANGELOG.md`](CHANGELOG.md) starts tracking notable changes from the
> release that follows `v0.9.0`.

## Install

```sh
go get github.com/libraz/go-oidc-provider/op@v0.9.0
```

Go 1.23+ (matches `go.mod`). Storage adapters that pull DB / Redis drivers are
published as sub-modules so their dependencies stay out of your `go.sum` until
you opt in:

```sh
go get github.com/libraz/go-oidc-provider/op/storeadapter/sql@v0.9.0
go get github.com/libraz/go-oidc-provider/op/storeadapter/redis@v0.9.0
```

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
  (React, Vue, Svelte, Angular, …) via `op.WithSPAUI`, or supply your own
  templates with `op.WithConsentUI`.
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
the live scoreboard is on the
[conformance results page](https://go-oidc-provider.libraz.net/compliance/ofcs).
A per-RFC matrix is at
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

Runnable demos live under [`examples/`](examples/README.md) — see that index
for the full goal-oriented table, the numeric topic bands, and the docker
stacks shipped with `07-mysql-store` and `09-redis-volatile`. Each row also
maps to a use-case page on the docs site under
[Use cases](https://go-oidc-provider.libraz.net/use-cases/).

```sh
go run -tags example ./examples/01-minimal
```

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
