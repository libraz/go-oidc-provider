# go-oidc-provider

[![CI](https://img.shields.io/github/actions/workflow/status/libraz/go-oidc-provider/ci.yml?branch=main&label=CI)](https://github.com/libraz/go-oidc-provider/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/libraz/go-oidc-provider?include_prereleases&sort=semver&display_name=tag&label=release)](https://github.com/libraz/go-oidc-provider/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/libraz/go-oidc-provider/op.svg)](https://pkg.go.dev/github.com/libraz/go-oidc-provider/op)
[![codecov](https://codecov.io/gh/libraz/go-oidc-provider/branch/main/graph/badge.svg)](https://codecov.io/gh/libraz/go-oidc-provider)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go&logoColor=white)](go.mod)
[![Docs](https://img.shields.io/badge/docs-go--oidc--provider.libraz.net-2563eb)](https://go-oidc-provider.libraz.net)
[![Go Report Card](https://goreportcard.com/badge/github.com/libraz/go-oidc-provider)](https://goreportcard.com/report/github.com/libraz/go-oidc-provider)

OpenID Connect Provider (Authorization Server) library for Go. `op.New(...)`
returns a standard `http.Handler` that mounts on `net/http`, `chi`, `gin` or any
other router. It depends on no framework and holds no global state, and it
targets the FAPI 2.0 Baseline and Message Signing profiles.

**Documentation: [go-oidc-provider.libraz.net](https://go-oidc-provider.libraz.net)**
— concepts, use cases, the options reference, operations guides, security
posture and the conformance scoreboard. This README covers installation, the
shape of the repository, and the decisions to know about before adopting the
library.

> **Status: `v1.2.0`.** The public `op` surface follows strict
> [Semantic Versioning](https://semver.org/spec/v2.0.0.html) from the 1.0
> release on. Symbols documented with an `Experimental:` marker are exempt: the
> authentication-step seam, the interaction UI types, and Grant Management.
> They are inventoried in [`api/experimental.txt`](api/experimental.txt), which
> `make verify` regenerates and diffs, so the exempt set cannot grow without
> review. [`CHANGELOG.md`](CHANGELOG.md) carries the migration notes.
>
> This is an independently maintained project, not a vendor product. Every
> release is regressed against the OpenID Foundation conformance suite, but the
> project carries no formal certification and support is best-effort.

## Install

```sh
go get github.com/libraz/go-oidc-provider@v1.2.0
```

Go 1.25+. Storage adapters are published as sub-modules on the same tag, so
their drivers stay out of your `go.sum` until you opt in:

```sh
go get github.com/libraz/go-oidc-provider/op/storeadapter/sql@v1.2.0
go get github.com/libraz/go-oidc-provider/op/storeadapter/redis@v1.2.0
go get github.com/libraz/go-oidc-provider/op/storeadapter/dynamodb@v1.2.0
```

## Quickstart

```go
handler, err := op.New(
    op.WithIssuer("https://idp.example.com"),
    op.WithStore(st),
    op.WithKeyset(op.Keyset{{KeyID: "k1", Signer: priv}}),
    op.WithCookieKeys(cookieKey), // 32 bytes, AES-256-GCM
    op.WithLoginFlow(op.LoginFlow{
        Primary: op.PrimaryPassword{Store: st.UserPasswords()},
    }),
)
if err != nil {
    log.Fatal(err)
}
log.Fatal(http.ListenAndServe(":8080", handler))
```

`Issuer`, `Store` and `Keyset` are always required. `CookieKeys` is required
whenever the `authorization_code` grant is enabled, which is the default.
`op.New` returns an error rather than booting in an unsafe configuration, so an
incomplete setup fails at construction time.

A security profile is declared with one option, and the constructor refuses to
start when the declared profile conflicts with the rest of the configuration:

```go
op.WithProfile(profile.Baseline)      // OAuth 2.1: PKCE on every code request
op.WithProfile(profile.FAPI2Baseline) // PAR + JAR + DPoP, ES256, alg lock
```

Next steps: [Quick Start](https://go-oidc-provider.libraz.net/getting-started/install)
· [Required options](https://go-oidc-provider.libraz.net/getting-started/required-options)
· [Mounting the handler](https://go-oidc-provider.libraz.net/getting-started/mount)
· [Security profiles](https://go-oidc-provider.libraz.net/use-cases/security-profile).
[`examples/01-minimal`](examples/01-minimal/main.go) shows the same setup end to
end, including key generation, store wiring and graceful shutdown.

The defaults assume production: https only, public network only.
`http://127.0.0.1` is exempt from both checks, so most examples run without any
development option. Two options cover the cases the IP literal does not: the
textual host `localhost`, and a plain-http `backchannel_logout_uri`. Both are
documented under
[`redirect_uri`](https://go-oidc-provider.libraz.net/concepts/redirect-uri) and
[Issuer](https://go-oidc-provider.libraz.net/concepts/issuer).

## Scope

- **Embeds as `http.Handler`.** Framework-agnostic, mountable at any prefix.
- **Bring your own user model and storage.** Small `store.*` substore
  interfaces; the library never touches your `users` table directly.
- **Headless interaction driver.** Login, consent and logout can be driven from
  a SPA via `op.WithSPAUI`, or rendered from your own templates with
  `op.WithConsentUI`.
- **Audit-first observability.** Business events go through `audit.Emitter`,
  and `op.WithPrometheus(reg)` registers a curated counter set on your
  registry. The library does not mount `/metrics`, install request-duration
  middleware, or wrap your router; that is the embedder's responsibility.

Deliberately out of scope: an IdP (the library has no user table, no password
hashing and no email delivery), a generic OAuth2 framework, and a UI kit. See
[Why this library](https://go-oidc-provider.libraz.net/why).

## Standards

- **Core.** OpenID Connect Core 1.0 and Discovery 1.0; OAuth 2.0 (RFC 6749),
  its Security BCP (RFC 9700) and Authorization Server Metadata (RFC 8414).
- **Request and token hardening.** PKCE (RFC 7636), DPoP (RFC 9449), PAR
  (RFC 9126), JAR (RFC 9101), JARM, mTLS (RFC 8705), issuer identification
  (RFC 9207), Rich Authorization Requests (RFC 9396), step-up authentication
  (RFC 9470).
- **Grants.** Authorization code, refresh token, client credentials, device
  authorization (RFC 8628), CIBA Core 1.0, token exchange (RFC 8693), and
  embedder-defined grants through `op.WithCustomGrant`.
- **Token and client lifecycle.** JWT access tokens (RFC 9068), revocation
  (RFC 7009), introspection (RFC 7662), Dynamic Client Registration and its
  management API (RFC 7591 / RFC 7592).
- **Session termination.** RP-Initiated Logout 1.0 and Back-Channel Logout 1.0.
  Front-channel logout is not implemented.

FAPI 2.0 Baseline and Message Signing are the target profiles. Per-RFC detail
is in the
[RFC matrix](https://go-oidc-provider.libraz.net/compliance/rfc-matrix), and
every release is regressed against the OpenID Foundation conformance suite,
with results on the
[scoreboard](https://go-oidc-provider.libraz.net/compliance/ofcs).

Two deliberate departures from the specifications:

- **Signing is ES256 only.** ID tokens, JWT access tokens, signed UserInfo and
  JARM responses are all signed with ES256, permanently rather than as a staged
  rollout. OpenID Connect Core §15.1 makes RS256 mandatory to implement, so a
  relying party that can only verify RS256 is not supported. Verification is
  wider: RS256, PS256, ES256 and EdDSA are accepted on client assertions and
  request objects.
- **A rejected DPoP proof answers in the OAuth error envelope.** Endpoints that
  accept a proof on a form post return `400 invalid_request` instead of
  RFC 9449 §7's `invalid_dpop_proof`, so a relying party that already handles
  the OAuth error codes needs no additional case. Two responses keep their own
  code: the §8 nonce challenge answers `use_dpop_nonce` with a `DPoP-Nonce`
  header, and a proof rejected at a protected resource answers
  `401 invalid_token`.

Both, and the other decisions of this kind, are recorded in
[Design judgments](https://go-oidc-provider.libraz.net/security/design-judgments).

## Storage

Implement the substore interfaces in [`op/store`](op/store) to use your own
backend, or take one of the shipped adapters:

| Adapter | Module | Purpose |
|---|---|---|
| `inmem` | main module | Reference store for development and tests. |
| `sql` | sub-module | `database/sql` for SQLite, MySQL 8.0+, PostgreSQL 14+, with reference DDL embedded per engine. |
| `redis` | sub-module | Volatile substores only; refuses to start without TLS and AUTH. |
| `dynamodb` | sub-module | One table per substore, transactional. Marked `Experimental:`. |
| `composite` | main module | Hot/cold splitter: durable substores to one backend, volatile to another. |

[`op/store/contract`](op/store/contract) is a reusable conformance harness
rather than an internal test. Point it at your backend and it exercises the
semantics the godoc declares, skipping the optional extensions you have not
implemented. The bundled adapters are validated by the same suite.

See [Choosing a storage layout](https://go-oidc-provider.libraz.net/use-cases/storage-decision)
and [Bring your own store](https://go-oidc-provider.libraz.net/use-cases/byo-store).

## Examples

[`examples/`](examples/README.md) holds 44 runnable demos, one option or
feature apiece, each mapped to a
[use-case page](https://go-oidc-provider.libraz.net/use-cases/).

```sh
(cd examples/01-minimal && GOWORK=off go run -tags example .)
```

Each example is its own module resolved through a development `replace`, so it
is run with the repository workspace disabled; `make example-01` does the same.

[`sample/`](sample/README.md) is one worked application rather than one option
apiece. It owns its accounts, embeds the OP in the same process, and completes
the round-trip against a relying party, with MySQL for the durable substores
and Redis for the volatile ones joined through `op/storeadapter/composite`. It
boots from `docker compose -f sample/compose.yaml up -d --build`. It is a
demonstration and is not intended for public hosting.

## Community

- [SECURITY.md](.github/SECURITY.md) — vulnerability reporting policy and
  supported versions.
- [CONTRIBUTING.md](.github/CONTRIBUTING.md) — contribution mechanics,
  Conventional Commits scopes, test layering expectations.
- [CODE_OF_CONDUCT.md](.github/CODE_OF_CONDUCT.md) — Contributor Covenant 2.1
  and the project's reporting channel.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Third-party dependency
licenses are tracked in [`THIRD_PARTY.md`](THIRD_PARTY.md), regenerated from
`go.mod` by `make licenses`.
