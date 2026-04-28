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
excluded from `go test ./...` and from production go.sum:

| Path | Demonstrates |
|---|---|
| [`examples/minimal`](examples/minimal/main.go) | Smallest boot: `op.New` with the four required options. |
| [`examples/fapi2`](examples/fapi2/main.go) | FAPI 2.0 Baseline profile: `op.WithProfile`, PAR / JAR / DPoP features, `private_key_jwt` client with inline JWKs. |
| [`examples/custom-interaction`](examples/custom-interaction/main.go) | Plug a non-default `interaction.Driver` via `op.WithInteraction` — example ships a tiny inline-HTML driver. |

Run any of them with the build tag, e.g.:

```sh
go run -tags example ./examples/minimal
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
`github.com/libraz/go-oidc-provider/op/store`. v1.0 ships an in-memory reference
implementation and a `composite` adapter for hot/cold splits. SQL, Redis, and
DynamoDB adapters land in v1.x as separate sub-modules to keep driver
dependencies opt-in.

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
