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

```go
package main

import (
    "log"
    "net/http"

    "github.com/libraz/go-oidc-provider/op"
)

func main() {
    handler, err := op.New(
        op.WithIssuer("https://idp.example.com"),
        // op.WithKeyset(...), op.WithClientStore(...), ...
    )
    if err != nil {
        log.Fatal(err)
    }
    log.Fatal(http.ListenAndServe(":8080", handler))
}
```

`op.New` returns a standard `http.Handler` and is framework-agnostic. Mount it on
any router (`net/http`, `chi`, `gin`, …) at the path of your choice.

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

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
