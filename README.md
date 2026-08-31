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

> **Status: `v1.1.0`.** The public `op` surface is under strict
> [Semantic Versioning](https://semver.org/spec/v2.0.0.html) from the 1.0
> release on. The one exemption is symbols documented with an `Experimental:`
> marker; they are inventoried in [`api/experimental.txt`](api/experimental.txt),
> which is regenerated and diffed by `make verify` so the exempt set cannot grow
> without review. Worth knowing before you build on it: the exempt set is the
> authentication-step seam (`LoginFlow`, `WithLoginFlow`, `WithAuthenticators`
> and the hooks around them), the interaction UI types, and Grant Management,
> which tracks an IETF draft. Protocol surface, storage interfaces, and every
> other option are stable. [`CHANGELOG.md`](CHANGELOG.md) tracks notable
> changes from the release that follows `v0.9.0`.
>
> This is a spare-time project, not a vendor product. It is regressed against
> the OpenID Foundation conformance suite on every release, but it carries no
> formal certification, and support is best-effort.

## Install

```sh
go get github.com/libraz/go-oidc-provider/op@v1.1.0
```

Go 1.25+. Storage adapters are published as sub-modules so their
dependencies stay out of your `go.sum` until you opt in:

```sh
go get github.com/libraz/go-oidc-provider/op/storeadapter/sql@v1.1.0
go get github.com/libraz/go-oidc-provider/op/storeadapter/redis@v1.1.0
go get github.com/libraz/go-oidc-provider/op/storeadapter/dynamodb@v1.1.0
```

## Quickstart

`op.New` always requires `Issuer`, `Store`, and `Keyset`. `CookieKeys` is also
required when the `authorization_code` grant is enabled, which is the default
grant set. The constructor returns an error rather than booting in an unsafe
configuration, so partial setups fail fast.

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

`WithLoginFlow` declares how a browser session authenticates. It is not part
of the required set — an OP serving only `client_credentials` has no user to
authenticate — but a provider that mounts the authorize endpoint without one
has no credential to prompt for, and the first request that needs an
interaction answers `server_error`. Start from `op.PrimaryPassword` and add
factors as rules
([`examples/20-mfa-totp`](examples/20-mfa-totp/main.go) composes a second
factor onto the same flow).

End-to-end startup (key generation, store wiring, graceful shutdown) lives in
[`examples/01-minimal`](examples/01-minimal/main.go); see also
[Quick Start](https://go-oidc-provider.libraz.net/getting-started/install) and
[Required options](https://go-oidc-provider.libraz.net/getting-started/required-options).

### Local development

The defaults are tuned for production (https-only, public-network-only), but a
loopback IP literal is already carved out: `http://127.0.0.1:8080` is a valid
issuer and a valid `redirect_uri` host with no options at all. That is why most
examples under [`examples/`](examples) need neither opt-in below — they bind
`127.0.0.1` throughout.

Two narrower opt-ins exist for the cases the IP literal does not cover:

```go
op.WithAllowLocalhostLoopback(),                 // admit the textual host "localhost"
op.WithAllowInsecureBackchannelLogoutForDev(),   // admit an http:// backchannel_logout_uri
```

`WithAllowLocalhostLoopback` is needed only when something in the wiring must
be spelled `localhost` rather than `127.0.0.1` — 9 of the 44 examples reach for
it, mostly because a stub RP registers a `http://localhost:…/callback`
`redirect_uri`, and [`29-passkey`](examples/29-passkey/main.go) because WebAuthn
requires a Relying Party ID that is a domain and browsers reject an IP literal
for it. The textual host is not in the default carve-out because `localhost`
resolution can be hijacked (RFC 8252 §7.3).

`WithAllowInsecureBackchannelLogoutForDev` is needed only to register a
plain-http `backchannel_logout_uri`, which 1 of the 44 examples does
([`42-back-channel-logout`](examples/42-back-channel-logout/main.go)).

Both are dev / CI-only. Add neither unless the validator has actually rejected
your wiring, and drop them when porting a demo into a production stack.

### Security profiles in one switch

```go
op.WithProfile(profile.Baseline)      // OAuth 2.1: PKCE on every code request
op.WithProfile(profile.FAPI2Baseline) // PAR + JAR + DPoP, ES256, alg lock
```

Declaring no profile is a configuration too: it is the OpenID Connect Core 1.0
shape, which predates RFC 7636 and leaves PKCE optional for confidential
clients. `profile.Baseline` is how a deployment states the stricter posture on
purpose instead of inheriting the permissive one by omission.

The constructor refuses to start when the declared profile and the rest of the
options conflict, including a profile that names a flow the OP has not been
wired to serve. Every constructed provider emits one `startup.profile` audit
record carrying the declared profiles, features and grants alongside the policy
they resolved to. See
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

Core: OpenID Connect Core 1.0; OAuth 2.0 (RFC 6749) and the Security Best
Current Practices (RFC 9700); OAuth 2.0 Authorization Server Metadata
(RFC 8414) alongside OpenID Connect Discovery 1.0.

Request and token hardening: PKCE (RFC 7636), DPoP (RFC 9449), PAR (RFC 9126),
JAR (RFC 9101), JARM, mTLS (RFC 8705), authorization-response issuer
identification (RFC 9207), Rich Authorization Requests (RFC 9396),
step-up authentication (RFC 9470); FAPI 2.0 Baseline / Message Signing.

Additional grants: Device Authorization Grant (RFC 8628), Client-Initiated
Backchannel Authentication (CIBA Core 1.0), Token Exchange (RFC 8693), plus
embedder-defined grants through `op.WithCustomGrant`.

Token and client lifecycle: JWT-profile access tokens (RFC 9068), token
revocation (RFC 7009), token introspection (RFC 7662), Dynamic Client
Registration and its management API (RFC 7591 / RFC 7592, OpenID Connect
Dynamic Client Registration 1.0).

Session termination: OpenID Connect RP-Initiated Logout 1.0 and Back-Channel
Logout 1.0. Front-channel logout is not implemented.

Each release is regressed against the OpenID Foundation conformance suite —
the live scoreboard is on the
[conformance results page](https://go-oidc-provider.libraz.net/compliance/ofcs).
A per-RFC matrix is at
[Compliance — RFC matrix](https://go-oidc-provider.libraz.net/compliance/rfc-matrix).

**One deliberate departure: signing is ES256 only.** ID tokens, JWT access
tokens, signed UserInfo and JARM responses are all signed with ES256, and
that is permanent rather than a staged rollout. OpenID Connect Core §15.1
makes RS256 mandatory to implement, so this is a knowing departure from the
letter of the specification: a relying party that can only verify RS256 is
not supported. The trade is one vetted curve with no algorithm negotiation
and therefore no downgrade path to defend, and ES256 is a first-class
algorithm in the FAPI 2.0 profiles this library targets — which exclude
RS256 outright. *Verification* is wider: RS256, PS256, ES256 and EdDSA are
all accepted on client assertions and request objects.

**A second departure: a rejected DPoP proof answers in the OAuth error
envelope.** RFC 9449 §7 defines `invalid_dpop_proof`, but every endpoint that
accepts a proof on a form post — token, PAR, device authorization and CIBA —
returns HTTP 400 with `error=invalid_request`, the envelope those endpoints
already use for every other failure, so a relying party keying off the OAuth
error codes needs no additional code class. The
`error_description` separates the failure families (`DPoP proof malformed`,
`DPoP proof signature invalid`, `DPoP proof does not bind to this request`,
`DPoP proof iat outside acceptable window`, `DPoP proof replayed`) without
naming the precise sub-cause, which would tell a prober which check it
reached. Two cases keep their own code, because collapsing them would cost the
client information it has to act on: the §8 nonce challenge answers
`error=use_dpop_nonce` with a `DPoP-Nonce` response header so a retry is
distinguishable from a terminal failure, and a proof rejected at a protected
resource answers `401 invalid_token` under the Bearer-token error rules that
govern that surface.

## Storage

Bring your own backend by implementing the substore interfaces in
[`op/store`](op/store). The repository ships:

| Adapter | Module path | Purpose |
|---|---|---|
| `inmem` | `op/storeadapter/inmem` | Reference / dev / test store. The contract harness in [`op/store/contract`](op/store/contract) runs against it. |
| `sql` | `op/storeadapter/sql` | `database/sql` adapter for SQLite, MySQL 8.0+, PostgreSQL 14+. **Sub-module.** Contract harness exercises every substore against a real engine via testcontainers (`go test -tags=testcontainers`). |
| `redis` | `op/storeadapter/redis` | Volatile substores (`InteractionStore`, `ConsumedJTIStore`, `SessionStore`). **Sub-module.** Redis TTL governs sessions; compose with a durable backend for grants and credentials. Refuses to start without TLS (`rediss://`) and AUTH unless `WithDevModeAllowPlaintext` is set explicitly. |
| `dynamodb` | `op/storeadapter/dynamodb` | DynamoDB adapter, one table per substore. Implements `store.Transactional` by buffering writes and committing them as one `TransactWriteItems`, so the browser authorization-code flow runs on DynamoDB alone. **Sub-module.** Contract harness runs against `amazon/dynamodb-local` (`go test -tags=testcontainers`). Marked `Experimental:`, so it is listed in [`api/experimental.txt`](api/experimental.txt) and exempt from the SemVer promise. |
| `composite` | `op/storeadapter/composite` | Hot/cold splitter — durable substores to one backend, volatile to another, while enforcing the transactional-cluster invariant. |

**Verify your backend against the contract suite.**
[`op/store/contract`](op/store/contract) is a reusable conformance harness, not
an internal test: point it at your backend and it exercises the semantics the
godoc declares — sentinel errors, single-use consumption, hash-on-store for
bearer secrets — and skips each optional extension you have not implemented.
The bundled adapters are validated by the same suite. Which extensions the OP
requires, and what turns each requirement on, is tabulated in the
[`op/store` package documentation](https://pkg.go.dev/github.com/libraz/go-oidc-provider/op/store);
a missing required extension is rejected by `op.New` rather than at request time.

**Authentication-factor stores.** The factors a login flow can require — TOTP,
passkey, recovery codes, email OTP, and the cross-factor brute-force lockout
counter — are separate substores (`store.TOTPStore`, `store.PasskeyStore`,
`store.RecoveryStore`, `store.EmailOTPStore`, `store.AuthnLockoutStore`)
injected through the authenticator config rather than reached through
`store.Store`: a deployment that never enables a second factor should not have
to provision their tables. The `inmem`, `sql`, and `dynamodb` adapters all
implement them, under accessors of the same name (`TOTPs()`, `Passkeys()`,
`RecoveryCodes()`, `EmailOTPs()`, `AuthnLockouts()`), so the three are drop-in
interchangeable:

```go
op.WithAuthnLockoutStore(st.AuthnLockouts())
op.StepTOTP{Store: st.TOTPs(), EncryptionKey: mfaKey}
```

Their contracts are pinned by the same harness as everything else
(`contract.RunTOTPs`, `RunPasskeys`, `RunRecoveryCodes`, `RunEmailOTPs`,
`RunAuthnLockouts`), so a bring-your-own implementation can be verified the
same way — [`examples/26-byo-store-from-scratch`](examples/26-byo-store-from-scratch/main.go)
is the worked example of doing that for a backend the repository does not ship.
[`examples/27-durable-mfa-store`](examples/27-durable-mfa-store/main.go) shows
the shipped path: factor tables and core tables on one database, one migration,
one connection pool.

**Provisioning the schema.** The `sql` adapter embeds reference DDL for each
engine under
[`op/storeadapter/sql/schema/{sqlite,mysql,postgres}/v1.sql`](op/storeadapter/sql/schema)
— readable straight from the repository if you want your DBA to review it
before adopting the library. `Store.Schema()` returns the DDL for the
configured dialect with any `WithNaming` table renames already applied, so it
can be fed to your migration tooling or diffed against the schema you already
run. `Store.Migrate(ctx)` applies it to the live connection instead; it is a
development convenience used by the examples and tests, and production
deployments are expected to keep migrations under their own tooling. The
authentication-factor tables are part of the same DDL, so enabling a second
factor needs no separate migration. DynamoDB mirrors the split:
`TableDefinitions()` returns the key schemas for CloudFormation or Terraform,
`CreateTables(ctx)` provisions them for development and tests.

## Examples

Runnable demos live under [`examples/`](examples/README.md) — see that index
for the full goal-oriented table, the numeric topic bands, and the docker
stacks shipped with `07-mysql-store`, `09-redis-volatile`,
`17-spa-composite-store`, and `18-dynamodb-store`. Each row also
maps to a use-case page on the docs site under
[Use cases](https://go-oidc-provider.libraz.net/use-cases/).

```sh
(cd examples/01-minimal && GOWORK=off go run -tags example .)
```

Each example is its own module resolved through a development `replace`, so it
is run with the repository workspace disabled; `make example-01` does the same.

## Reference application

[`sample/`](sample/README.md) is the counterpart to the numbered examples: one
worked application instead of one option apiece. It owns its accounts, embeds
the OP in the same process, and completes the round-trip against a relying
party, with MySQL for the durable substores and Redis for the volatile ones
joined through `op/storeadapter/composite`. It boots from
`docker compose -f sample/compose.yaml up -d --build`, and it is a
demonstration — not something to host publicly.

## Community

- [SECURITY.md](.github/SECURITY.md) — vulnerability reporting policy and supported
  versions.
- [CONTRIBUTING.md](.github/CONTRIBUTING.md) — contribution mechanics, Conventional
  Commits scopes, test layering expectations.
- [CODE_OF_CONDUCT.md](.github/CODE_OF_CONDUCT.md) — Contributor Covenant 2.1 and the
  project's reporting channel.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Third-party dependency
licenses are tracked in [`THIRD_PARTY.md`](THIRD_PARTY.md), regenerated from
`go.mod` by `make licenses`.
