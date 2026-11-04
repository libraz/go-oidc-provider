# go-oidc-provider

[![CI](https://img.shields.io/github/actions/workflow/status/libraz/go-oidc-provider/ci.yml?branch=main&label=CI)](https://github.com/libraz/go-oidc-provider/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/libraz/go-oidc-provider?include_prereleases&sort=semver&display_name=tag&label=release)](https://github.com/libraz/go-oidc-provider/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/libraz/go-oidc-provider/op.svg)](https://pkg.go.dev/github.com/libraz/go-oidc-provider/op)
[![codecov](https://codecov.io/gh/libraz/go-oidc-provider/branch/main/graph/badge.svg)](https://codecov.io/gh/libraz/go-oidc-provider)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go&logoColor=white)](go.mod)
[![Docs](https://img.shields.io/badge/docs-go--oidc--provider.libraz.net-2563eb)](https://go-oidc-provider.libraz.net)

OpenID Connect Provider (Authorization Server) library for Go. `op.New(...)`
returns a `*op.Provider`, an `http.Handler` with a `Shutdown` method, that
mounts on `net/http`, `chi`, `gin` or any other router. It depends on no
framework and holds no global state, and it targets the FAPI 2.0 Baseline and
Message Signing profiles.

**Documentation: [go-oidc-provider.libraz.net](https://go-oidc-provider.libraz.net)**
— concepts, use cases, the options reference, operations guides, security
posture and the conformance scoreboard. This README covers installation, the
shape of the repository, and the decisions to know about before adopting the
library.

> **Status: `v1.5.0`.** The public `op` surface follows strict
> [Semantic Versioning](https://semver.org/spec/v2.0.0.html) from the 1.0
> release on. Symbols documented with an `Experimental:` marker are exempt.
> Today that is Grant Management, Client ID Metadata Documents, the ID-JAG
> profile (issuing and redeeming Identity Assertion JWT Authorization Grants)
> and the RISC security event types delivered through Shared Signals. Each
> tracks a draft specification whose wire shape may still change. The exempt
> set is inventoried in
> [`api/experimental.txt`](api/experimental.txt), which `make verify`
> regenerates and diffs, so the exempt set cannot grow without review.
> [`CHANGELOG.md`](CHANGELOG.md) carries the migration notes.
>
> This is an independently maintained project, not a vendor product. Every
> release is regressed against the OpenID Foundation conformance suite, but the
> project carries no formal certification and support is best-effort.

## Install

```sh
go get github.com/libraz/go-oidc-provider@v1.5.0
```

Go 1.26+. Storage adapters are published as sub-modules on the same tag, so
their drivers stay out of your `go.sum` until you opt in:

```sh
go get github.com/libraz/go-oidc-provider/op/storeadapter/sql@v1.5.0
go get github.com/libraz/go-oidc-provider/op/storeadapter/redis@v1.5.0
go get github.com/libraz/go-oidc-provider/op/storeadapter/dynamodb@v1.5.0
```

## Quickstart

```go
db, err := sql.Open("mysql", dsn) // your existing database
if err != nil {
    log.Fatal(err)
}
st, err := oidcsql.New(db, oidcsql.MySQL()) // op/storeadapter/sql
if err != nil {
    log.Fatal(err)
}
// Migrate creates or upgrades the OP's tables. Run it once from a deploy job
// (or write the files for your migration tool with `op-schema export`);
// calling it here keeps the example short.
if err := st.Migrate(context.Background()); err != nil {
    log.Fatal(err)
}

keys, err := op.LoadKeyset("signing.pem") // PEM private key
if err != nil {
    log.Fatal(err)
}
cookieKeys, err := op.LoadSymmetricKeys("cookie.key") // 32 bytes, AES-256-GCM
if err != nil {
    log.Fatal(err)
}

handler, err := op.New(
    op.WithIssuer("https://idp.example.com"),
    op.WithStore(st),
    op.WithKeyset(keys),
    op.WithCookieKeys(cookieKeys...),
    op.WithLogger(slog.Default()), // without it, request-time warnings are discarded
    op.WithLoginFlow(op.LoginFlow{
        Primary: op.PrimaryPassword{
            Store: users{db}, // your type with the three methods below
            // LegacySchemes: []op.PasswordHashScheme{op.BcryptHashScheme()}, // uncomment for bcrypt hashes
        },
    }),
    op.WithStaticClients(op.ConfidentialClient{ // the relying party that signs users in
        ID:           "my-app",
        Secret:       os.Getenv("MY_APP_CLIENT_SECRET"),
        RedirectURIs: []string{"https://app.example.com/callback"},
        Scopes:       []string{"openid", "profile", "email"},
    }),
)
if err != nil {
    log.Fatal(err)
}
log.Fatal(http.ListenAndServe(":8080", handler))
```

Generate the keys once:

```sh
openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out signing.pem
openssl rand -hex 32 > cookie.key
```

`users` is your existing users table, read through three methods of
`store.UserPasswordStore`. Each returns `store.ErrNotFound` for an unknown
user:

```go
func (u users) FindBySubject(ctx context.Context, sub string) (*store.User, error)
func (u users) FindByUsername(ctx context.Context, login string) (*store.User, error)
func (u users) ReadPasswordHash(ctx context.Context, sub string) ([]byte, error) // PHC argon2id; bcrypt via PrimaryPassword.LegacySchemes
```

The table gains no column when it already has an opaque identifier assigned
once and never reused (not an auto-increment id or an email address). The
same store supplies the claims: `/userinfo` returns them, and the ID Token
carries them only for the scopes listed in `op.WithIDTokenScopeClaims`, such
as `op.WithIDTokenScopeClaims("profile", "email")`. `op.WithUserStore` is for
claims kept elsewhere. A table of bcrypt hashes needs the
`LegacySchemes` line above: without it every login against such a hash fails,
and the OP logs one WARN that names the field through the logger given to
`op.WithLogger`. See
[Bring your own user store](https://go-oidc-provider.libraz.net/use-cases/byo-userstore).

`st` holds the OP's own records (clients, codes, tokens, sessions) in
`oidc_*` tables next to yours. `op.New` checks the tables your configuration
uses and names every missing one in one error;
[`TABLES.md`](op/storeadapter/sql/schema/TABLES.md) lists them. The adapter
never closes `db`; it stays yours. `go run
github.com/libraz/go-oidc-provider/op/storeadapter/sql/cmd/op-schema export`
writes the migrations as golang-migrate, goose or Flyway files. For an
application that already has a users table and a migration tool, see
[Integrate with an existing database](https://go-oidc-provider.libraz.net/getting-started/existing-db).

Startup inserts a static client that the store lacks and refuses one whose
stored record differs, so an edited client (a new redirect URI, a rotated
secret) is written by `op.SyncStaticClients` from a deploy job before the new
version starts. Production seeds `SecretHash` from
`go run github.com/libraz/go-oidc-provider/cmd/op-client-secret` rather than a
plaintext `Secret`. See
[Client onboarding](https://go-oidc-provider.libraz.net/use-cases/client-onboarding).

Login and consent render the OP's built-in HTML pages until you replace
them: `op.WithUI` takes one mode. `op.SPAUI` hands both to your own SPA,
`op.DriverUI` to your own server-rendered `interaction.Driver`, and
`op.HTMLUI` swaps the template of any one screen (login, consent or account
chooser) while keeping the rest built in.
[Choosing a UI path](https://go-oidc-provider.libraz.net/use-cases/spa-custom-interaction#choosing-a-ui-path)
tabulates which `op.WithUI` value fits which need.
To serve the OP from your existing router rather than its own listener, see
[Mounting the handler](https://go-oidc-provider.libraz.net/getting-started/mount).

`Issuer`, `Store` and `Keyset` are always required. `CookieKeys` and
`LoginFlow` are required whenever the `authorization_code` grant is enabled,
which is the default.
`op.New` returns an error rather than booting in an unsafe configuration, so an
incomplete setup fails at construction time.

The endpoints mount under `/oidc` (`op.WithMountPrefix` moves them), while
the discovery document stays at `/.well-known/openid-configuration` under the
issuer, so that is the first URL to fetch.

A security profile is declared with one option, and the constructor refuses to
start when the declared profile conflicts with the rest of the configuration.
Without one the OP runs `profile.OAuth21`, which requires PKCE on every
authorization-code request. Relying parties that cannot send PKCE need the
OpenID Connect Core shape, which is declared rather than defaulted:

```go
op.WithProfile(profile.FAPI2Baseline) // PAR required, DPoP (or mTLS) bound tokens, ES256 only
op.WithProfile(profile.OIDCCore)      // PKCE optional for confidential clients
```

`FAPI2Baseline` also accepts a client assertion only when its `aud` is the
issuer identifier as a single string, and does not rotate refresh tokens:
refresh responses carry no `refresh_token`, and the one issued stays valid
until it expires.

`profile.OAuth21` is the OAuth 2.1 posture, not FAPI 2.0 Baseline; the FAPI
profiles are `profile.FAPI2Baseline` and `profile.FAPI2MessageSigning`.

Next steps: [Quick Start](https://go-oidc-provider.libraz.net/getting-started/install)
· [Required options](https://go-oidc-provider.libraz.net/getting-started/required-options)
· [Mounting the handler](https://go-oidc-provider.libraz.net/getting-started/mount)
· [Security profiles](https://go-oidc-provider.libraz.net/use-cases/security-profile).
[`examples/01-minimal`](examples/01-minimal/main.go) shows the same setup end to
end, including key generation, store wiring and graceful shutdown.

Not sure which page to open? [Start here](https://go-oidc-provider.libraz.net/getting-started/start-here)
picks the pages and examples that match your goal.

The defaults assume production: https only, public network only.
`http://127.0.0.1` is exempt from the `redirect_uri` and issuer checks, so
most examples run without any development option. The options for
`localhost`, plain-http back-channel receivers and private-network fetches
are listed under
[Running locally](https://go-oidc-provider.libraz.net/getting-started/required-options#running-locally).

## Scope

- **Embeds as `http.Handler`.** Framework-agnostic, mountable at any prefix.
- **Bring your own user model and storage.** Small `store.*` substore
  interfaces; the library never touches your `users` table directly.
- **Headless interaction driver.** Login and consent can be driven from a SPA
  via `op.SPAUI` or rendered by your own `interaction.Driver` through
  `op.DriverUI`, and `op.HTMLUI` replaces the login, consent or chooser
  template alone, all passed to `op.WithUI`. The logout confirmation and signed-out pages are the
  OP's built-in, localised ones unless `op.WithLogoutUI` replaces them with
  your own templates.
- **Audit-first observability.** Business events go through `audit.Emitter`,
  and `op.WithPrometheus(reg)` registers a curated counter set on your
  registry. The library does not mount `/metrics`, install request-duration
  middleware, or wrap your router; that is the embedder's responsibility.

Deliberately out of scope: an IdP (the library does not own your user records
and has no email delivery), a generic OAuth2 framework, and a UI kit. See
[Why this library](https://go-oidc-provider.libraz.net/why).

## Standards

- **Core.** OpenID Connect Core 1.0 and Discovery 1.0; OAuth 2.0 (RFC 6749),
  its Security BCP (RFC 9700) and Authorization Server Metadata (RFC 8414).
- **Request and token hardening.** PKCE (RFC 7636), DPoP (RFC 9449), PAR
  (RFC 9126), JAR (RFC 9101), JARM, issuer identification (RFC 9207), Rich
  Authorization Requests (RFC 9396), step-up authentication (RFC 9470).
- **mTLS (RFC 8705).** Certificate-bound access tokens, and `tls_client_auth`
  and `self_signed_tls_client_auth` client authentication.
- **Grants.** Authorization code, refresh token, client credentials, device
  authorization (RFC 8628), CIBA Core 1.0, token exchange (RFC 8693), JWT bearer
  (RFC 7523), and embedder-defined grants through `op.WithCustomGrant`.
- **Token and client lifecycle.** JWT access tokens (RFC 9068), revocation
  (RFC 7009), introspection (RFC 7662), Dynamic Client Registration and its
  management API (RFC 7591 / RFC 7592).
- **Client registration.** Dynamic Client Registration as above, plus Client ID
  Metadata Documents (experimental, opt-in) for clients that identify
  themselves with an HTTPS URL, such as MCP clients.
- **Session termination.** RP-Initiated Logout 1.0 and Back-Channel Logout 1.0.
  Front-channel logout is not implemented.

FAPI 2.0 Baseline and Message Signing are the target profiles. Per-RFC detail
is in the
[RFC matrix](https://go-oidc-provider.libraz.net/compliance/rfc-matrix), and
every release is regressed against the OpenID Foundation conformance suite,
with results on the
[scoreboard](https://go-oidc-provider.libraz.net/compliance/ofcs).

Two deliberate departures from the specifications:

- **One signing algorithm per OP, ES256 by default.**
  `op.WithSigningAlgorithm(op.AlgRS256)` switches the whole OP to RS256; there
  is no per-client choice.
  [Why](https://go-oidc-provider.libraz.net/security/design-judgments#dj-11)
- **DPoP proof failures use the OAuth error envelope.** Form-post endpoints
  return `400 invalid_request` rather than `invalid_dpop_proof`.
  [Why](https://go-oidc-provider.libraz.net/security/design-judgments#dj-40)

## Storage

Implement the substore interfaces in [`op/store`](op/store) to use your own
backend, or take one of the shipped adapters:

| Adapter | Module | Purpose |
|---|---|---|
| `inmem` | main module | Reference store for development and tests. |
| `sql` | sub-module | `database/sql` for SQLite, MySQL 8.0+, PostgreSQL 14+, with reference DDL embedded per engine and per-release migration files from `Store.Migrations()` or `op-schema export`. |
| `redis` | sub-module | Volatile substores only; refuses to start without TLS and AUTH. |
| `dynamodb` | sub-module | One table per substore, transactional. |
| `composite` | main module | Hot/cold splitter: durable substores to one backend, volatile to another. |

[`op/store/contract`](op/store/contract) is a reusable conformance harness
rather than an internal test. Point it at your backend and it exercises the
semantics the godoc declares, skipping the optional extensions you have not
implemented. The bundled adapters are validated by the same suite.

See [Choosing a storage layout](https://go-oidc-provider.libraz.net/use-cases/storage-decision)
and [Bring your own store](https://go-oidc-provider.libraz.net/use-cases/byo-store).

## Examples

[`examples/`](examples/README.md) holds 50 runnable demos, one option or
feature apiece, each mapped to a
[use-case page](https://go-oidc-provider.libraz.net/use-cases/).

```sh
(cd examples/01-minimal && GOWORK=off go run -tags example .)
```

An example that pulls a dependency beyond the library — a store adapter, a
metrics client — is its own module resolved through a development `replace`
and runs with the repository workspace disabled, like `01-minimal` above. The
rest carry no `go.mod` and run from the checkout as-is; see
[`examples/README.md`](examples/README.md) for the split. Each smoke-tested
example has its own `make example-NN` target; `make example-01` runs
`01-minimal` the same way.

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
