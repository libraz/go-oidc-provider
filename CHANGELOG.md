# Changelog

This project has not yet had a tagged release. Notable changes will be
tracked here in [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
format starting with `v0.9.0`.

The project follows strict [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
from `v1.0.0` onwards; pre-v1.0 minor releases (including the `v0.9.x`
series) may carry breaking changes — see the `Changed` / `Removed`
sections of each release for the migration notes.

## [Unreleased]

## [v0.9.0] — initial public release (planned)

`v0.9.0` is the first publicly tagged release of go-oidc-provider. The
release ships the OIDC Provider core together with the storage adapters
required to run a real deployment. The `v1.0.0` tag is held back until
`v0.9.x` has accumulated production feedback.

The main module and the storage-adapter sub-modules share the same
`v0.9.0` tag. Embedders pull each sub-module independently:

```
go get github.com/libraz/go-oidc-provider@v0.9.0
go get github.com/libraz/go-oidc-provider/op/storeadapter/sql@v0.9.0
go get github.com/libraz/go-oidc-provider/op/storeadapter/redis@v0.9.0
```

### Added

- `op/storeadapter/sql` — sub-module backed by `database/sql`. MySQL 8.4,
  PostgreSQL, and SQLite (`modernc.org/sqlite`, CGO-free) drivers.
  Bundled DDL under `op/storeadapter/sql/schema/{mysql,postgres,sqlite}`.
  Testcontainers harness gated behind `//go:build testcontainers`.
  Implements `store.UserPasswordStore` (FindByUsername / ReadPasswordHash)
  and exposes `*Store.PutUserWithPassword` so embedders can run the
  built-in PrimaryPassword Step against a SQL backend.
- `op/storeadapter/redis` — sub-module backed by `github.com/redis/go-redis/v9`.
  Implements the volatile substores (Sessions, Interactions, ConsumedJTIs).
  TLS + AUTH required by default; plaintext only via `WithDevModeAllowPlaintext`.
- `op/storeadapter/composite` — hot/cold split. `composite.New` validates
  at construction time that every kind in the transactional cluster
  resolves to a single backend, which prevents cross-store rotation
  bugs by structure rather than convention.
- `op.WithMFAEncryptionKey([]byte)` — at-rest encryption for TOTP secrets.
- `op.WithPrometheus(*prometheus.Registry)` — registers OIDC-domain
  counters on the embedder's registry. Exposing `/metrics` and
  HTTP-lifecycle metrics remain the embedder's responsibility.
- Examples 06–09 demonstrate the storage adapters end-to-end. 07, 08,
  and 09 each pair the OP with an rpkit-driven RP and seed a password
  user (demo / demo) so a browser can drive the full Authorization
  Code + PKCE round-trip:
  - `examples/06-sql-store` — SQLite single-node
  - `examples/07-mysql-store` — MySQL-only (every substore in MySQL).
    Ships `compose.yaml` + `Dockerfile`; mysql stays on the internal
    docker network, only the OP container publishes 8080 / 9090.
  - `examples/08-composite-hot-cold` — SQLite durable + inmem volatile
    via composite. Runs as `go run -tags example .` with no external
    services.
  - `examples/09-redis-volatile` — MySQL durable + Redis volatile (the
    canonical hot/cold deployment shape). Ships `compose.yaml` +
    `Dockerfile` that runs the OP, mysql, and redis on a private docker
    network; only the OP container publishes 8080 / 9090.

[Unreleased]: https://github.com/libraz/go-oidc-provider/compare/v0.9.0...HEAD
[v0.9.0]: https://github.com/libraz/go-oidc-provider/releases/tag/v0.9.0
