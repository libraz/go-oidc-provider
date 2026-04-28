# go-oidc-provider — OFCS Conformance Harness

This directory carries the artifacts needed to run go-oidc-provider
against the [OpenID Foundation Conformance Suite][ofcs]. Three plans
are scaffolded:

| Plan file                               | Profile                  | What it exercises                            |
| --------------------------------------- | ------------------------ | -------------------------------------------- |
| `plans/oidcc-basic.json`                | `oidcc-basic`            | Authorization Code + PKCE, ID token, UserInfo |
| `plans/fapi2-baseline.json`             | `fapi2-baseline`         | + PAR, JAR, DPoP                             |
| `plans/fapi2-message-signing.json`      | `fapi2-message-signing`  | + JARM, signed introspection                 |

## Prerequisites

- Docker (Compose v2 — invoked as `docker compose`)
- `openssl` (for cert generation)
- `curl` and `python3` (for the drive/seed-plans scripts)

OFCS itself is pulled as a pre-built image from
`registry.gitlab.com/openid/conformance-suite` at the tag pinned in
[`docker-compose.yml`](docker-compose.yml). No separate OFCS checkout
or `mvn install` step is required.

## One command from a clean clone

```sh
make conformance-up
```

That target runs, in order:

1. `scripts/conformance.sh certs` — self-signed RSA-2048 cert for the
   OP listener (covers `localhost` + `host.docker.internal`), a pair
   of RSA-2048 PKCS#8 client cert/key files for the FAPI 2.0 mtls /
   mtls2 plan slots, and a JKS truststore that bundles the system
   cacerts plus the OP cert. Material lands in `conformance/certs/`
   and is gitignored.
2. `scripts/conformance.sh ofcs-up` — `docker compose up -d` against
   `conformance/docker-compose.yml`. The compose file mounts the JKS
   from step 1 into the OFCS server container and points the JVM at
   it via `JAVA_EXTRA_ARGS`, so the suite trusts the OP without any
   manual trust-store ceremony. Waits for `https://localhost:8443`
   to answer.
3. `scripts/conformance.sh op-up` — builds and launches `cmd/op-demo`
   on `https://127.0.0.1:9443`, seeded with redirect URIs for all
   three plan aliases. PID lands in `conformance/op-demo.pid`, logs
   in `conformance/op-demo.log`.
4. `scripts/conformance.sh seed-plans` — POSTs each plan template
   from `plans/` to OFCS via its REST API, injecting mtls/mtls2 PEM
   material into the FAPI 2.0 plans. Prints the resulting plan IDs.

Tear everything down (including the mongo volume that holds OFCS
state) with:

```sh
make conformance-down
```

## Running modules

```sh
# Multiple modules at once. Pass a plan-id printed by seed-plans.
scripts/conformance.sh batch <plan-id> oidcc-server oidcc-userinfo-get ...

# Single browser-driven flow (e.g. when iterating on a particular module
# from the OFCS UI; copy the "Browser" URL it prints):
scripts/conformance.sh drive 'https://host.docker.internal:9443/oidc/authorize?...'
```

`OFCS_DEMO_USER` / `OFCS_DEMO_PASS` override the default `demo` / `demo`
credentials. `OFCS_DRIVE_REJECT=1` simulates the user cancelling the
consent screen (used by `*user-rejects-authentication*` modules; the
batch sub-command sets it automatically based on the test name).

The OFCS web UI is at <https://localhost:8443>; pre-built plan
templates can also be imported there manually if you prefer the UI to
the REST seed-plans path.

## Lifecycle commands

| Command                   | What it does                                           |
| ------------------------- | ------------------------------------------------------ |
| `make conformance-up`     | One-shot: certs + OFCS + OP + seed-plans               |
| `make conformance-down`   | One-shot: tear down OP + OFCS, wipe mongo volume       |
| `make conformance-certs`  | Re-generate OP cert / FAPI client material / JKS       |
| `make conformance-ofcs-up`/`-down`/`-status` | OFCS containers only                |
| `make conformance-op-up`/`-down`/`-status`   | `cmd/op-demo` only                  |
| `make conformance-seed-plans`               | Re-create the OFCS plans            |

## File map

```
conformance/
├── README.md             ← this file
├── docker-compose.yml    ← pinned OFCS stack (mongo + nginx + server)
├── certs/                ← generated TLS material (gitignored, .gitkeep is committed)
├── keys/                 ← FAPI client JWKS used by op-demo (committed)
├── op-demo.log           ← op-demo runtime log (gitignored)
├── op-demo.pid           ← op-demo PID file (gitignored)
└── plans/                ← OFCS plan templates (committed)
    ├── oidcc-basic.json
    ├── fapi2-baseline.json
    └── fapi2-message-signing.json
```

## Bumping the pinned OFCS release

`docker-compose.yml`'s `IMAGE_TAG` default is the canonical pin. To
move forward:

```sh
# Override per-invocation:
IMAGE_TAG=release-vX.Y.Z make conformance-up

# Or edit conformance/docker-compose.yml and commit the new default.
```

OFCS test logic does drift between releases (module renames, condition
strictness changes, new variants); rerun the batch spot-check after
any bump and update `scripts/conformance.sh` if a module needs a
different driver hint.

[ofcs]: https://gitlab.com/openid/conformance-suite
