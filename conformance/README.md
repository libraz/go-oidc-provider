# go-oidc-provider — OFCS Conformance Harness

This directory carries the artifacts needed to run go-oidc-provider
against the [OpenID Foundation Conformance Suite][ofcs]. Nine plans
are scaffolded:

| Plan file                               | Profile                  | What it exercises                            |
| --------------------------------------- | ------------------------ | -------------------------------------------- |
| `plans/oidcc-basic.json`                | `oidcc-basic`            | Authorization Code + PKCE, ID token, UserInfo |
| `plans/oidcc-config.json`               | `oidcc-config`           | Discovery document + JWKS shape              |
| `plans/oidcc-dynamic.json`              | `oidcc-dynamic`          | Discovery + Dynamic Client Registration      |
| `plans/oidcc-formpost.json`             | `oidcc-formpost-basic`   | Authorization Code + `response_mode=form_post` |
| `plans/oidcc-rp-initiated-logout.json`  | `oidcc-rp-init-logout`   | OpenID Connect RP-Initiated Logout 1.0       |
| `plans/oidcc-back-channel-logout.json`  | `oidcc-back-channel-rp-initiated-logout` | RP-Initiated + back-channel `logout_token` |
| `plans/fapi2-baseline.json`             | `fapi2-baseline`         | + PAR, JAR, DPoP                             |
| `plans/fapi2-message-signing.json`      | `fapi2-message-signing`  | + JARM, signed introspection                 |
| `plans/fapi-ciba.json`                  | `fapi-ciba-id1`          | CIBA poll mode (signed JAR + DPoP)           |

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

## Capturing a baseline

Run every module in every seeded plan and record the pass/fail
outcome to a deterministic JSON snapshot. The intended use is
"freeze the current conformance state, then verify a refactor does
not regress against it":

```sh
# 1) Stack up + plans seeded
make conformance-up

# 2) Capture a labelled snapshot
make conformance-baseline LABEL=pre-loginflow
# → conformance/baselines/<UTC-date>-pre-loginflow.json

# 3) Make changes, capture again
make conformance-baseline LABEL=post-loginflow

# 4) Diff. Exits non-zero on any module that lost PASSED.
make conformance-baseline-diff \
    BASELINE_OLD=conformance/baselines/2026-04-29T01-00-00Z-pre-loginflow.json \
    BASELINE_NEW=conformance/baselines/2026-04-29T05-00-00Z-post-loginflow.json
```

The module list is queried from OFCS at runtime (so a catalog drift
between OFCS releases is captured automatically). Set
`BASELINE_FILTER` to a regex when you only want to baseline a
subset:

```sh
BASELINE_FILTER='^oidcc-' make conformance-baseline LABEL=oidcc-only
```

Snapshot files are gitignored — they record an environment-specific
moment in time and would churn between machines / OFCS bumps. If you
want to commit a single canonical "released" snapshot, copy the
desired file out from under `baselines/` to a path of your choice.

The diff output classifies modules as:

- **regressions** — were `PASSED`, now anything else (exit non-zero)
- **fixes** — were not `PASSED`, now `PASSED`
- **non-pass churn** — both states are non-`PASSED` but differ
- **catalog drift** — module appears in only one snapshot

## Lifecycle commands

| Command                   | What it does                                           |
| ------------------------- | ------------------------------------------------------ |
| `make conformance-up`     | One-shot: certs + OFCS + OP + seed-plans               |
| `make conformance-down`   | One-shot: tear down OP + OFCS, wipe mongo volume       |
| `make conformance-certs`  | Re-generate OP cert / FAPI client material / JKS       |
| `make conformance-ofcs-up`/`-down`/`-status` | OFCS containers only                |
| `make conformance-op-up`/`-down`/`-status`   | `cmd/op-demo` only                  |
| `make conformance-seed-plans`               | Re-create the OFCS plans            |
| `make conformance-baseline LABEL=...`        | Snapshot every module's pass/fail   |
| `make conformance-baseline-diff BASELINE_OLD=... BASELINE_NEW=...` | Compare two snapshots |

## File map

```
conformance/
├── README.md             ← this file
├── docker-compose.yml    ← pinned OFCS stack (mongo + nginx + server)
├── certs/                ← generated TLS material (gitignored, .gitkeep is committed)
├── keys/                 ← FAPI client JWKS used by op-demo (committed)
├── op-demo.log           ← op-demo runtime log (gitignored)
├── op-demo.pid           ← op-demo PID file (gitignored)
├── .plan-ids.json        ← seed-plans output: {plan_name → plan_id} (gitignored)
├── baselines/            ← `baseline` snapshots (gitignored)
└── plans/                ← OFCS plan templates (committed)
    ├── oidcc-basic.json
    ├── oidcc-config.json
    ├── oidcc-dynamic.json
    ├── oidcc-formpost.json
    ├── oidcc-rp-initiated-logout.json
    ├── oidcc-back-channel-logout.json
    ├── fapi2-baseline.json
    ├── fapi2-message-signing.json
    └── fapi-ciba.json
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

## Release sign-off (v0.9.1)

The v0.9.1 release blocker is "every plan lands green at least once,
flake is ruled out for any plan that didn't, and a final pass runs
op-demo under the race detector with zero `WARNING: DATA RACE` hits".
The ceremony is manual; CI does not gate on it because OFCS runtime
exceeds the budget of a hobby-OSS pipeline.

The OP_ENABLE_DCR=1 flag is required for `oidcc-dynamic` and
`oidcc-back-channel-logout` (both use OFCS's dynamic_client variant
to mint per-test client records).

### One-time setup per machine

```sh
make conformance-up                   # certs + OFCS + op-demo + seed-plans
```

For the **logout** and **DCR** plans, restart op-demo with DCR turned
on so OFCS can mint per-test client records:

```sh
OP_ENABLE_DCR=1 make conformance-op-up
# op-demo prints the Initial Access Token to conformance/op-demo.log;
# grep "DCR Initial Access Token" conformance/op-demo.log
```

For the **fapi-ciba** plan, restart with `OP_PROFILE=fapi-ciba` so
the op-demo wires `op.WithCIBA` and the auto-approving substore:

```sh
OP_PROFILE=fapi-ciba make conformance-op-up
```

### Single-pass green ceremony

Run each of the 8 plans through `make conformance-baseline` once.
Use `LABEL=v0.9.1-rc<N>-<plan>` so the file names sort
chronologically.

```sh
# Capture
make conformance-baseline LABEL=v0.9.1-rc1-fapi2-baseline

# Compare against the previous release point
make conformance-baseline-diff \
    BASELINE_OLD=conformance/baselines/2026-05-01T16-42-42Z-pre-v0.9.0-fixed-3.json \
    BASELINE_NEW=conformance/baselines/<latest>.json
```

If a plan regresses on the first try, rerun **only that plan** a
handful of times to distinguish flake from real regression. A flake
is acceptable as long as a subsequent run is green; a deterministic
regression blocks the release.

### Final race-detector pass

After the per-plan green captures, run one more pass with op-demo
built under `-race`. The flag is opt-in so day-to-day iteration
stays fast:

```sh
make conformance-down
OPDEMO_RACE=1 make conformance-up
# … run baseline as above …
make conformance-baseline LABEL=v0.9.1-rc-final-race-<plan>

# After every plan finishes, scan the log for races. A clean run
# prints zero hits.
grep -c "WARNING: DATA RACE" conformance/op-demo.log
```

A non-zero count is a release blocker — investigate before tagging.

### What "green" means here

The diff command exits non-zero on any module that *was* `PASSED` in
the reference and *is no longer* `PASSED` in the new capture. Modules
that were never green (skipped, awaiting review, OFCS-side bug) do
not block the run; they are tracked in
[`docs/plans/013-v0.9.1-plan.md`](../docs/plans/013-v0.9.1-plan.md) §7.

[ofcs]: https://gitlab.com/openid/conformance-suite
