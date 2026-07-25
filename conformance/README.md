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

`conformance-baseline-diff` is a regression-reporting command, not a release
gate. Its output classifies modules as:

- **regressions** — were `PASSED`, now anything else (exit non-zero)
- **fixes** — were not `PASSED`, now `PASSED`
- **non-pass churn** — both states are non-`PASSED` but differ
- **catalog drift** — module appears in only one snapshot

In particular, a module that is `FAILED` in both snapshots is not a new
regression and does not make this command fail. Use the strict release verifier
described below for release sign-off.

## Capturing a deployment-shaped baseline

The automated gate runs the OP on its in-memory store, which keeps a
conformance run free of external state. `op-demo` can also run on the
storage split a deployment uses — durable substores on MySQL, volatile
ones on Redis — so the same module set can be captured against that
shape. The store adapters are already validated against real engines by
the contract suite (`scripts/test_contracts.sh`); this covers what that
cannot, which is the composite router under protocol load.

Bring the engines up yourself, then:

```sh
export OP_STORE=composite
export OP_MYSQL_DSN='opdemo:opdemo@tcp(127.0.0.1:3306)/opdemo?parseTime=true&charset=utf8mb4&loc=UTC'
export OP_REDIS_DSN='redis://127.0.0.1:6379/0'

make conformance-op-down && make conformance-op-up
make conformance-baseline LABEL=composite
```

The schema migrates on startup and the demo user is upserted, so a fresh
database needs no preparation. Reset both engines between captures:
records surviving a previous run change what the replay and reuse
modules observe.

This capture is manual and is not part of the release gate. Running it
twice — once per backend — would double the gate's wall-clock for
evidence that only changes when the adapters or the router change.

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
| `make conformance-release-verify BASELINE_REFERENCE=... BASELINE_CANDIDATE=...` | Strict release gate |

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
├── release-exclusions.json ← reviewed, time-bounded non-PASS exceptions
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

## Strict release sign-off

Release sign-off uses `conformance-release-verify`; a successful
`conformance-baseline-diff` is not sufficient. The strict verifier requires:

- the candidate and approved reference to contain exactly the same plan/module
  catalog;
- every candidate module to be `FINISHED/PASSED`, unless its exact
  plan/module/status/result tuple is present in the exclusion manifest;
- no empty status or result;
- no stale, missing, duplicate, or expired exclusion; and
- the exclusion manifest to be tracked and byte-for-byte unchanged from
  `HEAD`.

Any violation exits non-zero. An OFCS catalog addition or removal therefore
requires explicit review and a new approved reference; it cannot disappear
inside an otherwise green comparison.

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

### Capture and verify

Run all nine seeded plans in one baseline capture. The driver restarts op-demo
with the required profile between plans. Keep the previously approved snapshot
as the reference and capture the release candidate separately.

```sh
# Capture the release candidate.
make conformance-baseline LABEL=v0.10.0-rc1

# Optional diagnostics: report new regressions and fixes.
make conformance-baseline-diff \
    BASELINE_OLD=conformance/baselines/<approved-reference>.json \
    BASELINE_NEW=conformance/baselines/<v0.10.0-rc1>.json

# Required release gate.
make conformance-release-verify \
    BASELINE_REFERENCE=conformance/baselines/<approved-reference>.json \
    BASELINE_CANDIDATE=conformance/baselines/<v0.10.0-rc1>.json
```

The default policy is
[`conformance/release-exclusions.json`](release-exclusions.json). Override it
only when verifying a historical release:

```sh
make conformance-release-verify \
    BASELINE_REFERENCE=conformance/baselines/<approved-reference>.json \
    BASELINE_CANDIDATE=conformance/baselines/<candidate>.json \
    CONFORMANCE_EXCLUSIONS=conformance/<historical-exclusions>.json
```

An exclusion is an exact, temporary release-policy decision. Each entry must
name the observed terminal state and include a non-empty reason, owner, and
exclusive ISO expiry date:

```json
{
  "schema": "go-oidc-provider/conformance-exclusions/v1",
  "exclusions": [
    {
      "plan": "oidcc-dynamic-certification-test-plan",
      "module": "exact-ofcs-module-name",
      "status": "FINISHED",
      "result": "SKIPPED",
      "reason": "Implicit flow is outside the documented product profile.",
      "owner": "conformance-maintainers",
      "expires": "2026-10-01"
    }
  ]
}
```

On and after `expires`, the verifier blocks the release. A changed outcome also
blocks until the module passes or reviewers update and commit the policy.
Broad prose exceptions, a local uncommitted manifest, and rerunning until one
module happens to pass do not satisfy the gate.

### Final race-detector pass

After the per-plan green captures, run one more pass with op-demo
built under `-race`. The flag is opt-in so day-to-day iteration
stays fast:

```sh
make conformance-down
OPDEMO_RACE=1 make conformance-up
# … run baseline as above …
make conformance-baseline LABEL=v0.10.0-rc-final-race

# After every plan finishes, scan the log for races. A clean run
# prints zero hits.
grep -c "WARNING: DATA RACE" conformance/op-demo.log
```

A non-zero count is a release blocker — investigate before tagging.

[ofcs]: https://gitlab.com/openid/conformance-suite
