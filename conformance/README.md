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

- Docker / Docker Compose
- `openssl` (for cert generation)
- A local clone of [openid/conformance-suite][ofcs] built with
  `mvn -B clean install` per the OFCS README. The official guidance is
  to run OFCS from that clone; this repository does not bundle a
  vendored copy.

## One-time setup

1. Generate a self-signed cert covering `localhost` and
   `host.docker.internal`:

   ```sh
   make conformance-certs
   ```

   Material lands in `conformance/certs/`. The cert is a 30-day ECDSA
   P-256 self-signed leaf — it is not committed (`*.pem` is gitignored).

2. Bring up OFCS from your local `conformance-suite/` clone:

   ```sh
   cd /path/to/conformance-suite
   docker compose -f docker-compose-dev.yml up -d
   ```

   The OFCS web UI lands at <https://localhost:8443>.

3. Add the cert from step 1 to OFCS's trust store so the suite can
   reach `https://host.docker.internal:9443`. The simplest path is
   to mount `conformance/certs/localhost.pem` into the OFCS container
   and re-run with the suite's `JAVA_TRUST_STORE_PASSWORD` /
   custom-trust env vars; the OFCS README documents the exact knobs.
   This step is empirical and is captured by the **E2-green** wave.

## Running a plan

1. Start `cmd/op-demo` with TLS:

   ```sh
   make conformance-op-up
   ```

   This launches op-demo on `https://127.0.0.1:9443`, seeded with
   redirect URIs for all three plan aliases so you do not have to
   restart between plans. PID lands in `conformance/op-demo.pid`,
   logs in `conformance/op-demo.log`.

2. Open the OFCS web UI, sign in (default localhost has no auth), and
   import one of the JSON files under `plans/`. The aliases are:

   - `go-oidc-oidcc-basic`
   - `go-oidc-fapi2-baseline`
   - `go-oidc-fapi2-msg-signing`

3. Run the imported plan from the OFCS UI. Each module reports
   PASS / WARNING / FAILURE; export the JSON summary when complete.

   For modules that block on the browser-redirect step, copy the
   `Authorize` URL OFCS prints in its log and feed it to the harness:

   ```sh
   scripts/conformance.sh drive 'https://host.docker.internal:9443/oidc/authorize?...'
   ```

   The `drive` sub-command walks op-demo's SSR interaction (login →
   consent), captures the OFCS callback redirect, and posts the
   implicit-bridge body OFCS expects. Override credentials with
   `OFCS_DEMO_USER` / `OFCS_DEMO_PASS` if you have re-seeded the
   demo authenticator.

4. Stop op-demo when done:

   ```sh
   make conformance-op-down
   ```

5. Bring OFCS down from your `conformance-suite/` clone when finished.

## What this scaffolding does **not** do (yet)

- **Headless plan execution via OFCS REST API.** OFCS does expose a
  plan-creation API but the surface and auth knobs change between
  releases. Empirical work — pinning a release tag, encoding the API
  calls, polling for completion, scraping JSON reports — lives in the
  E2-green wave, after we know which release we are targeting and
  which calls actually work.

- **Bundled OFCS image.** The OFCS publishes images intermittently and
  does not version-tag them aggressively; the canonical run is `mvn
  install` + `docker compose` from a local clone. We mirror that.

- **CA trust automation.** Mounting our self-signed cert into OFCS's
  Java trust store is a manual one-time step today. The E2-green wave
  will fold that into `make conformance-up` once we have a known
  working incantation.

## File map

```
conformance/
├── README.md             ← this file
├── certs/                ← generated TLS material (gitignored, .gitkeep is committed)
├── op-demo.log           ← op-demo runtime log (gitignored)
├── op-demo.pid           ← op-demo PID file (gitignored)
└── plans/                ← OFCS plan templates (committed)
    ├── oidcc-basic.json
    ├── fapi2-baseline.json
    └── fapi2-message-signing.json
```

[ofcs]: https://gitlab.com/openid/conformance-suite
