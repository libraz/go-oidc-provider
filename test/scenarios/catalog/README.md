# Spec scenario catalog

This directory is the source of truth for the Spec Scenario Suite.
Each `<feature>.yaml` file enumerates RFC-bound scenario rows; the
`TestScenario_<PREFIX>_<NNN>_<Slug>` functions in
`test/scenarios/<feature>_test.go` bind to those rows 1:1.

The catalog is committed alongside the tests so that contributors get
the spec contract without having to hunt for external research notes.

## File shape

| Top-level key | Required | Notes |
|---------------|---------|-------|
| `feature`     | yes | snake_case slug; must equal the filename without `.yaml`. |
| `prefix`      | yes | Uppercase token, unique across every catalog file. |
| `title`       | yes | One-line human-readable feature name. |
| `specs`       | yes | List of spec citations covering the file as a whole. |
| `description` | no  | Multi-line context. Plain English. |
| `rows`        | yes | List of scenario rows (see below). |

Per row:

| Row key              | Required | Notes |
|----------------------|---------|-------|
| `id`                 | yes | `<prefix>(-<sub_prefix>)*-<NNN>` — stable, never reuse. |
| `severity`           | yes | `P0` / `P1` / `P2`. |
| `spec`               | yes | Specific RFC clause or OIDC § the row binds to. |
| `behaviour`          | yes | Plain-English expected behaviour, imperative voice. |
| `status`             | no  | `active` / `pending` / `out-of-scope` (default `pending`). |
| `cross_refs`         | no  | List of `<feature>#<ID>` refs to other rows. |
| `notes`              | no  | Reviewer context (blocked-on, fixture needs, etc.). |
| `out_of_scope_reason`| if `status == out-of-scope` | Brief justification, may reference an ADR. |

Severity grading:

- **P0** — security / spec compliance. A misimplementation would be a
  vulnerability or a compliance failure.
- **P1** — correctness / interop. A misimplementation would be a bug
  visible to RPs.
- **P2** — error shape / UX / observability. A misimplementation would
  be unpleasant but not breaking.

`schema.json` carries the JSON Schema definition (consumable by IDEs
that follow the `# yaml-language-server: $schema=...` directive at
the top of every catalog file).

## Editing

The catalog is intended to be edited via `scripts/scenario.sh`, which
wraps `tools/scenariotool` to enforce schema, ID uniqueness, and
cross-reference integrity:

```sh
scripts/scenario.sh validate         # CI-grade structural check
scripts/scenario.sh list <feature>   # Print rows for one file
scripts/scenario.sh lookup <id>      # Resolve a single ID across all files
scripts/scenario.sh coverage         # Catalog ↔ Go test binding state
```

`make scenario-validate` and `make scenario-coverage` are the entry
points wired into the developer workflow. `make verify` runs the
validator as part of the pre-merge gate.

Direct hand-edits are permitted — the validator catches drift — but
the script gate is preferred for consistency.

## Naming conventions

- File names match `feature` field exactly: `discovery.yaml`,
  `authorization_code.yaml`, `client_id_metadata_document.yaml`.
- IDs are sequential within a prefix; gaps are allowed (a deleted row
  leaves its number retired). Sub-prefixes (`CA-CSJWT-11`) are
  used when one feature area splits into multiple test families.
- `cross_refs` use forward references freely; the validator only
  fails on a missing target ID.

## Status workflow

```
   pending  ── add a test ──▶  active
       │
       └── decide it's not ours ──▶  out-of-scope (with reason)
```

`active` rows MUST have a corresponding `TestScenario_<id>_<slug>`
function. `pending` rows MAY have a `t.Skip("pending: <ID>")`
placeholder. `out-of-scope` rows MUST NOT have a Go function and are
allowlisted in the coverage diff.
