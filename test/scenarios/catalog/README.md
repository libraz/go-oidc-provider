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
| `covered_by`         | no  | `<package path>.<TestFunc>` naming the test that asserts this row from outside the suite. Only valid when `status == active`. |
| `shape`              | no  | `presence` / `value` / `order` / `identity` — what the row demands. Inferred from `behaviour` when omitted. |
| `cross_refs`         | no  | List of `<feature>#<ID>` refs to other rows. |
| `notes`              | no  | Reviewer context (blocked-on, fixture needs, etc.). |
| `out_of_scope_reason`| if `status == out-of-scope` | Brief justification, may reference an ADR. |

File-level `shape_exempt_reason` exempts a file from the shape gate; see
below.

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

## Row shape — what a row demands

Coverage answers whether every row has a test. It cannot answer whether
the rows say enough, and the two are easy to confuse: a file can sit at
100% coverage while asserting nothing an implementation could get
wrong in an interesting way.

A row that says an ID Token "MUST include `auth_time`" is satisfied by
an implementation that emits `auth_time` with the wrong value. Every
row about `auth_time` on the authorization-code path was written that
way, so an exit that reported the wrong authentication time — and
dropped `acr` and `amr` while doing it — passed the whole suite.

`shape` names which of four things a row demands:

| Shape      | The row demands |
|------------|-----------------|
| `presence` | Something appears, or is absent. |
| `value`    | A particular value, or a relationship between two values. |
| `order`    | A sequence: what happens before what, what is consumed once, what may not be replayed. |
| `identity` | Which principal, client, grant or session the thing refers to. |

The field is optional. `make scenario-shape-report` infers a shape from
the `behaviour` text, and the inference only ever moves a row *out* of
`presence` — a sentence it cannot read counts as presence, which makes a
file look thinner rather than richer. Declare `shape:` when the prose is
clear to a reader but not to the inference.

`make scenario-shape` (part of `make verify`) fails a file whose
in-scope rows are all presence-shaped. Out-of-scope rows are excluded
from the count, so a file cannot clear the gate by declaring rows away.
A file that genuinely can only assert presence sets
`shape_exempt_reason` at the file level; a file that later grows a
non-presence row must drop the exemption, which the gate also checks.

The ratio is a scoping signal rather than a target. A file near the top
of the report is one whose coverage number says the least about it, and
is the next place worth reading for a hole.

## Editing

The catalog is intended to be edited via `scripts/scenario.sh`, which
wraps `tools/scenariotool` to enforce schema, ID uniqueness, and
cross-reference integrity:

```sh
scripts/scenario.sh validate              # CI-grade structural check
scripts/scenario.sh list <feature>        # Print rows for one file
scripts/scenario.sh lookup <id>           # Row + bound TestScenario_<id>_* + cross_ref status
scripts/scenario.sh stats [<feature>]     # Severity x status dashboard
scripts/scenario.sh next [-severity P0|P1|P2] [-count N] [<feature>]
                                          # Next pending row(s) with file:line of the t.Skip stub
scripts/scenario.sh flip <id> <status> [-reason "..."]
                                          # Set status to active|pending|out-of-scope (in-place YAML edit)
scripts/scenario.sh coverage [--strict|--check-bindings|--yaml-only]
                                          # Catalog ↔ Go test binding state
                                          # --check-bindings fails on drift between row and test
                                          # --strict additionally fails on skip-only bindings
                                          # --yaml-only skips `go test -list` (use when build is broken)
```

`make scenario-validate`, `make scenario-coverage`,
`make scenario-coverage-yaml-only`, and `make scenario-stats` are the
entry points wired into the developer workflow. `make verify` runs the
validator and `coverage --strict` as part of the pre-merge gate;
`--strict` is a superset of `--check-bindings`, so the tolerant mode
stays available as `make scenario-coverage-bindings` for a tree
mid-change.

Flag-vs-positional ordering follows Go's `flag` package: any `-flag`
arguments must precede positional arguments
(e.g. `scripts/scenario.sh next -severity P0 discovery`, not the
reverse).

Direct hand-edits are permitted — the validator catches drift — but
the script gate is preferred for consistency.

## Citing code from a row

`behaviour`, `notes`, and `out_of_scope_reason` frequently point at the
implementation — an out-of-scope claim is only auditable if a reviewer
can check it against the tree. Two rules make those pointers hold, and
the validator enforces both:

- **Cite `package.Symbol`, never `file.go:123`.** A line number is
  correct until the next edit to the file above it, and nothing about
  the reference changes when it stops being true. Use the package name
  for an exported symbol (`op.WithMTLSProxy`, `store.Client.Resources`)
  and the package path when the symbol is unexported or the name would
  be ambiguous (`internal/clientauth.verifySignature`). Methods and
  struct fields are citable as `Type.Member`.
- **A `package.Symbol` token means "this exists".** The validator
  resolves every one of them against the repository's declarations, so
  a row MUST NOT use that form for something the OP deliberately lacks.
  Name the absent thing in prose instead — "no per-resource token-format
  option", not `op.WithPerResourceFormat` — or the gate will read it as
  a claim and fail.

Audit event names (`grant.error`, `interaction.chooser`) and bare file
paths are left alone: the first are wire strings rather than Go symbols,
and the second do not rot the way a line number does.

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
function that asserts something, or a `covered_by` naming the test that
does. `pending` rows MAY have a `t.Skip("pending: <ID>")` placeholder.
`out-of-scope` rows MAY keep a `t.Skip` stub as a marker where the test
would go — that is the shape the suite uses — but MUST NOT have a test
that runs, because a row declaring the behaviour unreachable and a test
asserting it are not both true.

The coverage gate reads exactly those rules:

- a row with no test at all, and a `TestScenario_*` matching no row,
  both fail;
- a test that runs under an `out-of-scope` row fails;
- a `covered_by` naming a test that no longer exists fails, so
  delegated coverage cannot rot the way a prose reference does;
- a row bound only to a `t.Skip` stub is reported and fails `--strict`,
  which is the mode `make verify` runs; `--check-bindings` tolerates it.

That last rule decides what to do with a row whose behaviour is
reachable but not yet asserted. Because the pre-merge gate is
`--strict`, such a row cannot be parked at `pending` behind a skip
stub — the stub fails the gate. It either gets a real test and goes
`active`, or it stays `out-of-scope` with a reason that is true of the
shipping tree. "Reachable but untested" is not one of the available
answers, which is deliberate: it is exactly the state that lets a gap
sit unnoticed.

## Catalog-adjacent inventories

Files starting with `_` share this directory but do **not** follow the
feature-file shape — they are auxiliary inventories owned by their
own subcommand. The validator skips them.

### `_advisories.yaml` — CVE / GHSA queue

Schema: `_advisories.schema.json`. Pairs the `// Tracks: <id>`
comments scattered through `internal/<feature>/*_test.go` (and any
other Go source under `internal/`, `op/`, `test/`) with their queue
metadata: severity, source URL, threat category (`T-NN`), and status
(`covered` / `tracking` / `out-of-scope`).

The Go source is the source of truth for binding (which test asserts
the structural mitigation). This file is the queue.

```sh
scripts/scenario.sh advisories          # human dashboard
scripts/scenario.sh advisories --check  # exit non-zero on drift / orphan / wrong-status
scripts/scenario.sh advisories --json   # machine-readable
make scenario-advisories                # make wrappers
make scenario-advisories-strict         # --check, also wired into `make verify`
```

Status semantics (enforced by `--check`):

| status | meaning | gate |
|--------|---------|------|
| `covered`      | At least one `// Tracks: <id>` exists in Go source | MUST find ≥1 occurrence; missing → drift |
| `tracking`     | Queued but not yet annotated                      | MUST find 0 occurrences; presence → flip to covered |
| `out-of-scope` | Intentional exclusion (embedder-owned, not OP)    | `out_of_scope_reason` required; presence is allowed |

Orphan detection: a `// Tracks: <id>` that does not have an entry in
this file fails the gate. This forces every advisory reference in the
codebase to be reviewed and categorised.

Workflow when a new advisory lands:

1. Add a row to `_advisories.yaml` with `status: tracking`, plus
   `severity` / `source` / `threat`.
2. Decide whether the structural mitigation already exists.
3. If yes: append `// Tracks: <id>` to the leading comment of the
   relevant `*_test.go` function and flip `status: covered`.
4. If no: write the test first, then 3.
5. Run `make scenario-advisories-strict` to confirm the gate is clean.
