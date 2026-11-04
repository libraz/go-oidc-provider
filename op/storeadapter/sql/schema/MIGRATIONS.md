# SQL adapter schema migrations

The SQL lives in `schema/migrations/{sqlite,mysql,postgres}/`, one file per
release in golang-migrate's `NNNNNN_<version>.up.sql` form.
`000001_v1.0.0.up.sql` creates the schema v1.0.0 shipped; each later file
applies one release's changes. `Store.Migrations()` returns the configured
dialect's files with the `WithTablePrefix` and `WithNaming` table names applied,
so a migration tool can read them directly; take the files from it rather than
from the repository when the names differ from the defaults. `TABLES.md` lists
what each table holds and when the OP uses it.

There are two ways to apply them, and a database can move from the first to the
second without a reset.

## Applying with Store.Migrate

`Store.Migrate(ctx)` applies the files in order and records progress in a
version table named `<prefix>schema_migrations` (`oidc_schema_migrations` by
default; the `schema_migrations` `WithNaming` key names it outright). The table has golang-migrate's layout: one row, `version` (the number
of the last file applied) and `dirty`. Run it once from a deploy job, not at
every replica's start, with a context long enough for the DDL: on MySQL the
v1.3.0 file rewrites the collation of every table that holds identifiers.

- **An empty database** gets every file. **A recorded database** gets only the
  files after its version, so running `Migrate` again changes nothing.
  `op.New` never calls it.
- **A database with the adapter's tables but no version table** (created by
  an earlier `Migrate`, `Store.Schema()` or `v1.sql`) is recorded at the current
  release when `ValidateSchema` finds nothing wrong. Otherwise `Migrate` changes
  nothing and returns the schema problems plus one of two instructions. When
  only columns or tables are missing, the error gives the statement that records
  the release the schema is at, for example `INSERT INTO oidc_schema_migrations
  (version, dirty) VALUES (4, false);`; run it and call `Migrate` again. The
  release is estimated from missing columns and tables only, so check it
  against the schema. When indexes or collations are also wrong (MySQL), the
  error names the migrations to apply first instead of an `INSERT`. A column
  you added yourself under the name a later release adds passes the check and
  is recorded; rename it before the first run.
- **A version newer than this release** is not an error: nothing is applied and
  `ValidateSchema` decides, so a replica of an older build restarted during a
  rollout keeps working.
- **Dirty recovery.** On MySQL, whose DDL cannot be rolled back, a file that
  fails part-way leaves the row at that file's number with `dirty = true`; the
  error names the file, the statement number and the statement. Every
  `Migrate` then stops with `version table <t> is dirty at version <n>` until
  you have checked which statements applied, finished or undone them by hand,
  and run `UPDATE oidc_schema_migrations SET version = <n>, dirty = false`
  (or `migrate force <n>`). On SQLite and PostgreSQL a file and its version
  update share one transaction, so a failure leaves nothing behind. A context
  that expires part-way through a MySQL file leaves it dirty the same way.
- **Locks.** On MySQL and PostgreSQL `Migrate` holds an advisory lock whose key
  is derived as golang-migrate derives it, so two `Migrate` calls, or `Migrate`
  and golang-migrate, never run together; the second waits until its context
  ends. SQLite serializes writers with `BEGIN IMMEDIATE`; set `busy_timeout` on
  the DSN. Behind pgbouncer, use session pooling or a direct connection:
  transaction pooling does not hold an advisory lock.
- **Empty prefix.** `WithTablePrefix("")` makes `Migrate` refuse, because the
  version table would be `schema_migrations`, golang-migrate's default table
  and the application's own history. Name the table through
  `WithNaming(map[string]string{"schema_migrations": "..."})`, or apply
  `Store.Migrations()` with a migration tool instead.
- **PostgreSQL schema.** The version table and the lock live in the first
  `search_path` schema (`current_schema()`), as golang-migrate's do. Keep the
  OP's tables in that schema.
- MySQL does not need `multiStatements=true` for `Migrate`, which runs one
  statement at a time.

`Store.Schema()` and `schema/<dialect>/v1.sql` are the reference for the
complete current schema, for diff review; the `v1` names the schema
generation, not release v1.0.0. They do not create a database.

## Applying with your own tool

Apply every file from `Store.Migrations()` in order, recording versions in a
table of your tool's.

- **A new database** applies every file in order.
- **An existing database** is first recorded at the last release it applied,
  then takes only the later files. With golang-migrate that is
  `migrate force <N>`: a database created by v1.2.0 runs `migrate force 3`,
  after which `migrate up` applies v1.3.0 onwards. Run it against the OP's own
  version table (see [Coexisting with your application's
  migrations](#coexisting-with-your-applications-migrations)), never the
  application's.
- Each file holds several statements. golang-migrate enables multi-statement
  execution by itself for a `mysql://` URL; a `*sql.DB` passed to
  `mysql.WithInstance` needs `multiStatements=true` in its own DSN.
- Atlas reads the directory with `format=golang-migrate` once
  `atlas migrate hash` has written its `atlas.sum`.

A team that used `Store.Migrate` and moves to golang-migrate points
`x-migrations-table=oidc_schema_migrations` (or `<prefix>schema_migrations`)
at the table `Migrate` wrote and runs `migrate up`; no `migrate force` is
needed. The reverse also works.

## Checks after applying

After applying, `op.New` checks at construction the tables the configuration
uses and fails naming any that is missing. `Store.ValidateSchema` checks every
table, for a CI or deploy gate (`Store.Migrate` runs it too). A missing column
fails either check with the migration that adds it, for example
`oidcsql: schema for oidc_clients is missing required columns:
previous_secret_hash, previous_secret_expires_at; apply migration 000006_v1.5.0
(schema/migrations/mysql/000006_v1.5.0.up.sql)`. On MySQL both also check that
the identifier columns use a binary collation. Both also check that every
column `schema/<dialect>/v1.sql` leads an index with leads an index of the
table, under any index name: an index of your own, or a composite one with the
same leading column, passes. A missing one fails with `oidcsql: <table> has no
index on <column>`; apply the migration that adds it. When everything missing was added by a later
release, the error ends with the `migrate force <N>` number that records the
schema's current release, to be run against the OP's own version table.

## Other migration tools

The files are plain SQL named `NNNNNN_vX.Y.Z.up.sql` in golang-migrate layout;
there are no down files.

- **goose** and **Flyway**: `op-schema export --format goose|flyway` writes the
  files with the tool's names and headers (see Coexisting with your application's migrations).
- **Atlas and others**: apply the files in numeric order.

On PostgreSQL in a schema other than `public`, the adapter resolves tables
through the connection's `search_path`, so set `search_path` on the DSN or
connection. The schema check locates each table in the first
`search_path` schema that holds an ordinary or partitioned table of that name
(views are not considered), and a missing
table is reported with the schemas it looked in (on MySQL, the database name).
Table names passed to `WithNaming`, and the prefix passed to `WithTablePrefix`,
are plain identifiers, never schema-qualified.

`WithTablePrefix` and `WithNaming` rename the DDL by replacing each default
`oidc_` table name, longest first, wherever it occurs as a substring; that is
how an index name such as `idx_oidc_sessions_expires` follows its table. `New`
fails when a table or index name that results exceeds 63 bytes, naming the
index and its table key. A missing-index error points at `Store.Schema()`
rather than `v1.sql` when the names are not the defaults.

## Coexisting with your application's migrations

The OP's files need their own version history, separate from the application's.
Both sets are numbered from 1, and a tool that records them in one table sees
the second set as already applied or out of order. Keep a separate directory
and a separate version table for each tool:

- **golang-migrate**: give the OP its own table through the database driver's
  `x-migrations-table` URL parameter, for example
  `postgres://...?x-migrations-table=oidc_schema_migrations`, or through the
  driver `Config.MigrationsTable` when you build it with `WithInstance`.
  `oidc_schema_migrations` is the table `Store.Migrate` uses (with
  `WithTablePrefix`, `<prefix>schema_migrations`), so the two tools share one
  history. `migrate force N` records a version in that table only, leaving the
  application's history alone.
- **goose**: keep the OP's files in a directory of their own and run goose
  against it with `goose -table oidc_goose_db_version ...`, or call
  `goose.SetTableName("oidc_goose_db_version")` before running it from Go.
- **Flyway**: use a separate `table` (for example `oidc_flyway_history`) and
  separate `locations` for the OP's files.
- **Atlas**: use a separate migration directory and a separate revisions table
  for the OP.

goose and Flyway read files from disk, not from an `fs.FS`. `op-schema` writes
`Store.Migrations()` out with the tool's file names, after `WithTablePrefix`
applied (it needs no database connection):

```sh
go run github.com/libraz/go-oidc-provider/op/storeadapter/sql/cmd/op-schema \
    export --dialect postgres --prefix oidc_ --format goose --out db/oidc
```

`--format` is `golang-migrate` (`NNNNNN_vX.Y.Z.up.sql`, as `Store.Migrations()`
names them), `goose` (`NNNNNN_vX.Y.Z.sql`, each file opening with `-- +goose
Up` and ending with an empty `-- +goose Down`; no statement needs
`-- +goose StatementBegin`) or `flyway` (`V<N>__vX_Y_Z.sql`). The directory is
created when missing. The tool applies a prefix only; for `WithNaming` overrides, write the files
from `Store.Migrations()` yourself.

The sections below explain what each release changes.

## v1.1.0

File: `000002_v1.1.0.up.sql`.

`allowed_scopes` holds the scope ceiling of a registration access token. It is
nullable on purpose: `NULL` is an unrestricted ceiling, which is also how RATs
created before ceilings existed read.

`row_version` on the TOTP and email-OTP tables is the SQL representation of
the public record's `Version`; applications must not write or manage it.
Existing rows start at one. A public record's Version is zero only before it
has been persisted; every successful Put or conditional transition installs a
fresh, opaque signed-63-bit generation token. Tokens are equality-only: they
must never be incremented, reused after delete/recreate, or assigned semantic
meaning by an application. These columns are a writer compatibility boundary;
see [Deployment order and writer compatibility](#deployment-order-and-writer-compatibility).

`idx_oidc_grants_client_subject` bounds distinct subject enumeration during
client deletion; the pre-existing `(subject, client_id, updated_at)` index
serves the opposite direction. `idx_oidc_grants_client` serves the
client-scoped cascade, which filters on `client_id` alone and cannot use
either composite. The `expires_at` indexes bound the retention sweep: a
`DELETE` filtered on an unindexed column scans the table, and on MySQL it
takes a lock per row it examines rather than per row it removes, so the cost
grows with the data the sweep exists to bound.

## v1.2.0

File: `000003_v1.2.0.up.sql`.

The three `client_id` indexes on the token tables bound the rest of the
client-deletion cascade. It revokes with an `UPDATE` rather than a `DELETE`,
which the engine plans identically: filtered on an unindexed column it scans,
and on MySQL the per-examined-row lock then covers the whole table, blocking
every concurrent refresh and introspection until the client deletion commits.

On MySQL the users table's `username` moves to a binary collation, for the
reason given under v1.3.0.

## v1.3.0

File: `000004_v1.3.0.up.sql`.

MySQL only; the SQLite and PostgreSQL files change nothing.

These changes make every `client_id` and `subject` column, plus
`oidc_clients.id`, match bytes, which is what the adapter documents and what
SQLite and PostgreSQL do already. MySQL's default collation is case- and
accent-insensitive, so without them `PutUserWithPassword("Alice", ...)`
overwrites the row `alice` already has instead of creating a second one,
`FindBySubject("ALICE")` resolves `alice`, and `GetClient("MYAPP")` resolves
`myapp` — on MySQL only. Every one of these columns is an identifier compared
for exact equality against a value the OP itself generated or a client/subject
string an embedder chose, never freeform text, so binary collation costs
nothing but the case- and accent-folding the default was never supposed to
apply to them. Apply the `MODIFY` statements before provisioning subjects or
client IDs that differ only in case or accents; on a database that already
holds rows a `MODIFY` fails if two existing values collide under the binary
collation, which names the rows that have to be reconciled first.

## v1.4.0

File: `000005_v1.4.0.up.sql`.

The authorization-code, refresh-token and opaque-access-token columns carry
the auth_time, acr, amr, authorization_details and claims request of the
authorization each row was issued under, so a later authorization that
rewrites the shared grant does not change what an earlier code, chain or token
releases. `authorization_recorded` marks a row written with them; a row left at
the default of zero is read the way earlier releases read every row, from its
grant.

`chain_id` on refresh tokens and opaque access tokens names the rotation chain
a row belongs to, so a refresh rotation retires only its own chain's opaque
access tokens; a row left at the empty default falls back to retiring every
opaque access token of its grant. `access_revoked_at` on grant revocations is
the cutoff of a tombstone that covers the grant's access tokens only (the
cascade of a single refresh-token revocation), kept apart from `revoked_at` so
the grant's other refresh chains and codes still redeem.

Old and new writers may run side by side once these columns exist; see
[Deployment order and writer compatibility](#deployment-order-and-writer-compatibility).

## v1.5.0

File: `000006_v1.5.0.up.sql`.

`previous_secret_hash` and `previous_secret_expires_at` on the clients table
hold the one previous client secret a rotation keeps valid until its expiry
(epoch seconds, `0` for none). MySQL cannot give a `TEXT` column a literal
default, so its `ADD COLUMN ... TEXT NOT NULL` fills existing rows with the
empty string, which reads as no previous secret.

`oidc_ssf_streams` and `oidc_ssf_events` are new tables holding the Shared
Signals Framework transmitter's streams and its queue of Security Event Tokens.
`op.New` requires them only when `op.WithSharedSignals` is set, and
`Store.ValidateSchema`, which checks every table, always does; they stay empty
until Shared Signals is enabled.

`idx_oidc_sessions_subject` on `oidc_sessions(subject)` serves the delete of
every session of one subject, which `Provider.ForgetSubject` issues; without it
the `DELETE` scans the table.

## Deployment order and writer compatibility

Run the `ALTER TABLE` statements (including the `NOT NULL DEFAULT 1`
`row_version` columns) and backfill/validate them before starting a binary that
uses the versioned queries. The migration is additive and can be rolled back by
the deployment's normal schema procedure, but a rollback must stop all versioned
writers first.

Do not run old and new adapter binaries against the same MFA tables. Old
writers omit `row_version` from their updates and do not participate in the
opaque-token compare-and-swap protocol; even if their statements continue to
execute, they can overwrite a value without advancing or checking the
generation. Treat the schema change and the versioned writer rollout as one
compatibility boundary: drain old writers, apply the columns, validate the
schema, then start only new writers. A mixed old/new deployment is unsupported
and must fail the rollout rather than relying on `CREATE TABLE IF NOT EXISTS` or
driver-specific affected-row behavior to provide compatibility.

The authorization-state columns are not part of that boundary. An older binary
that writes these tables leaves `authorization_recorded` at zero, which the
current binary reads as a row predating the columns and resolves from the
grant, so old and new writers may run side by side once the columns exist.
The chain and access-token-only revocation columns follow the same rule for
writers. An older binary does not read `access_revoked_at`, so until every node
runs the current binary, a JWT access token whose grant was revoked through a
single refresh-token revocation still verifies on the older nodes.

Do not drop and recreate these tables to make the new shape appear. Apply the
migrations (`Store.Migrate` or your tool) with the deployment's schema
lock/rollback procedure before starting a binary that emits queries using the
new columns.
