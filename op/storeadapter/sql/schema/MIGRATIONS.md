# SQL adapter schema migrations

The SQL lives in `schema/migrations/{sqlite,mysql,postgres}/`, one file per
release in golang-migrate's `NNNNNN_<version>.up.sql` form.
`000001_v1.0.0.up.sql` creates the schema v1.0.0 shipped; each later file
applies one release's changes. `Store.Migrations()` returns the configured
dialect's files with the `WithNaming` table names applied, so a migration tool
can read them directly; take the files from it rather than from the repository
when the names differ from the defaults. `TABLES.md` lists what each table
holds and when the OP uses it.

- **A new database** applies every file in order, or runs `Store.Schema()`
  (`schema/<dialect>/v1.sql`) instead; both reach the same schema.
- **An existing database** is first recorded at the last release it applied,
  then takes only the later files. With golang-migrate that is
  `migrate force <N>`: a database created by v1.2.0 runs `migrate force 3`,
  after which `migrate up` applies v1.3.0 onwards. A database built from
  `Store.Schema()` of the current release is recorded at the newest file.
- golang-migrate's MySQL driver needs `multiStatements=true` in the DSN,
  because each file holds several statements.
- Atlas reads the directory with `format=golang-migrate` once
  `atlas migrate hash` has written its `atlas.sum`.

`Store.Migrate` does not upgrade an existing database. Its `CREATE TABLE IF
NOT EXISTS` statements leave an existing table as it is, so no column is ever
added that way. On SQLite and PostgreSQL the index statements are the same
standalone `CREATE INDEX IF NOT EXISTS` statements `v1.sql` carries, so a
`Store.Migrate` run does add a missing index. **On MySQL the migration files
are the only way to get the indexes.** MySQL has no `CREATE INDEX IF NOT
EXISTS`, so `v1.sql` declares every index inline in its `CREATE TABLE`, which
does nothing to a table that already exists.

After applying, `op.New` checks at construction the tables the configuration
uses and fails naming any that is missing. `Store.ValidateSchema` checks every
table, for a CI or deploy gate (`Store.Migrate` runs it too). A missing column
fails either check with the migration that adds it, for example
`oidcsql: schema for oidc_clients is missing required columns:
previous_secret_hash, previous_secret_expires_at; apply migration 000006_v1.5.0
(schema/migrations/mysql/000006_v1.5.0.up.sql)`. On MySQL both also check that
the identifier columns use a binary collation. Neither checks indexes.

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
until Shared Signals is enabled. Being new,
they are created by a `Store.Migrate` run as well, indexes included on every
dialect; the file repeats the statements for deployments that never run it.

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

Do not rely on a fresh `v1.sql` run to upgrade an existing database, and do not
silently drop/recreate these tables to make the new shape appear. Apply the
`ALTER` statements with the deployment's schema lock/rollback procedure before
starting a binary that emits queries using the new columns.
