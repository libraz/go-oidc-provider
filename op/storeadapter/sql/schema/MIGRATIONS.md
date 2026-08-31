# SQL adapter schema migrations

`schema/{sqlite,mysql,postgres}/v1.sql` is the complete shape for a new
database. `Store.Migrate` is a development/test convenience: its
`CREATE TABLE IF NOT EXISTS` statements do not alter tables that already
exist. Deployments that carry a table created by an earlier adapter release
or schema version — including the prior v1.0.0 shape — must apply the required
`ALTER` statements through their normal migration tool, then run the adapter's
schema check.

The following columns and indexes are additions covered by this schema
revision. Use the physical table names configured with `WithNaming` when they
differ from the defaults.

On SQLite and PostgreSQL the index statements are the same ones `v1.sql`
carries, so a `Store.Migrate` run adds them to an existing database on its
own; they are repeated here because a deployment that never runs `Migrate`
still needs them. **On MySQL they are the only way to get the indexes.** MySQL
has no `CREATE INDEX IF NOT EXISTS`, so `v1.sql` declares every index inline in
its `CREATE TABLE` — and `CREATE TABLE IF NOT EXISTS` does nothing to a table
that already exists. A MySQL database created by an earlier release therefore
never acquires a later index unless these `ALTER` statements are applied by
hand.

SQLite:

```sql
ALTER TABLE oidc_registration_access_tokens
    ADD COLUMN allowed_scopes TEXT NULL;
ALTER TABLE oidc_totp_secrets
    ADD COLUMN row_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE oidc_email_otps
    ADD COLUMN row_version INTEGER NOT NULL DEFAULT 1;
CREATE INDEX IF NOT EXISTS idx_oidc_grants_client_subject
    ON oidc_grants(client_id, subject, updated_at);
CREATE INDEX IF NOT EXISTS idx_oidc_grants_client
    ON oidc_grants(client_id);
CREATE INDEX IF NOT EXISTS idx_oidc_authorization_codes_expires
    ON oidc_authorization_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_oidc_refresh_tokens_expires
    ON oidc_refresh_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_oidc_access_tokens_expires
    ON oidc_access_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_oidc_sessions_expires
    ON oidc_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_oidc_par_records_expires
    ON oidc_par_records(expires_at);
CREATE INDEX IF NOT EXISTS idx_oidc_interactions_expires
    ON oidc_interactions(expires_at);
CREATE INDEX IF NOT EXISTS idx_oidc_consumed_jtis_expires
    ON oidc_consumed_jtis(expires_at);
CREATE INDEX IF NOT EXISTS idx_oidc_refresh_tokens_client
    ON oidc_refresh_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_oidc_access_tokens_client
    ON oidc_access_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_oidc_opaque_access_tokens_client
    ON oidc_opaque_access_tokens(client_id);
```

MySQL/MariaDB:

```sql
ALTER TABLE oidc_registration_access_tokens
    ADD COLUMN allowed_scopes JSON NULL;
ALTER TABLE oidc_totp_secrets
    ADD COLUMN row_version BIGINT NOT NULL DEFAULT 1;
ALTER TABLE oidc_email_otps
    ADD COLUMN row_version BIGINT NOT NULL DEFAULT 1;
ALTER TABLE oidc_grants
    ADD INDEX idx_oidc_grants_client_subject (client_id, subject, updated_at);
ALTER TABLE oidc_grants
    ADD INDEX idx_oidc_grants_client (client_id);
ALTER TABLE oidc_authorization_codes
    ADD INDEX idx_oidc_authorization_codes_expires (expires_at);
ALTER TABLE oidc_refresh_tokens
    ADD INDEX idx_oidc_refresh_tokens_expires (expires_at);
ALTER TABLE oidc_access_tokens
    ADD INDEX idx_oidc_access_tokens_expires (expires_at);
ALTER TABLE oidc_sessions
    ADD INDEX idx_oidc_sessions_expires (expires_at);
ALTER TABLE oidc_par_records
    ADD INDEX idx_oidc_par_records_expires (expires_at);
ALTER TABLE oidc_interactions
    ADD INDEX idx_oidc_interactions_expires (expires_at);
ALTER TABLE oidc_consumed_jtis
    ADD INDEX idx_oidc_consumed_jtis_expires (expires_at);
ALTER TABLE oidc_refresh_tokens
    ADD INDEX idx_oidc_refresh_tokens_client (client_id);
ALTER TABLE oidc_access_tokens
    ADD INDEX idx_oidc_access_tokens_client (client_id);
ALTER TABLE oidc_opaque_access_tokens
    ADD INDEX idx_oidc_opaque_access_tokens_client (client_id);
ALTER TABLE oidc_users
    MODIFY username VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL;
```

PostgreSQL:

```sql
ALTER TABLE oidc_registration_access_tokens
    ADD COLUMN allowed_scopes JSONB NULL;
ALTER TABLE oidc_totp_secrets
    ADD COLUMN row_version BIGINT NOT NULL DEFAULT 1;
ALTER TABLE oidc_email_otps
    ADD COLUMN row_version BIGINT NOT NULL DEFAULT 1;
CREATE INDEX IF NOT EXISTS idx_oidc_grants_client_subject
    ON oidc_grants(client_id, subject, updated_at);
CREATE INDEX IF NOT EXISTS idx_oidc_grants_client
    ON oidc_grants(client_id);
CREATE INDEX IF NOT EXISTS idx_oidc_authorization_codes_expires
    ON oidc_authorization_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_oidc_refresh_tokens_expires
    ON oidc_refresh_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_oidc_access_tokens_expires
    ON oidc_access_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_oidc_sessions_expires
    ON oidc_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_oidc_par_records_expires
    ON oidc_par_records(expires_at);
CREATE INDEX IF NOT EXISTS idx_oidc_interactions_expires
    ON oidc_interactions(expires_at);
CREATE INDEX IF NOT EXISTS idx_oidc_consumed_jtis_expires
    ON oidc_consumed_jtis(expires_at);
CREATE INDEX IF NOT EXISTS idx_oidc_refresh_tokens_client
    ON oidc_refresh_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_oidc_access_tokens_client
    ON oidc_access_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_oidc_opaque_access_tokens_client
    ON oidc_opaque_access_tokens(client_id);
```

The `allowed_scopes` column is nullable intentionally: `NULL` represents an
unrestricted RAT ceiling, including RATs created before scope ceilings were
introduced. `row_version` is the SQL representation of the public record's
`Version`; applications must not write or manage it directly. Existing rows
start at one. A public record's Version is zero only before it has been
persisted; every successful Put or conditional transition installs a fresh,
opaque signed-63-bit generation token. Tokens are equality-only: they must
never be incremented, reused after delete/recreate, or assigned semantic
meaning by an application.
`idx_oidc_grants_client_subject` bounds distinct subject enumeration during
client deletion; the pre-existing `(subject, client_id, updated_at)` index
serves the opposite direction. `idx_oidc_grants_client` serves the client-scoped
cascade, which filters on `client_id` alone and cannot use either composite.
The `expires_at` indexes bound the retention sweep: a `DELETE` filtered on an
unindexed column scans the table, and on MySQL it takes a lock per row it
examines rather than per row it removes, so the cost grows with the data the
sweep exists to bound.
The MySQL-only `oidc_users.username` collation change makes the lookup match
bytes, which is what the adapter documents and what SQLite and PostgreSQL do
already. MySQL's default collation is case- and accent-insensitive, so without
it a login submitted as `ALICE` resolves `alice` on MySQL and nowhere else, and
two usernames differing only in case cannot both exist. Apply it before
provisioning usernames that differ only in case; on a database that already
holds rows the `MODIFY` fails if two existing usernames collide under the
binary collation, which names the accounts that have to be reconciled first.
The three `client_id` indexes on the token tables bound the rest of that same
cascade. It revokes with an `UPDATE` rather than a `DELETE`, which the engine
plans identically: filtered on an unindexed column it scans, and on MySQL the
per-examined-row lock then covers the whole table, blocking every concurrent
refresh and introspection until the client deletion commits.

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

Do not rely on a fresh `v1.sql` run to upgrade an existing database, and do not
silently drop/recreate these tables to make the new shape appear. Apply the
`ALTER` statements with the deployment's schema lock/rollback procedure before
starting a binary that emits queries using the new columns.
