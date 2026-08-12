# SQL adapter schema migrations

`schema/{sqlite,mysql,postgres}/v1.sql` is the complete shape for a new
database. `Store.Migrate` is a development/test convenience: its
`CREATE TABLE IF NOT EXISTS` statements do not alter tables that already
exist. Deployments that carry a table created by an earlier adapter release
or schema version — including the prior v1.0.0 shape — must apply the required
`ALTER` statements through their normal migration tool, then run the adapter's
schema check.

The following columns and index are additions covered by this schema revision.
Use the physical table names configured with `WithNaming` when they differ
from the defaults.

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
The grant index bounds distinct subject enumeration during client deletion; the
pre-existing `(subject, client_id, updated_at)` index serves the opposite
direction.

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
