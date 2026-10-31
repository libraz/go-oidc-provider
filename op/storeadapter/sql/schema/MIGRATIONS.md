# SQL adapter schema migrations

`schema/{sqlite,mysql,postgres}/v1.sql` is the complete shape for a new
database; a new database needs nothing from this document. `TABLES.md` lists
what each table holds and when the OP uses it.

An existing database needs the sections below for every release after the one
that created it, applied in order. A database created by v1.2.0 that is moving
to the current release applies v1.3.0, v1.4.0 and v1.5.0. Use the physical
table names configured with `WithNaming` when they differ from the defaults.

`Store.Migrate` does not do this for you. Its `CREATE TABLE IF NOT EXISTS`
statements leave an existing table as it is, so no column is ever added that
way. On SQLite and PostgreSQL the index statements are the same standalone
`CREATE INDEX IF NOT EXISTS` statements `v1.sql` carries, so a `Store.Migrate`
run does add a missing index; they are repeated here for deployments that never
run `Migrate`. **On MySQL these sections are the only way to get the indexes.**
MySQL has no `CREATE INDEX IF NOT EXISTS`, so `v1.sql` declares every index
inline in its `CREATE TABLE`, which does nothing to a table that already exists.

After applying, call `Store.ValidateSchema` at startup (`Store.Migrate` runs it
too). A missing column fails it with the name of the section that adds it, for
example `oidcsql: schema for oidc_clients is missing required columns:
previous_secret_hash, previous_secret_expires_at; apply the v1.5.0 section of
schema/MIGRATIONS.md`. It does not check indexes or MySQL collations.

## v1.1.0

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
```

## v1.2.0

The three `client_id` indexes on the token tables bound the rest of the
client-deletion cascade. It revokes with an `UPDATE` rather than a `DELETE`,
which the engine plans identically: filtered on an unindexed column it scans,
and on MySQL the per-examined-row lock then covers the whole table, blocking
every concurrent refresh and introspection until the client deletion commits.

On MySQL the users table's `username` moves to a binary collation, for the
reason given under v1.3.0.

SQLite:

```sql
CREATE INDEX IF NOT EXISTS idx_oidc_refresh_tokens_client
    ON oidc_refresh_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_oidc_access_tokens_client
    ON oidc_access_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_oidc_opaque_access_tokens_client
    ON oidc_opaque_access_tokens(client_id);
```

MySQL/MariaDB:

```sql
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
CREATE INDEX IF NOT EXISTS idx_oidc_refresh_tokens_client
    ON oidc_refresh_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_oidc_access_tokens_client
    ON oidc_access_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_oidc_opaque_access_tokens_client
    ON oidc_opaque_access_tokens(client_id);
```

## v1.3.0

MySQL only; SQLite and PostgreSQL have nothing to apply.

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

MySQL/MariaDB:

```sql
ALTER TABLE oidc_clients
    MODIFY id VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL;
ALTER TABLE oidc_users
    MODIFY subject VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL;
ALTER TABLE oidc_authorization_codes
    MODIFY client_id VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL;
ALTER TABLE oidc_authorization_codes
    MODIFY subject VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL;
ALTER TABLE oidc_refresh_tokens
    MODIFY client_id VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL;
ALTER TABLE oidc_refresh_tokens
    MODIFY subject VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL;
ALTER TABLE oidc_access_tokens
    MODIFY client_id VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL;
ALTER TABLE oidc_access_tokens
    MODIFY subject VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL DEFAULT '';
ALTER TABLE oidc_opaque_access_tokens
    MODIFY client_id VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL;
ALTER TABLE oidc_opaque_access_tokens
    MODIFY subject VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL DEFAULT '';
ALTER TABLE oidc_grants
    MODIFY client_id VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL;
ALTER TABLE oidc_grants
    MODIFY subject VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL;
ALTER TABLE oidc_sessions
    MODIFY subject VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL;
ALTER TABLE oidc_par_records
    MODIFY client_id VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL;
ALTER TABLE oidc_interactions
    MODIFY client_id VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL;
ALTER TABLE oidc_registration_access_tokens
    MODIFY client_id VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL;
ALTER TABLE oidc_device_codes
    MODIFY client_id VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL;
ALTER TABLE oidc_device_codes
    MODIFY subject VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL DEFAULT '';
ALTER TABLE oidc_ciba_requests
    MODIFY client_id VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL;
ALTER TABLE oidc_ciba_requests
    MODIFY subject VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL DEFAULT '';
ALTER TABLE oidc_totp_secrets
    MODIFY subject VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL;
ALTER TABLE oidc_passkeys
    MODIFY subject VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL;
ALTER TABLE oidc_recovery_codes
    MODIFY subject VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL;
ALTER TABLE oidc_email_otps
    MODIFY subject VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL;
ALTER TABLE oidc_authn_lockouts
    MODIFY subject VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL;
```

## v1.4.0

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

SQLite:

```sql
ALTER TABLE oidc_authorization_codes ADD COLUMN auth_time INTEGER NOT NULL DEFAULT 0;
ALTER TABLE oidc_authorization_codes ADD COLUMN acr TEXT NOT NULL DEFAULT '';
ALTER TABLE oidc_authorization_codes ADD COLUMN amr TEXT NOT NULL DEFAULT '[]';
ALTER TABLE oidc_authorization_codes ADD COLUMN authorization_details TEXT NOT NULL DEFAULT 'null';
ALTER TABLE oidc_authorization_codes ADD COLUMN claims TEXT NOT NULL DEFAULT 'null';
ALTER TABLE oidc_authorization_codes ADD COLUMN authorization_recorded INTEGER NOT NULL DEFAULT 0;
ALTER TABLE oidc_refresh_tokens ADD COLUMN claims TEXT NOT NULL DEFAULT 'null';
ALTER TABLE oidc_refresh_tokens ADD COLUMN authorization_recorded INTEGER NOT NULL DEFAULT 0;
ALTER TABLE oidc_opaque_access_tokens ADD COLUMN authorization_details TEXT NOT NULL DEFAULT 'null';
ALTER TABLE oidc_opaque_access_tokens ADD COLUMN claims TEXT NOT NULL DEFAULT 'null';
ALTER TABLE oidc_opaque_access_tokens ADD COLUMN authorization_recorded INTEGER NOT NULL DEFAULT 0;
ALTER TABLE oidc_refresh_tokens ADD COLUMN chain_id TEXT NOT NULL DEFAULT '';
ALTER TABLE oidc_opaque_access_tokens ADD COLUMN chain_id TEXT NOT NULL DEFAULT '';
ALTER TABLE oidc_grant_revocations ADD COLUMN access_revoked_at INTEGER NOT NULL DEFAULT 0;
```

MySQL/MariaDB:

```sql
ALTER TABLE oidc_authorization_codes
    ADD COLUMN auth_time BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN acr VARCHAR(255) NOT NULL DEFAULT '',
    ADD COLUMN amr JSON NULL,
    ADD COLUMN authorization_details JSON NULL,
    ADD COLUMN claims JSON NULL,
    ADD COLUMN authorization_recorded TINYINT(1) NOT NULL DEFAULT 0;
ALTER TABLE oidc_refresh_tokens
    ADD COLUMN claims JSON NULL,
    ADD COLUMN authorization_recorded TINYINT(1) NOT NULL DEFAULT 0;
ALTER TABLE oidc_opaque_access_tokens
    ADD COLUMN authorization_details JSON NULL,
    ADD COLUMN claims JSON NULL,
    ADD COLUMN authorization_recorded TINYINT(1) NOT NULL DEFAULT 0;
ALTER TABLE oidc_refresh_tokens
    ADD COLUMN chain_id VARCHAR(64) NOT NULL DEFAULT '';
ALTER TABLE oidc_opaque_access_tokens
    ADD COLUMN chain_id VARCHAR(64) NOT NULL DEFAULT '';
ALTER TABLE oidc_grant_revocations
    ADD COLUMN access_revoked_at BIGINT NOT NULL DEFAULT 0;
```

PostgreSQL:

```sql
ALTER TABLE oidc_authorization_codes
    ADD COLUMN auth_time BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN acr TEXT NOT NULL DEFAULT '',
    ADD COLUMN amr JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN authorization_details JSONB NOT NULL DEFAULT 'null'::jsonb,
    ADD COLUMN claims JSONB NOT NULL DEFAULT 'null'::jsonb,
    ADD COLUMN authorization_recorded SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE oidc_refresh_tokens
    ADD COLUMN claims JSONB NOT NULL DEFAULT 'null'::jsonb,
    ADD COLUMN authorization_recorded SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE oidc_opaque_access_tokens
    ADD COLUMN authorization_details JSONB NOT NULL DEFAULT 'null'::jsonb,
    ADD COLUMN claims JSONB NOT NULL DEFAULT 'null'::jsonb,
    ADD COLUMN authorization_recorded SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE oidc_refresh_tokens
    ADD COLUMN chain_id TEXT NOT NULL DEFAULT '';
ALTER TABLE oidc_opaque_access_tokens
    ADD COLUMN chain_id TEXT NOT NULL DEFAULT '';
ALTER TABLE oidc_grant_revocations
    ADD COLUMN access_revoked_at BIGINT NOT NULL DEFAULT 0;
```

## v1.5.0

`previous_secret_hash` and `previous_secret_expires_at` on the clients table
hold the one previous client secret a rotation keeps valid until its expiry
(epoch seconds, `0` for none). MySQL cannot give a `TEXT` column a literal
default, so its `ADD COLUMN ... TEXT NOT NULL` fills existing rows with the
empty string, which reads as no previous secret.

SQLite:

```sql
ALTER TABLE oidc_clients ADD COLUMN previous_secret_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE oidc_clients ADD COLUMN previous_secret_expires_at INTEGER NOT NULL DEFAULT 0;
```

MySQL/MariaDB:

```sql
ALTER TABLE oidc_clients
    ADD COLUMN previous_secret_hash TEXT NOT NULL,
    ADD COLUMN previous_secret_expires_at BIGINT NOT NULL DEFAULT 0;
```

PostgreSQL:

```sql
ALTER TABLE oidc_clients
    ADD COLUMN previous_secret_hash TEXT NOT NULL DEFAULT '',
    ADD COLUMN previous_secret_expires_at BIGINT NOT NULL DEFAULT 0;
```

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
