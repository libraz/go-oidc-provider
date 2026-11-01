// Package oidcsql is the SQL storage adapter for go-oidc-provider. It
// implements every substore declared in
// [github.com/libraz/go-oidc-provider/op/store] against a [database/sql]
// handle, supports SQLite, MySQL 8.0+ and PostgreSQL 14+, and is
// published as a sub-module so its driver dependencies do not bleed
// into the host module's go.sum. The package is named oidcsql rather
// than after its directory so it does not shadow [database/sql].
//
// # Backends
//
// The package ships three [Dialect] values — [SQLite], [MySQL],
// [Postgres] — that capture the per-engine SQL syntax differences the
// adapter needs (placeholder syntax, upsert clause, column types). Open
// a *sql.DB with the driver of your choice and pass it to [New]
// together with the matching dialect:
//
//	db, _ := sql.Open("sqlite", "file:oidc.db?_pragma=journal_mode(WAL)")
//	store, err := oidcsql.New(db, oidcsql.SQLite())
//
// The adapter does not import any specific driver itself; the embedder
// chooses which driver registers with database/sql. The default test
// suite uses modernc.org/sqlite (CGO-free); the testcontainers-gated
// suite (run with `go test -tags=testcontainers ./...`) boots
// MySQL 8.0 and PostgreSQL 16 containers via Docker and runs the
// same contract harness against them, exercising the canonical
// drivers github.com/go-sql-driver/mysql and
// github.com/jackc/pgx/v5/stdlib. Production embedders may substitute
// alternative drivers provided they speak the same wire dialect.
//
// # Schema
//
// Reference DDL ships under schema/{sqlite,mysql,postgres}/v1.sql and
// is embedded via go:embed. [Store.Schema] returns the SQL for the
// configured dialect so embedders can run it from migrations or shell
// out to psql/mysql; [Store.Migrate] applies it to the live connection
// for development convenience. Production deployments are expected to
// run migrations through their existing tooling rather than hand
// control to the adapter. op.New checks at construction, without creating
// anything, that the tables and required columns the configuration uses
// exist; [Store.ValidateSchema] checks every table, for a CI or deploy
// gate.
// Existing databases are not altered by Store.Migrate. The upgrade path is
// the migration files under schema/migrations/<dialect>, one per release in
// golang-migrate form, which [Store.Migrations] returns with any
// [WithNaming] overrides applied; schema/MIGRATIONS.md explains each
// release. schema/TABLES.md lists what each table holds, when op.New checks
// it, and why a few tables must exist even while they stay empty. Run
// against an empty database, op.New names every table the configuration
// needs in one error. The reference DDL creates every table, including
// those a configuration never reaches; such a table stays empty.
//
// # Users
//
// An application with its own users table keeps it: it passes its own
// store.UserPasswordStore to op.PrimaryPassword, the OP reads claims from
// that store, and oidc_users stays empty. oidc_users, [Store.PutUser],
// [Store.PutUserWithPassword] and [Store.UserPasswords] serve a deployment
// with no users table of its own.
//
// # Naming overrides
//
// [WithNaming] accepts a map of logical → physical identifier
// rewrites so embedders that already own a "clients" table can graft
// the OP onto a different name without forking the schema. Identifiers
// are validated against the SQL standard regular identifier grammar
// by [validateIdentifier] (a byte-walking ASCII validator — no regex)
// before any query is built; values that fail validation cause [New]
// to return an error. The validator is one of six defence layers
// against identifier injection: see queries.go and the package's
// ast_audit_test.go / queries_test.go for the rest.
//
// # Transactions
//
// The adapter implements [store.Transactional]. A [store.Tx] obtained
// from [Store.BeginTx] holds a single underlying [database/sql.Tx]
// which is shared by every substore handle the Tx returns. Commit /
// Rollback finalise the underlying transaction; every later call
// through the handle — a lookup as much as a write, and a second Commit
// — fails with an error satisfying errors.Is(err,
// [store.ErrTxRequired]). The driver's own database/sql.ErrTxDone is
// translated to it so a retained handle is distinguishable from a
// transport fault rather than being retried as one.
//
// # Retention
//
// Most OP tables hold short-lived rows, and nothing in the request path
// deletes them once they expire: an authorization code that was never
// redeemed, a PAR record whose client walked away, an interaction the
// user abandoned, a session that timed out, and the rotation record
// behind a refresh token nobody redeemed all stay on disk, as do
// expired access-token records, revocation tombstones and consumed-JTI
// markers. One authorization request writes one row, and an
// unauthenticated caller can drive that loop, so a deployment that never
// reclaims them grows until the disk or the index does. Operating this
// adapter includes scheduling the reclamation.
//
// [Store.GC] is the entry point. It deletes expired authorization
// codes, PAR records, interactions, sessions, refresh-token rotation
// records, access-token registry rows, opaque access tokens, grant
// revocations and consumed JTIs in one call, returns per-table counts as
// [GCStats], and runs on the *sql.DB the Store already holds — a cron
// job or worker needs nothing but a handle to the same Store. The
// adapter starts no goroutine of its own: when the sweep runs, how
// often, and on which replica are the embedder's decisions, not the
// library's.
//
//	stats, err := store.GC(ctx, time.Now())
//
// Passing an earlier cutoff keeps a grace window; rows whose expires_at
// is zero opt out of the sweep entirely.
//
// The nine sweeps do not cost the same. Eight are range scans on
// expires_at; the refresh-token one is a per-grant anti-join, because a
// rotation record stays needed until every refresh token issued under
// its grant has expired (see [Store.GC] for why). Size the schedule
// against that sweep rather than against the row counts.
//
// The access-token, opaque access-token and grant-revocation substores
// also expose a GC method of their own, for a caller that wants to
// reclaim one table on a separate schedule; Store.GC already covers
// them, so a schedule need not add them twice. The consumed-JTI GC is
// reachable only through Store.GC. Device codes and CIBA requests evict
// expired rows on their own insert path.
//
// Every table any of those sweeps deletes from carries an index on
// expires_at in the reference DDL, as does the grants table on
// client_id for the cascade a client deletion runs. Without them the
// sweep scans, and on MySQL an unindexed DELETE locks the rows it
// examines rather than the rows it removes — so the reclamation job
// contends with live traffic in proportion to the backlog it exists to
// clear. Embedders who applied the DDL before these indexes shipped
// should add them: re-running the SQLite or PostgreSQL schema picks
// them up, while MySQL declares indexes inside CREATE TABLE and so
// needs an explicit ALTER TABLE on an existing database.
//
// # Cardinality and PII
//
// The adapter never logs row content. Errors returned to the caller
// are wrapped through the sentinels declared in
// [github.com/libraz/go-oidc-provider/op/store] so that callers can
// switch on them with [errors.Is] without needing driver-specific
// knowledge.
package oidcsql
