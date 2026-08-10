// Package oidcsql is the SQL storage adapter for go-oidc-provider. It
// implements every substore declared in
// [github.com/libraz/go-oidc-provider/op/store] against a [database/sql]
// handle, supports SQLite, MySQL 8.0+ and PostgreSQL 14+, and is
// published as a sub-module so its driver dependencies do not bleed
// into the host module's go.sum.
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
// control to the adapter.
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
// Rollback finalise the underlying transaction; subsequent calls on
// the substore handles return [store.ErrTxRequired].
//
// # Retention
//
// Most OP tables hold short-lived rows, and nothing in the request path
// deletes them once they expire: an authorization code that was never
// redeemed, a PAR record whose client walked away, an interaction the
// user abandoned, and a session that timed out all stay on disk. One
// authorization request writes one row, and an unauthenticated caller
// can drive that loop, so a deployment that never reclaims them grows
// until the disk or the index does. Operating this adapter includes
// scheduling the reclamation.
//
// [Store.GC] is the entry point. It deletes expired authorization
// codes, PAR records, interactions and sessions in one call, returns
// per-table counts as [GCStats], and runs on the *sql.DB the Store
// already holds — a cron job or worker needs nothing but a handle to
// the same Store. The adapter starts no goroutine of its own: when the
// sweep runs, how often, and on which replica are the embedder's
// decisions, not the library's.
//
//	stats, err := store.GC(ctx, time.Now())
//
// Passing an earlier cutoff keeps a grace window; rows whose expires_at
// is zero opt out of the sweep entirely.
//
// The remaining expiring tables are already covered elsewhere and do
// not need to be added to the schedule twice. Access tokens, opaque
// access tokens, grant revocations and consumed JTIs each expose a GC
// method on the substore interface they implement, because how long a
// revocation record outlives the token it revokes is an OP policy
// decision rather than plain expiry. Device codes and CIBA requests
// evict expired rows on their own insert path.
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
