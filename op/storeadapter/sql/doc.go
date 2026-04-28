// Package oidcsql is the SQL storage adapter for go-oidc-provider. It
// implements every substore declared in
// [github.com/libraz/go-oidc-provider/op/store] against a [database/sql]
// handle, supports the three engines documented in 003 §7.2 (SQLite,
// MySQL, PostgreSQL), and is published as a sub-module so its driver
// dependencies do not bleed into the host module's go.sum.
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
// chooses which driver registers with database/sql. The integration
// tests under //go:build integration import the canonical drivers
// (modernc.org/sqlite, github.com/go-sql-driver/mysql,
// github.com/jackc/pgx/v5/stdlib) but production embedders may
// substitute alternatives provided they speak the same wire dialect.
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
// (matched in [identifierPattern]) before any query is built; values
// that fail validation cause [New] to return an error. The validator
// is the single defence against identifier injection in the adapter:
// every query is composed by interpolating validated identifiers and
// dialect-specific placeholders only, so the construction-time check
// is structural rather than advisory.
//
// # Transactions
//
// The adapter implements [store.Transactional]. A [store.Tx] obtained
// from [Store.BeginTx] holds a single underlying [database/sql.Tx]
// which is shared by every substore handle the Tx returns. Commit /
// Rollback finalise the underlying transaction; subsequent calls on
// the substore handles return [store.ErrTxRequired].
//
// # Cardinality and PII
//
// The adapter never logs row content. Errors returned to the caller
// are wrapped through the sentinels declared in
// [github.com/libraz/go-oidc-provider/op/store] so that callers can
// switch on them with [errors.Is] without needing driver-specific
// knowledge.
package oidcsql
