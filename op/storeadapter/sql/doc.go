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
// # Cardinality and PII
//
// The adapter never logs row content. Errors returned to the caller
// are wrapped through the sentinels declared in
// [github.com/libraz/go-oidc-provider/op/store] so that callers can
// switch on them with [errors.Is] without needing driver-specific
// knowledge.
package oidcsql
