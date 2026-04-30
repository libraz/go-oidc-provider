package oidcsql

import (
	"embed"
	"fmt"
	"path"
	"strings"
)

//go:embed schema
var schemaFS embed.FS

// Dialect describes the per-engine SQL syntax differences this adapter
// needs. Three values are shipped — [SQLite], [MySQL], [Postgres] — and
// the embedder selects the matching one when calling [New]. The struct
// is intentionally exported but opaque: callers configure it through
// the package-level constructors and never construct it directly.
type Dialect struct {
	name           string
	usesDollar     bool
	upsertConflict bool
	greatest       string
	schema         []byte
}

// Name returns the dialect's stable identifier ("sqlite", "mysql",
// "postgres"). It is exposed for diagnostics and audit logging; the
// adapter itself routes on the unexported fields.
func (d Dialect) Name() string { return d.name }

// SQLite returns the [Dialect] value that targets SQLite via either
// modernc.org/sqlite or mattn/go-sqlite3. Tests in this package use
// the modernc driver so CI does not require CGO; the adapter does not
// inspect the driver name itself.
func SQLite() Dialect {
	return Dialect{
		name:           "sqlite",
		usesDollar:     false,
		upsertConflict: true,
		// SQLite exposes MAX as a scalar (variadic) function distinct
		// from the aggregate; PostgreSQL and MySQL spell the same shape
		// GREATEST. The grant-tombstone upsert uses this to extend
		// ExpiresAt to max(existing, supplied) idempotently.
		greatest: "MAX",
		schema:   mustSchema("sqlite"),
	}
}

// MySQL returns the [Dialect] value that targets MySQL 8.x or
// MariaDB 10.5+ via github.com/go-sql-driver/mysql.
func MySQL() Dialect {
	return Dialect{
		name:           "mysql",
		usesDollar:     false,
		upsertConflict: false,
		greatest:       "GREATEST",
		schema:         mustSchema("mysql"),
	}
}

// Postgres returns the [Dialect] value that targets PostgreSQL 14+
// via github.com/jackc/pgx/v5/stdlib or any other database/sql driver
// that speaks the PostgreSQL frontend protocol.
func Postgres() Dialect {
	return Dialect{
		name:           "postgres",
		usesDollar:     true,
		upsertConflict: true,
		greatest:       "GREATEST",
		schema:         mustSchema("postgres"),
	}
}

func mustSchema(name string) []byte {
	b, err := schemaFS.ReadFile(path.Join("schema", name, "v1.sql"))
	if err != nil {
		panic(fmt.Sprintf("oidcsql: missing embedded schema for %s: %v", name, err)) //nolint:forbidigo // build-time invariant: every dialect's schema is bundled via go:embed; a missing entry is a compile-equivalent bug.
	}
	return b
}

// rebind rewrites a query that uses the portable "?" placeholder into
// the dialect's native form. SQLite and MySQL accept "?" verbatim;
// PostgreSQL requires positional "$N" markers.
func (d Dialect) rebind(query string) string {
	if !d.usesDollar {
		return query
	}
	var b strings.Builder
	b.Grow(len(query) + 8)
	idx := 0
	for _, r := range query {
		if r == '?' {
			idx++
			b.WriteByte('$')
			b.WriteString(itoa(idx))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// upsertOnConflict assembles the dialect-appropriate "insert or
// replace by key" tail. cols is the full INSERT column list, sets is
// the comma-separated assignment list applied on conflict, key is the
// conflicting unique key (PK column name).
func (d Dialect) upsertOnConflict(key, sets string) string {
	if d.upsertConflict {
		return " ON CONFLICT(" + key + ") DO UPDATE SET " + sets
	}
	return " ON DUPLICATE KEY UPDATE " + sets
}

// excludedRef returns the dialect-specific reference to the row that
// would have been inserted, used inside the assignment list of an
// upsert. PostgreSQL/SQLite expose it via the EXCLUDED pseudo-table;
// MySQL uses VALUES(col) pre-8.0.20 and the row alias post-8.0.20.
// The adapter targets MySQL 8.0.20+ so the alias form is used.
func (d Dialect) excludedRef(col string) string {
	if d.upsertConflict {
		return "EXCLUDED." + col
	}
	return "new." + col
}

// upsertAlias returns the row alias clause appended after VALUES on
// MySQL and an empty string on the other engines. MySQL 8.0.20+
// supports `INSERT ... VALUES (...) AS new ON DUPLICATE KEY UPDATE
// col = new.col`, replacing the deprecated VALUES(col) function.
func (d Dialect) upsertAlias() string {
	if d.upsertConflict {
		return ""
	}
	return " AS new"
}

// upsertDoNothing returns the dialect-appropriate "ignore the conflict"
// tail. SQLite and PostgreSQL spell it `ON CONFLICT(key) DO NOTHING`;
// MySQL has no DO NOTHING form, so the substore re-binds the key
// column to itself in `ON DUPLICATE KEY UPDATE` which is a no-op the
// optimiser elides. Used by [GrantRevocationStore.RevokeJTI] where a
// second insert against an already-denylisted JTI must not perturb the
// existing row's audit fields.
func (d Dialect) upsertDoNothing(key string) string {
	if d.upsertConflict {
		return " ON CONFLICT(" + key + ") DO NOTHING"
	}
	return " ON DUPLICATE KEY UPDATE " + key + " = " + key
}

// greatestExpr returns the dialect-appropriate two-argument max-of
// scalar expression. SQLite exposes MAX as a variadic scalar function;
// PostgreSQL and MySQL spell the same shape GREATEST. The grant
// tombstone upsert uses this to extend ExpiresAt to max(existing,
// supplied) without losing the original RevokedAt.
func (d Dialect) greatestExpr(a, b string) string {
	return d.greatest + "(" + a + ", " + b + ")"
}

// itoa renders a non-negative int without pulling in strconv (the
// rebind hot path is exercised on every query and the int values are
// always small parameter indices).
func itoa(n int) string {
	if n < 10 {
		return string(rune('0' + n)) //nolint:gosec // n is bounded to [0,9] by the caller; no overflow possible.
	}
	var buf [16]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
