//go:build example

package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

// engine is everything that differs between the three databases the
// example runs on: the database/sql driver, the OP adapter's dialect, how
// a bind parameter is spelled, and the DDL and insert statement of the
// demo users table. The application's own queries in users.go are written
// once with "?" and pass through placeholders.
type engine struct {
	name   string
	driver string
	oidc   func() oidcsql.Dialect
	// numbered is true when the driver wants $1, $2, ... (PostgreSQL)
	// instead of "?".
	numbered bool
	// usersDDL creates app_users. subject is the opaque, never-reused
	// OIDC subject, filled with 128 random bits when a row omits it.
	usersDDL string
	// timeArg converts the instant a row is disabled into the value bound
	// to disabled_at: SQLite has no timestamp type and keeps an RFC 3339
	// string, MySQL (DATETIME(6), UTC) and PostgreSQL (timestamptz) take
	// the time.Time itself.
	timeArg func(time.Time) any
	// insertUser inserts one demo user (email, display_name,
	// password_hash) and skips a row whose email already exists, so a
	// hash an earlier login rewrote is kept.
	insertUser string
}

var engines = map[string]engine{
	"sqlite": {
		name:   "sqlite",
		driver: "sqlite",
		oidc:   oidcsql.SQLite,
		usersDDL: `CREATE TABLE IF NOT EXISTS app_users (
			id INTEGER PRIMARY KEY,
			subject TEXT UNIQUE NOT NULL DEFAULT (lower(hex(randomblob(16)))),
			email TEXT UNIQUE NOT NULL,
			display_name TEXT NOT NULL,
			password_hash TEXT,
			disabled_at TEXT
		)`,
		timeArg:    func(t time.Time) any { return t.UTC().Format(time.RFC3339) },
		insertUser: "INSERT OR IGNORE INTO app_users (email, display_name, password_hash) VALUES (?, ?, ?)",
	},
	"mysql": {
		name:   "mysql",
		driver: "mysql",
		oidc:   oidcsql.MySQL,
		usersDDL: `CREATE TABLE IF NOT EXISTS app_users (
			id BIGINT AUTO_INCREMENT PRIMARY KEY,
			subject VARCHAR(64) COLLATE utf8mb4_bin NOT NULL DEFAULT (LOWER(HEX(RANDOM_BYTES(16)))),
			email VARCHAR(255) NOT NULL,
			display_name VARCHAR(255) NOT NULL,
			password_hash VARCHAR(255) NULL,
			disabled_at DATETIME(6) NULL,
			UNIQUE KEY app_users_subject (subject),
			UNIQUE KEY app_users_email (email)
		)`,
		timeArg:    func(t time.Time) any { return t.UTC() },
		insertUser: "INSERT IGNORE INTO app_users (email, display_name, password_hash) VALUES (?, ?, ?)",
	},
	"postgres": {
		name:     "postgres",
		driver:   "pgx",
		oidc:     oidcsql.Postgres,
		numbered: true,
		usersDDL: `CREATE TABLE IF NOT EXISTS app_users (
			id BIGSERIAL PRIMARY KEY,
			subject TEXT UNIQUE NOT NULL DEFAULT replace(gen_random_uuid()::text, '-', ''),
			email TEXT UNIQUE NOT NULL,
			display_name TEXT NOT NULL,
			password_hash TEXT,
			disabled_at TIMESTAMPTZ
		)`,
		timeArg:    func(t time.Time) any { return t.UTC() },
		insertUser: "INSERT INTO app_users (email, display_name, password_hash) VALUES (?, ?, ?) ON CONFLICT (email) DO NOTHING",
	},
}

// engineFor resolves EXAMPLE53_DIALECT.
func engineFor(name string) (engine, error) {
	e, ok := engines[name]
	if !ok {
		return engine{}, fmt.Errorf("unknown EXAMPLE53_DIALECT %q; use sqlite, mysql or postgres", name)
	}
	return e, nil
}

// placeholders rewrites the "?" bind parameters of query into the engine's
// spelling. The queries in this example contain no "?" inside a literal.
func (e engine) placeholders(query string) string {
	if !e.numbered {
		return query
	}
	var b strings.Builder
	n := 0
	for i := range len(query) {
		if query[i] != '?' {
			b.WriteByte(query[i])
			continue
		}
		n++
		b.WriteByte('$')
		b.WriteString(strconv.Itoa(n))
	}
	return b.String()
}
