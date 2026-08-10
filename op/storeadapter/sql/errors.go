package oidcsql

import (
	"errors"
	"fmt"
	"strings"
)

// pgUniqueViolation is the SQLSTATE PostgreSQL assigns to a
// unique-constraint violation. pgx appends it to every server error as
// "(SQLSTATE 23505)", assembled client-side, so it survives whatever
// language the server was configured to speak.
const pgUniqueViolation = "23505"

// isDuplicate reports whether err describes a unique-constraint or
// primary-key collision on the underlying driver.
//
// The adapter deliberately does not import the driver packages to read
// their error types: an embedder running Postgres would otherwise link
// the MySQL driver into their binary, and vice versa. The check is by
// message substring instead — but which substring matters.
//
// MySQL and PostgreSQL both translate server error text (both spell the
// setting lc_messages), so "duplicate entry" and "duplicate key value"
// are present only on an English-configured server. What is not
// translated is the numeric identity the driver renders itself:
// go-sql-driver formats "Error <number> (<sqlstate>)" in Go, and pgx
// appends "(SQLSTATE <code>)" in Go. Those are matched first and are
// the load-bearing checks; the English phrases stay as a fall-back for
// drivers that surface neither.
//
// A misclassification here fails closed — the write still fails, and
// the caller reports a storage error instead of the specific "already
// exists" — so the cost is a wrong error surface and a wrong audit
// signal, not an admitted duplicate.
func isDuplicate(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	// The number is matched against the driver's own error rather than
	// a wrapper's rendering of it, because the anchor below is a
	// prefix and any wrapping puts text in front of it.
	root := strings.ToLower(rootError(err).Error())
	// ER_DUP_ENTRY and its named-key variant, both rendered by the
	// driver rather than by the server.
	if hasMySQLErrorNumber(root, "1062") || hasMySQLErrorNumber(root, "1586") {
		return true
	}
	if strings.Contains(msg, "sqlstate "+pgUniqueViolation) {
		return true
	}
	// SQLite has no message catalogue to localise: modernc.org/sqlite
	// and mattn/go-sqlite3 both surface the English constants compiled
	// into the engine.
	return strings.Contains(msg, "unique constraint") || // sqlite + postgres (English server)
		strings.Contains(msg, "duplicate entry") || // mysql (English server)
		strings.Contains(msg, "duplicate key value") || // postgres (English server)
		strings.Contains(msg, "primary key constraint") || // sqlite alt phrasing
		strings.Contains(msg, "violates unique") // postgres alternate (English server)
}

// hasMySQLErrorNumber reports whether msg opens with go-sql-driver's
// rendering of the supplied MySQL server error number. The driver
// formats "Error <number> (<sqlstate>): <message>", or "Error
// <number>: <message>" when the server sent no SQLSTATE.
//
// The match is anchored at the start rather than searched for, because
// the server-supplied message that follows can contain anything — a
// value being inserted, a table name, the text of another error — and
// a substring search would let that text claim an identity it does not
// have.
func hasMySQLErrorNumber(msg, number string) bool {
	return strings.HasPrefix(msg, "error "+number+" (") ||
		strings.HasPrefix(msg, "error "+number+":")
}

// rootError walks to the end of err's unwrap chain. The driver error
// sits at the bottom; everything above it is this adapter's own
// context.
func rootError(err error) error {
	for {
		next := errors.Unwrap(err)
		if next == nil {
			return err
		}
		err = next
	}
}

// wrapErr decorates a driver error with the substore name so the
// caller can identify the source without losing the underlying chain.
// Callers MUST NOT pass [databasesql.ErrNoRows] through this helper;
// the not-found mapping happens before the call site.
func wrapErr(op string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("oidcsql: %s: %w", op, err)
}
