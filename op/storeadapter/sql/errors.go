package oidcsql

import (
	"fmt"
	"strings"
)

// isDuplicate reports whether err describes a unique-constraint or
// primary-key collision on the underlying driver. The adapter cannot
// import driver-specific error types without dragging the drivers
// into go.sum, so the check is by message-substring instead. This is
// the standard portable approach used by other ORM-free adapters and
// is robust because the relevant strings are stable parts of each
// driver's error grammar.
func isDuplicate(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique constraint") || // sqlite (modernc.org/sqlite, mattn/go-sqlite3) + postgres (pgx)
		strings.Contains(msg, "duplicate entry") || // mysql (go-sql-driver)
		strings.Contains(msg, "duplicate key value") || // postgres
		strings.Contains(msg, "primary key constraint") || // sqlite alt phrasing
		strings.Contains(msg, "violates unique") // postgres alternate
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
