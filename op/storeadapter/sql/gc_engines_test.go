//go:build testcontainers

package oidcsql_test

import (
	"testing"
)

// The real-engine half of the retention sweep coverage. The fixture and every
// assertion live in gc_engines_shared_test.go alongside the SQLite case, so
// all three engines answer the same questions about the same rows.

func TestPostgres_GC(t *testing.T) {
	t.Parallel()
	runGCAcrossEngine(t, newPostgresFactory(t))
}

func TestMySQL_GC(t *testing.T) {
	t.Parallel()
	runGCAcrossEngine(t, newMySQLFactory(t))
}
