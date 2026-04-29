//go:build licenses

// File licenses_drivers.go exists solely to surface the canonical
// database driver dependencies the adapter is designed to support so
// that scripts/licenses.sh can enumerate them in THIRD_PARTY.md.
//
// The adapter itself does not import any specific driver — embedders
// pick the driver that matches their engine and pass an open *sql.DB
// to [New]. Without this file, go-licenses cannot see the drivers
// because they are referenced only by build-tagged contract test
// files (//go:build testcontainers).
//
// The file is gated behind the `licenses` build tag so the driver
// imports are excluded from regular builds, regular tests, and the
// testcontainers harness; only `make licenses` (which runs go-licenses
// with -tags=licenses) compiles it.

package oidcsql

import (
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)
