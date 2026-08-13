//go:build testcontainers

package oidcsql_test

import "testing"

// The recovery-slot post-condition is the one place where an engine's
// affected-row convention decides whether a single-use code survives
// its own redemption, so both container-backed engines carry the rows
// as well: MySQL reports changed rows, PostgreSQL reports matched ones,
// and only running the same assertion on both shows they now agree.
//
// The e-mail OTP rows ride along because the two substores share the
// redemption shape. That one is engine-agnostic — its row-version
// rotation always changes the row — but running it on every engine is
// what keeps the pair from drifting apart again.

func TestMySQL_RecoveryConsumeStamp(t *testing.T) {
	t.Parallel()
	runRecoveryConsumeStampContracts(t, newMySQLFactory(t))
}

func TestPostgres_RecoveryConsumeStamp(t *testing.T) {
	t.Parallel()
	runRecoveryConsumeStampContracts(t, newPostgresFactory(t))
}

func TestMySQL_EmailOTPConsumeStamp(t *testing.T) {
	t.Parallel()
	runEmailOTPConsumeStampContracts(t, newMySQLFactory(t))
}

func TestPostgres_EmailOTPConsumeStamp(t *testing.T) {
	t.Parallel()
	runEmailOTPConsumeStampContracts(t, newPostgresFactory(t))
}
