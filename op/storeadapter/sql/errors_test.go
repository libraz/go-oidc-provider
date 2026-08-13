//nolint:testpackage // tests reference the unexported isDuplicate classifier.
package oidcsql

import (
	"errors"
	"testing"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
)

// The driver error types are constructed here rather than string-
// formatted by hand so the test breaks if a driver changes how it
// renders an error — which is the assumption the classifier rests on.
// Importing them is a test-only dependency; production code stays
// driver-free so an embedder links only the driver they use.

// A MySQL server configured with a non-English lc_messages returns a
// translated message, and every English phrase the classifier used to
// rely on disappears with it. The error number is rendered by the
// driver in Go, so it is the part that survives.
func TestIsDuplicate_MySQLLocalizedMessage(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		err  *mysql.MySQLError
	}{
		{
			name: "ER_DUP_ENTRY, Japanese server",
			err: &mysql.MySQLError{
				Number:   1062,
				SQLState: [5]byte{'2', '3', '0', '0', '0'},
				Message:  "キー 'PRIMARY' に対して重複エントリー 'jti-1' です",
			},
		},
		{
			name: "ER_DUP_ENTRY_WITH_KEY_NAME, Japanese server",
			err: &mysql.MySQLError{
				Number:   1586,
				SQLState: [5]byte{'2', '3', '0', '0', '0'},
				Message:  "キー 'idx_jti' に対して重複エントリー 'jti-1' です",
			},
		},
		{
			name: "no SQLSTATE from the server",
			err: &mysql.MySQLError{
				Number:  1062,
				Message: "Doppelter Eintrag 'jti-1' für Schlüssel 'PRIMARY'",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if !isDuplicate(tc.err) {
				t.Errorf("isDuplicate(%q) = false, want true", tc.err.Error())
			}
		})
	}
}

// pgx assembles the "(SQLSTATE ...)" suffix client-side, so it outlives
// a translated Severity and Message.
func TestIsDuplicate_PostgresLocalizedMessage(t *testing.T) {
	t.Parallel()

	err := &pgconn.PgError{
		Severity: "ОШИБКА",
		Code:     "23505",
		Message:  "повторяющееся значение ключа нарушает ограничение уникальности \"jtis_pkey\"",
	}
	if !isDuplicate(err) {
		t.Errorf("isDuplicate(%q) = false, want true", err.Error())
	}
}

// A non-duplicate failure must stay non-duplicate whatever language it
// arrives in: classifying, say, a deadlock as "already exists" would
// turn a retryable fault into a permanent rejection.
func TestIsDuplicate_RejectsOtherDriverErrors(t *testing.T) {
	t.Parallel()

	for name, err := range map[string]error{
		"nil": nil,
		"mysql deadlock": &mysql.MySQLError{
			Number:   1213,
			SQLState: [5]byte{'4', '0', '0', '0', '1'},
			Message:  "デッドロックを検出しました",
		},
		"mysql not-null violation": &mysql.MySQLError{
			Number:   1048,
			SQLState: [5]byte{'2', '3', '0', '0', '0'},
			Message:  "カラム 'sub' は null にできません",
		},
		"postgres foreign-key violation": &pgconn.PgError{
			Severity: "ОШИБКА",
			Code:     "23503",
			Message:  "нарушение ограничения внешнего ключа",
		},
		"plain error": errors.New("oidcsql: connection refused"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if isDuplicate(err) {
				t.Errorf("isDuplicate(%v) = true, want false", err)
			}
		})
	}
}

// Call sites classify the raw driver error today, but the prefix
// anchor would quietly stop working the day one of them classifies a
// wrapped error instead — and it would fail open into "not a
// duplicate", which reads as an ordinary storage fault.
func TestIsDuplicate_SeesThroughWrapping(t *testing.T) {
	t.Parallel()

	driverErr := &mysql.MySQLError{
		Number:   1062,
		SQLState: [5]byte{'2', '3', '0', '0', '0'},
		Message:  "キー 'PRIMARY' に対して重複エントリー 'jti-1' です",
	}
	if !isDuplicate(wrapErr("jtis.Mark", driverErr)) {
		t.Errorf("isDuplicate(wrapped) = false, want true")
	}
}

// The error number must be matched as an identifier, not as digits
// occurring anywhere in the text. A row whose contents happen to
// contain the sequence is exactly the input that would otherwise turn
// an unrelated failure into a silent "already exists".
func TestIsDuplicate_IgnoresTheNumberInsideAMessage(t *testing.T) {
	t.Parallel()

	err := &mysql.MySQLError{
		Number:   1213,
		SQLState: [5]byte{'4', '0', '0', '0', '1'},
		Message:  "deadlock found when trying to get lock on error 1062 (23000) sample text",
	}
	if isDuplicate(err) {
		t.Errorf("isDuplicate(%q) = true; the number belongs to the message, not the driver prefix", err.Error())
	}
}

// A grant amendment that lost its basis must be recognisable on every
// engine, in whatever language the server speaks. The engines disagree
// on how they say it — PostgreSQL aborts the transaction, MySQL reports
// a deadlock or a lock-wait timeout, SQLite refuses the write — and the
// caller retries the cycle on all three or on none.
func TestIsLockConflict_AcrossEngines(t *testing.T) {
	t.Parallel()

	for name, err := range map[string]error{
		"mysql deadlock, Japanese server": &mysql.MySQLError{
			Number:   1213,
			SQLState: [5]byte{'4', '0', '0', '0', '1'},
			Message:  "デッドロックを検出しました",
		},
		"mysql lock wait timeout, Japanese server": &mysql.MySQLError{
			Number:   1205,
			SQLState: [5]byte{'H', 'Y', '0', '0', '0'},
			Message:  "ロック待ちがタイムアウトしました",
		},
		"postgres serialization failure": &pgconn.PgError{
			Severity: "ОШИБКА",
			Code:     "40001",
			Message:  "не удалось сериализовать доступ",
		},
		"postgres deadlock": &pgconn.PgError{
			Severity: "ОШИБКА",
			Code:     "40P01",
			Message:  "обнаружена взаимоблокировка",
		},
		"sqlite busy":          errors.New("database is locked (5) (SQLITE_BUSY)"),
		"sqlite busy snapshot": errors.New("database is locked (517)"),
		"sqlite table locked":  errors.New("database table is locked"),
		"wrapped": wrapErr("grants.Save", &pgconn.PgError{
			Code:    "40001",
			Message: "could not serialize access due to concurrent update",
		}),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if !isLockConflict(err) {
				t.Errorf("isLockConflict(%v) = false, want true", err)
			}
		})
	}
}

// Reporting an ordinary failure as a conflict is worse than missing
// one: the caller re-drives the whole cycle against a fault no re-read
// can clear, and the amendment it carries is applied twice as often as
// it was asked for.
func TestIsLockConflict_RejectsOtherDriverErrors(t *testing.T) {
	t.Parallel()

	for name, err := range map[string]error{
		"nil": nil,
		"mysql duplicate entry": &mysql.MySQLError{
			Number:   1062,
			SQLState: [5]byte{'2', '3', '0', '0', '0'},
			Message:  "キー 'PRIMARY' に対して重複エントリー 'g-1' です",
		},
		"postgres unique violation": &pgconn.PgError{
			Code:    "23505",
			Message: "duplicate key value violates unique constraint",
		},
		"plain error": errors.New("oidcsql: connection refused"),
		"the number inside a message": &mysql.MySQLError{
			Number:   1062,
			SQLState: [5]byte{'2', '3', '0', '0', '0'},
			Message:  "duplicate entry for error 1213 (40001) sample text",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if isLockConflict(err) {
				t.Errorf("isLockConflict(%v) = true, want false", err)
			}
		})
	}
}
