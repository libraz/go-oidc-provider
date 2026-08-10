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
