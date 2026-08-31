package oidcsql

import (
	"testing"
)

// The authentication-factor contracts ask a backend to produce a record
// whose values moved while its Version stayed put, so they can tell a
// compare-and-swap that matches the whole record from one that matches
// Version alone. No exported call reaches that state — every write the
// adapter performs stamps a fresh Version — so the hooks below issue the
// UPDATE themselves, against the same handle and the same configured
// table names the adapter uses. They live in a test file, so they are
// not part of the package's surface.

// DivergeTOTPRecord moves one column of the stored enrolment for subject
// without touching its version column, as a writer that bypassed the
// adapter would. It is the TOTP contract suite's Diverge hook for this
// adapter.
func (s *Store) DivergeTOTPRecord(t *testing.T, subject string) {
	t.Helper()
	s.divergeMFARow(t, s.names.totpSecrets, "failed_count", subject)
}

// DivergeEmailOTPRecord moves one column of the stored challenge for
// subject without touching its version column. It is the
// email-OTP contract suite's Diverge hook for this adapter.
func (s *Store) DivergeEmailOTPRecord(t *testing.T, subject string) {
	t.Helper()
	s.divergeMFARow(t, s.names.emailOTPs, "send_count", subject)
}

// divergeMFARow bumps a single counter column of the subject-keyed row in
// table, leaving every other column — the row version included — as it
// was.
func (s *Store) divergeMFARow(t *testing.T, table, column, subject string) {
	t.Helper()
	query := s.dialect.rebind(
		"UPDATE " + table + " SET " + column + " = " + column + " + 1 WHERE subject = ?",
	)
	res, err := s.db.ExecContext(t.Context(), query, subject)
	if err != nil {
		t.Fatalf("out-of-band update of %s: %v", table, err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		t.Fatalf("RowsAffected on the out-of-band update of %s: %v", table, err)
	}
	if affected != 1 {
		t.Fatalf("out-of-band update of %s touched %d rows, want 1", table, affected)
	}
}
