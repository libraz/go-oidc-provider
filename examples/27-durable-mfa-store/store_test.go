//go:build example

package main

import (
	"bytes"
	"context"
	databasesql "database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/libraz/go-oidc-provider/op/store"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

// openStore opens the SQLite file at path, migrates the adapter over
// it, and returns the store. A file DSN (not :memory:) is deliberate:
// the point of this example is that the factor rows outlive the
// process, which an in-memory database cannot express.
func openStore(t *testing.T, path string) (*oidcsql.Store, *databasesql.DB) {
	t.Helper()
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := databasesql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	s, err := oidcsql.New(db, oidcsql.SQLite())
	if err != nil {
		t.Fatalf("oidcsql.New: %v", err)
	}
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return s, db
}

// TestFactorsSurviveRestart is the claim the browser round-trip cannot
// make: a TOTP enrolment and a cross-factor lockout counter written
// through one process are still there after the connection is closed
// and the database reopened. Everything else about these stores —
// replay rejection, versioned compare-and-swap, error spellings — is
// pinned by the adapter's own op/store/contract run, so this test
// deliberately checks durability and nothing else.
func TestFactorsSurviveRestart(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "durable.db")
	ctx := context.Background()

	wantTOTP := &store.TOTPRecord{
		Subject: demoSubject,
		// Opaque AES-256-GCM envelope bytes. The store round-trips them
		// verbatim; a lossy text encoding would corrupt the secret.
		SecretCiphertext: []byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0x10},
		ConfirmedAt:      time.Unix(1_700_000_000, 0),
		LastAcceptedStep: 42,
	}
	wantLockout := &store.AuthnLockoutRecord{
		Subject:        demoSubject,
		FailedCount:    3,
		FirstFailureAt: time.Unix(1_700_000_500, 0),
	}

	// First process: enrol the factor and record some failures.
	first, db := openStore(t, path)
	if err := first.TOTPs().Put(ctx, wantTOTP); err != nil {
		t.Fatalf("TOTPs().Put: %v", err)
	}
	// Version 0 is the insert-only transition; the backend owns the
	// increment, so the persisted record comes back at version 1.
	swapped, err := first.AuthnLockouts().CompareAndSwap(ctx, 0, wantLockout)
	if err != nil {
		t.Fatalf("AuthnLockouts().CompareAndSwap: %v", err)
	}
	if !swapped {
		t.Fatal("CompareAndSwap(0, ...) = false, want true on an empty table")
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Second process: the same file, a fresh connection pool.
	second, _ := openStore(t, path)

	gotTOTP, err := second.TOTPs().Get(ctx, demoSubject)
	if err != nil {
		t.Fatalf("TOTPs().Get(after reopen): %v", err)
	}
	if !bytes.Equal(gotTOTP.SecretCiphertext, wantTOTP.SecretCiphertext) {
		t.Errorf("SecretCiphertext = %x, want %x", gotTOTP.SecretCiphertext, wantTOTP.SecretCiphertext)
	}
	if !gotTOTP.ConfirmedAt.Equal(wantTOTP.ConfirmedAt) {
		t.Errorf("ConfirmedAt = %v, want %v", gotTOTP.ConfirmedAt, wantTOTP.ConfirmedAt)
	}
	if gotTOTP.LastAcceptedStep != wantTOTP.LastAcceptedStep {
		t.Errorf("LastAcceptedStep = %d, want %d", gotTOTP.LastAcceptedStep, wantTOTP.LastAcceptedStep)
	}

	gotLockout, err := second.AuthnLockouts().Get(ctx, demoSubject)
	if err != nil {
		t.Fatalf("AuthnLockouts().Get(after reopen): %v", err)
	}
	if gotLockout.FailedCount != wantLockout.FailedCount {
		t.Errorf("FailedCount = %d, want %d", gotLockout.FailedCount, wantLockout.FailedCount)
	}
	if !gotLockout.FirstFailureAt.Equal(wantLockout.FirstFailureAt) {
		t.Errorf("FirstFailureAt = %v, want %v", gotLockout.FirstFailureAt, wantLockout.FirstFailureAt)
	}
	// The guess budget an attacker faces after a restart is the same
	// budget, at the same version — not a fresh one.
	if gotLockout.Version != 1 {
		t.Errorf("Version = %d, want 1", gotLockout.Version)
	}
}
