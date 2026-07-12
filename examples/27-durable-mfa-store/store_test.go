//go:build example

package main

import (
	"bytes"
	"context"
	databasesql "database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/libraz/go-oidc-provider/op/store"
)

// openTestDB opens a fresh SQLite file under t.TempDir() and returns
// the *sql.DB. A file DSN (not :memory:) is deliberate: the durability
// test reopens the same file in a second connection, which an in-memory
// database cannot express.
func openTestDB(t *testing.T, path string) *databasesql.DB {
	t.Helper()
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := databasesql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// newMigratedStore opens a store over path and applies its migration.
func newMigratedStore(t *testing.T, path string) *sqliteTOTPStore {
	t.Helper()
	db := openTestDB(t, path)
	s := newSQLiteTOTPStore(db)
	if err := s.migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return s
}

func sampleRecord() *store.TOTPRecord {
	return &store.TOTPRecord{
		Subject:          "demo-user",
		SecretCiphertext: []byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0x10},
		ConfirmedAt:      time.Unix(1_700_000_000, 0),
		FailedCount:      3,
		FirstFailureAt:   time.Unix(1_700_000_500, 0),
		LockedUntil:      time.Unix(1_700_003_600, 0),
		LastAcceptedStep: 42,
	}
}

func TestPutGetRoundTrip(t *testing.T) {
	s := newMigratedStore(t, filepath.Join(t.TempDir(), "totp.db"))
	ctx := context.Background()

	want := sampleRecord()
	if err := s.Put(ctx, want); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := s.Get(ctx, want.Subject)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	assertRecordEqual(t, got, want)

	// Put is an upsert: a second write overwrites every column.
	want.FailedCount = 7
	want.LastAcceptedStep = 100
	want.SecretCiphertext = []byte{0xaa, 0xbb}
	if err := s.Put(ctx, want); err != nil {
		t.Fatalf("Put(update): %v", err)
	}
	got, err = s.Get(ctx, want.Subject)
	if err != nil {
		t.Fatalf("Get(after update): %v", err)
	}
	assertRecordEqual(t, got, want)
}

func TestGetNotFound(t *testing.T) {
	s := newMigratedStore(t, filepath.Join(t.TempDir(), "totp.db"))
	_, err := s.Get(context.Background(), "absent")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get(absent) = %v, want ErrNotFound", err)
	}
}

func TestPutNilRecord(t *testing.T) {
	s := newMigratedStore(t, filepath.Join(t.TempDir(), "totp.db"))
	if err := s.Put(context.Background(), nil); err == nil {
		t.Fatal("Put(nil) = nil, want error")
	}
}

func TestAccept(t *testing.T) {
	s := newMigratedStore(t, filepath.Join(t.TempDir(), "totp.db"))
	ctx := context.Background()

	base := sampleRecord()
	base.LastAcceptedStep = 10
	if err := s.Put(ctx, base); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Advancing the step succeeds.
	advance := sampleRecord()
	advance.LastAcceptedStep = 11
	if err := s.Accept(ctx, advance); err != nil {
		t.Fatalf("Accept(advance) = %v, want nil", err)
	}
	got, err := s.Get(ctx, advance.Subject)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.LastAcceptedStep != 11 {
		t.Fatalf("LastAcceptedStep = %d, want 11", got.LastAcceptedStep)
	}

	// Re-accepting the same step is a replay.
	if err := s.Accept(ctx, advance); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("Accept(same step) = %v, want ErrAlreadyConsumed", err)
	}

	// An older step is a replay too.
	older := sampleRecord()
	older.LastAcceptedStep = 5
	if err := s.Accept(ctx, older); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("Accept(older step) = %v, want ErrAlreadyConsumed", err)
	}

	// A zero step never advances the guard.
	zero := sampleRecord()
	zero.LastAcceptedStep = 0
	if err := s.Accept(ctx, zero); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("Accept(zero step) = %v, want ErrAlreadyConsumed", err)
	}

	// A missing subject is distinguishable from a replay.
	absent := sampleRecord()
	absent.Subject = "absent"
	absent.LastAcceptedStep = 99
	if err := s.Accept(ctx, absent); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Accept(absent) = %v, want ErrNotFound", err)
	}
}

func TestAcceptNilRecord(t *testing.T) {
	s := newMigratedStore(t, filepath.Join(t.TempDir(), "totp.db"))
	if err := s.Accept(context.Background(), nil); err == nil {
		t.Fatal("Accept(nil) = nil, want error")
	}
}

func TestDelete(t *testing.T) {
	s := newMigratedStore(t, filepath.Join(t.TempDir(), "totp.db"))
	ctx := context.Background()

	rec := sampleRecord()
	if err := s.Put(ctx, rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Delete(ctx, rec.Subject); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(ctx, rec.Subject); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get(after delete) = %v, want ErrNotFound", err)
	}
	if err := s.Delete(ctx, rec.Subject); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Delete(absent) = %v, want ErrNotFound", err)
	}
}

func TestZeroTimeRoundTrip(t *testing.T) {
	s := newMigratedStore(t, filepath.Join(t.TempDir(), "totp.db"))
	ctx := context.Background()

	rec := sampleRecord()
	rec.FirstFailureAt = time.Time{}
	rec.LockedUntil = time.Time{}
	if err := s.Put(ctx, rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get(ctx, rec.Subject)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.FirstFailureAt.IsZero() {
		t.Errorf("FirstFailureAt = %v, want zero", got.FirstFailureAt)
	}
	if !got.LockedUntil.IsZero() {
		t.Errorf("LockedUntil = %v, want zero", got.LockedUntil)
	}
}

// TestDurability proves the store is not process-local: a record
// written through one connection survives a Close and reopen of the
// same file, ciphertext bytes and all.
func TestDurability(t *testing.T) {
	path := filepath.Join(t.TempDir(), "durable.db")
	ctx := context.Background()

	want := sampleRecord()

	// First connection: write, then close it entirely.
	db1 := openTestDB(t, path)
	s1 := newSQLiteTOTPStore(db1)
	if err := s1.migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := s1.Put(ctx, want); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := db1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Second connection over the same file: the record is still there.
	db2 := openTestDB(t, path)
	s2 := newSQLiteTOTPStore(db2)
	got, err := s2.Get(ctx, want.Subject)
	if err != nil {
		t.Fatalf("Get(after reopen): %v", err)
	}
	assertRecordEqual(t, got, want)
}

func assertRecordEqual(t *testing.T, got, want *store.TOTPRecord) {
	t.Helper()
	if got.Subject != want.Subject {
		t.Errorf("Subject = %q, want %q", got.Subject, want.Subject)
	}
	if !bytes.Equal(got.SecretCiphertext, want.SecretCiphertext) {
		t.Errorf("SecretCiphertext = %x, want %x", got.SecretCiphertext, want.SecretCiphertext)
	}
	if !got.ConfirmedAt.Equal(want.ConfirmedAt) {
		t.Errorf("ConfirmedAt = %v, want %v", got.ConfirmedAt, want.ConfirmedAt)
	}
	if got.FailedCount != want.FailedCount {
		t.Errorf("FailedCount = %d, want %d", got.FailedCount, want.FailedCount)
	}
	if !got.FirstFailureAt.Equal(want.FirstFailureAt) {
		t.Errorf("FirstFailureAt = %v, want %v", got.FirstFailureAt, want.FirstFailureAt)
	}
	if !got.LockedUntil.Equal(want.LockedUntil) {
		t.Errorf("LockedUntil = %v, want %v", got.LockedUntil, want.LockedUntil)
	}
	if got.LastAcceptedStep != want.LastAcceptedStep {
		t.Errorf("LastAcceptedStep = %d, want %d", got.LastAcceptedStep, want.LastAcceptedStep)
	}
}
