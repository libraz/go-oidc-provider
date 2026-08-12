package oidcsql_test

import (
	"context"
	databasesql "database/sql"
	"errors"
	"math"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

// TestSQLite_StoreIssuedMFAVersionCAS opens a real file-backed SQLite
// database, closes the first adapter/connection, and then opens a fresh
// connection before exercising stale writes. Two Store values over one live
// *sql.DB do not prove that the generation survives a process restart: both
// can accidentally share process-local state or an open SQLite snapshot.
func TestSQLite_StoreIssuedMFAVersionCAS(t *testing.T) {
	t.Parallel()

	dsn := "file:" + filepath.Join(t.TempDir(), "oidc.db") + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	clock := &fixedClock{now: contract.Reference}
	ctx := context.Background()

	db1, err := databasesql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open first SQLite connection: %v", err)
	}
	db1.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db1.Close() })
	a, err := oidcsql.New(db1, oidcsql.SQLite(), oidcsql.WithClock(clock))
	if err != nil {
		t.Fatalf("New first adapter: %v", err)
	}
	if err := a.Migrate(ctx); err != nil {
		t.Fatalf("Migrate first adapter: %v", err)
	}

	totpSeed := &store.TOTPRecord{
		Subject:          "reopen-versioned-totp",
		SecretCiphertext: []byte{0x01, 0x02, 0x03},
		ConfirmedAt:      contract.Reference.Add(-time.Hour),
	}
	if err := a.TOTPs().Put(ctx, totpSeed); err != nil {
		t.Fatalf("first TOTP Put: %v", err)
	}
	totpBeforeClose, err := a.TOTPs().Get(ctx, totpSeed.Subject)
	if err != nil {
		t.Fatalf("first TOTP Get: %v", err)
	}
	if totpBeforeClose.Version == 0 {
		t.Fatal("first TOTP Get returned zero Version")
	}

	emailSeed := &store.EmailOTPRecord{
		Subject:     "reopen-versioned-email",
		CodeSalt:    []byte{0x04, 0x05},
		CodeHash:    []byte{0xa0, 0xb0},
		SentAt:      contract.Reference,
		ExpiresAt:   contract.Reference.Add(time.Hour),
		RetainUntil: contract.Reference.Add(24 * time.Hour),
	}
	if err := a.EmailOTPs().Put(ctx, emailSeed); err != nil {
		t.Fatalf("first email OTP Put: %v", err)
	}
	emailBeforeClose, err := a.EmailOTPs().Get(ctx, emailSeed.Subject)
	if err != nil {
		t.Fatalf("first email OTP Get: %v", err)
	}
	if emailBeforeClose.Version == 0 {
		t.Fatal("first email OTP Get returned zero Version")
	}

	if err := db1.Close(); err != nil {
		t.Fatalf("close first SQLite connection: %v", err)
	}

	db2, err := databasesql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("reopen SQLite connection: %v", err)
	}
	db2.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db2.Close() })
	b, err := oidcsql.New(db2, oidcsql.SQLite(), oidcsql.WithClock(clock))
	if err != nil {
		t.Fatalf("New reopened adapter: %v", err)
	}
	if err := b.Migrate(ctx); err != nil {
		t.Fatalf("Migrate reopened adapter: %v", err)
	}

	totpAfterReopen, err := b.TOTPs().Get(ctx, totpSeed.Subject)
	if err != nil {
		t.Fatalf("reopened TOTP Get: %v", err)
	}
	if totpAfterReopen.Version != totpBeforeClose.Version {
		t.Fatalf("reopened TOTP Version = %d, want persisted %d", totpAfterReopen.Version, totpBeforeClose.Version)
	}
	emailAfterReopen, err := b.EmailOTPs().Get(ctx, emailSeed.Subject)
	if err != nil {
		t.Fatalf("reopened email OTP Get: %v", err)
	}
	if emailAfterReopen.Version != emailBeforeClose.Version {
		t.Fatalf("reopened email OTP Version = %d, want persisted %d", emailAfterReopen.Version, emailBeforeClose.Version)
	}

	// Advance each row after reopening, then submit the snapshot captured by
	// the closed adapter. A process restart must not turn that stale snapshot
	// into a successful write. The winning transition is value-identical so
	// Version, not a changed tuple field, is the only reason the stale retry
	// loses.
	totpWinner := *totpAfterReopen
	if err := b.TOTPs().CompareAndSwap(ctx, totpAfterReopen, &totpWinner); err != nil {
		t.Fatalf("reopened TOTP CAS winner: %v", err)
	}
	totpStaleNext := *totpBeforeClose
	if err := b.TOTPs().CompareAndSwap(ctx, totpBeforeClose, &totpStaleNext); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("stale TOTP CAS after reopen = %v, want ErrAlreadyConsumed", err)
	}

	emailWinner := *emailAfterReopen
	if err := b.EmailOTPs().CompareAndSwap(ctx, emailAfterReopen, &emailWinner); err != nil {
		t.Fatalf("reopened email OTP CAS winner: %v", err)
	}
	emailStaleNext := *emailBeforeClose
	if err := b.EmailOTPs().CompareAndSwap(ctx, emailBeforeClose, &emailStaleNext); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("stale email OTP CAS after reopen = %v, want ErrAlreadyConsumed", err)
	}

	// A legacy row at the signed BIGINT maximum is still replaceable: Put
	// installs a fresh opaque token rather than incrementing the old value or
	// treating RowsAffected as an overflow signal.
	if _, err := db2.ExecContext(ctx, "UPDATE oidc_totp_secrets SET row_version = ? WHERE subject = ?", int64(math.MaxInt64), totpSeed.Subject); err != nil {
		t.Fatalf("set TOTP maximum Version: %v", err)
	}
	maxTOTP, err := b.TOTPs().Get(ctx, totpSeed.Subject)
	if err != nil {
		t.Fatalf("get TOTP maximum Version: %v", err)
	}
	maxTOTPCASNext := *maxTOTP
	maxTOTPCASNext.FailedCount++
	if err := b.TOTPs().CompareAndSwap(ctx, maxTOTP, &maxTOTPCASNext); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("TOTP CAS at maximum Version = %v, want ErrAlreadyConsumed", err)
	}
	if afterRejectedCAS, err := b.TOTPs().Get(ctx, totpSeed.Subject); err != nil || !reflect.DeepEqual(afterRejectedCAS, maxTOTP) {
		t.Fatalf("TOTP CAS at maximum mutated row: record=%+v err=%v, want %+v", afterRejectedCAS, err, maxTOTP)
	}
	maxTOTPAccept := *maxTOTP
	maxTOTPAccept.LastAcceptedStep = 1
	if err := b.TOTPs().Accept(ctx, &maxTOTPAccept); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("TOTP Accept at maximum Version = %v, want ErrAlreadyConsumed", err)
	}
	if afterRejectedAccept, err := b.TOTPs().Get(ctx, totpSeed.Subject); err != nil || !reflect.DeepEqual(afterRejectedAccept, maxTOTP) {
		t.Fatalf("TOTP Accept at maximum mutated row: record=%+v err=%v, want %+v", afterRejectedAccept, err, maxTOTP)
	}
	maxTOTPReplacement := *maxTOTP
	maxTOTPReplacement.FailedCount++
	if err := b.TOTPs().Put(ctx, &maxTOTPReplacement); err != nil {
		t.Fatalf("Put over TOTP maximum Version: %v", err)
	}
	newTOTP, err := b.TOTPs().Get(ctx, totpSeed.Subject)
	if err != nil {
		t.Fatalf("get TOTP after maximum recovery: %v", err)
	}
	if newTOTP.Version == 0 || newTOTP.Version == uint64(math.MaxInt64) || newTOTP.FailedCount != maxTOTPReplacement.FailedCount {
		t.Fatalf("TOTP maximum recovery = version %d failed_count %d, want fresh token and count %d", newTOTP.Version, newTOTP.FailedCount, maxTOTPReplacement.FailedCount)
	}

	if _, err := db2.ExecContext(ctx, "UPDATE oidc_email_otps SET row_version = ? WHERE subject = ?", int64(math.MaxInt64), emailSeed.Subject); err != nil {
		t.Fatalf("set email OTP maximum Version: %v", err)
	}
	maxEmail, err := b.EmailOTPs().Get(ctx, emailSeed.Subject)
	if err != nil {
		t.Fatalf("get email OTP maximum Version: %v", err)
	}
	maxEmailCASNext := *maxEmail
	maxEmailCASNext.SendCount++
	if err := b.EmailOTPs().CompareAndSwap(ctx, maxEmail, &maxEmailCASNext); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("email OTP CAS at maximum Version = %v, want ErrAlreadyConsumed", err)
	}
	if afterRejectedCAS, err := b.EmailOTPs().Get(ctx, emailSeed.Subject); err != nil || !reflect.DeepEqual(afterRejectedCAS, maxEmail) {
		t.Fatalf("email OTP CAS at maximum mutated row: record=%+v err=%v, want %+v", afterRejectedCAS, err, maxEmail)
	}
	maxEmailConsume := *maxEmail
	maxEmailConsume.ConsumedAt = contract.Reference
	if err := b.EmailOTPs().Consume(ctx, &maxEmailConsume); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("email OTP Consume at maximum Version = %v, want ErrAlreadyConsumed", err)
	}
	if afterRejectedConsume, err := b.EmailOTPs().Get(ctx, emailSeed.Subject); err != nil || !reflect.DeepEqual(afterRejectedConsume, maxEmail) {
		t.Fatalf("email OTP Consume at maximum mutated row: record=%+v err=%v, want %+v", afterRejectedConsume, err, maxEmail)
	}
	maxEmailReplacement := *maxEmail
	maxEmailReplacement.SendCount++
	if err := b.EmailOTPs().Put(ctx, &maxEmailReplacement); err != nil {
		t.Fatalf("Put over email OTP maximum Version: %v", err)
	}
	newEmail, err := b.EmailOTPs().Get(ctx, emailSeed.Subject)
	if err != nil {
		t.Fatalf("get email OTP after maximum recovery: %v", err)
	}
	if newEmail.Version == 0 || newEmail.Version == uint64(math.MaxInt64) || newEmail.SendCount != maxEmailReplacement.SendCount {
		t.Fatalf("email OTP maximum recovery = version %d send_count %d, want fresh token and count %d", newEmail.Version, newEmail.SendCount, maxEmailReplacement.SendCount)
	}
}
