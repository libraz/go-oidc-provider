package oidcsql_test

import (
	"context"
	databasesql "database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

// TestSQLite_MFACompareAndSwapMatchesTheWholeRecord pins the precondition
// [store.TOTPStore.CompareAndSwap] and [store.EmailOTPStore.CompareAndSwap]
// state: the stored record has to equal previous field for field, not
// merely carry the same Version.
//
// The two conditions only ever disagree on a record whose values moved
// without its Version following, which is what the out-of-band UPDATE
// below produces. A backend that gated on the Version alone would apply
// the swap there, overwriting a record the caller never read — and the
// caller's next read would show a counter or a lock that its own write
// silently erased.
func TestSQLite_MFACompareAndSwapMatchesTheWholeRecord(t *testing.T) {
	t.Parallel()

	dsn := "file:" + filepath.Join(t.TempDir(), "oidc.db") + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := databasesql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	clock := &fixedClock{now: contract.Reference}
	s, err := oidcsql.New(db, oidcsql.SQLite(), oidcsql.WithClock(clock))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	t.Run("TOTP", func(t *testing.T) {
		t.Parallel()

		const subject = "whole-record-totp"
		if err := s.TOTPs().Put(ctx, &store.TOTPRecord{
			Subject:          subject,
			SecretCiphertext: []byte{0x01, 0x02},
			ConfirmedAt:      contract.Reference,
		}); err != nil {
			t.Fatalf("Put: %v", err)
		}
		previous, err := s.TOTPs().Get(ctx, subject)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}

		// A value moves and the generation token does not follow it, so
		// the stored record now matches previous on Version alone.
		if _, err := db.ExecContext(ctx,
			"UPDATE oidc_totp_secrets SET failed_count = failed_count + 1 WHERE subject = ?", subject); err != nil {
			t.Fatalf("out-of-band update: %v", err)
		}
		diverged, err := s.TOTPs().Get(ctx, subject)
		if err != nil {
			t.Fatalf("Get after the out-of-band update: %v", err)
		}
		if diverged.Version != previous.Version {
			t.Fatalf("the out-of-band update moved Version to %d; it has to stay at %d for this case to exist",
				diverged.Version, previous.Version)
		}

		next := *previous
		next.LockedUntil = contract.Reference.Add(time.Hour)
		if err := s.TOTPs().CompareAndSwap(ctx, previous, &next); !errors.Is(err, store.ErrAlreadyConsumed) {
			t.Fatalf("CompareAndSwap on a Version-equal, value-different record = %v, want ErrAlreadyConsumed", err)
		}
		after, err := s.TOTPs().Get(ctx, subject)
		if err != nil {
			t.Fatalf("Get after the refused swap: %v", err)
		}
		if !reflect.DeepEqual(after, diverged) {
			t.Errorf("the refused swap changed the record: %+v, want %+v", after, diverged)
		}
	})

	t.Run("EmailOTP", func(t *testing.T) {
		t.Parallel()

		const subject = "whole-record-email"
		if err := s.EmailOTPs().Put(ctx, &store.EmailOTPRecord{
			Subject:     subject,
			CodeSalt:    []byte{0x03},
			CodeHash:    []byte{0x04},
			SentAt:      contract.Reference,
			ExpiresAt:   contract.Reference.Add(5 * time.Minute),
			RetainUntil: contract.Reference.Add(24 * time.Hour),
			SendCount:   1,
		}); err != nil {
			t.Fatalf("Put: %v", err)
		}
		previous, err := s.EmailOTPs().Get(ctx, subject)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}

		if _, err := db.ExecContext(ctx,
			"UPDATE oidc_email_otps SET send_count = send_count + 1 WHERE subject = ?", subject); err != nil {
			t.Fatalf("out-of-band update: %v", err)
		}
		diverged, err := s.EmailOTPs().Get(ctx, subject)
		if err != nil {
			t.Fatalf("Get after the out-of-band update: %v", err)
		}
		if diverged.Version != previous.Version {
			t.Fatalf("the out-of-band update moved Version to %d; it has to stay at %d for this case to exist",
				diverged.Version, previous.Version)
		}

		next := *previous
		next.FailedCount++
		if err := s.EmailOTPs().CompareAndSwap(ctx, previous, &next); !errors.Is(err, store.ErrAlreadyConsumed) {
			t.Fatalf("CompareAndSwap on a Version-equal, value-different record = %v, want ErrAlreadyConsumed", err)
		}
		after, err := s.EmailOTPs().Get(ctx, subject)
		if err != nil {
			t.Fatalf("Get after the refused swap: %v", err)
		}
		if !reflect.DeepEqual(after, diverged) {
			t.Errorf("the refused swap changed the record: %+v, want %+v", after, diverged)
		}
	})
}
