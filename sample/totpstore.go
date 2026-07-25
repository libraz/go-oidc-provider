//go:build example

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	opstore "github.com/libraz/go-oidc-provider/op/store"
)

// The bundled SQL adapter persists the OIDC substores but not the
// authentication factors: their schema and key management are deployment
// decisions, so the library leaves them to the embedder. This file is that
// decision made once, for MySQL.
//
// The transitions are what make it more than a key-value table. Accept and
// CompareAndSwap both have to be single-winner under concurrency, because
// they are what stop a code from being redeemed twice and what stop a
// stale snapshot from rolling the failure counter backwards. Both are
// therefore expressed as conditional UPDATEs and judged by the affected
// row count, never as read-then-write.
const totpDDL = `
CREATE TABLE IF NOT EXISTS member_totp (
  subject            VARCHAR(64)   NOT NULL PRIMARY KEY,
  secret_ciphertext  VARBINARY(512) NOT NULL,
  confirmed_at       DATETIME(6)   NULL,
  failed_count       INT           NOT NULL DEFAULT 0,
  first_failure_at   DATETIME(6)   NULL,
  locked_until       DATETIME(6)   NULL,
  last_accepted_step BIGINT        NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`

// mysqlTOTPStore implements [opstore.TOTPStore] against MySQL.
type mysqlTOTPStore struct {
	db *sql.DB
}

func newTOTPStore(ctx context.Context, db *sql.DB) (*mysqlTOTPStore, error) {
	if _, err := db.ExecContext(ctx, totpDDL); err != nil {
		return nil, fmt.Errorf("create member_totp table: %w", err)
	}
	return &mysqlTOTPStore{db: db}, nil
}

// nullTime maps a zero time.Time onto SQL NULL, so "never confirmed" and
// "no failures yet" round-trip as absence rather than as the year zero.
func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC()
}

func timeOf(n sql.NullTime) time.Time {
	if !n.Valid {
		return time.Time{}
	}
	return n.Time
}

// Get implements [opstore.TOTPStore].
func (s *mysqlTOTPStore) Get(ctx context.Context, subject string) (*opstore.TOTPRecord, error) {
	const q = `SELECT secret_ciphertext, confirmed_at, failed_count,
	                  first_failure_at, locked_until, last_accepted_step
	           FROM member_totp WHERE subject = ?`
	var (
		rec                             opstore.TOTPRecord
		confirmed, firstFailure, locked sql.NullTime
	)
	err := s.db.QueryRowContext(ctx, q, subject).Scan(
		&rec.SecretCiphertext, &confirmed, &rec.FailedCount,
		&firstFailure, &locked, &rec.LastAcceptedStep,
	)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, opstore.ErrNotFound
	case err != nil:
		return nil, err
	}
	rec.Subject = subject
	rec.ConfirmedAt = timeOf(confirmed)
	rec.FirstFailureAt = timeOf(firstFailure)
	rec.LockedUntil = timeOf(locked)
	return &rec, nil
}

// Put implements [opstore.TOTPStore] with upsert semantics.
func (s *mysqlTOTPStore) Put(ctx context.Context, r *opstore.TOTPRecord) error {
	if r == nil || r.Subject == "" {
		return errors.New("sample: totp record needs a subject")
	}
	const q = `INSERT INTO member_totp
	   (subject, secret_ciphertext, confirmed_at, failed_count,
	    first_failure_at, locked_until, last_accepted_step)
	   VALUES (?, ?, ?, ?, ?, ?, ?)
	   ON DUPLICATE KEY UPDATE
	     secret_ciphertext  = VALUES(secret_ciphertext),
	     confirmed_at       = VALUES(confirmed_at),
	     failed_count       = VALUES(failed_count),
	     first_failure_at   = VALUES(first_failure_at),
	     locked_until       = VALUES(locked_until),
	     last_accepted_step = VALUES(last_accepted_step)`
	_, err := s.db.ExecContext(ctx, q,
		r.Subject, r.SecretCiphertext, nullTime(r.ConfirmedAt), r.FailedCount,
		nullTime(r.FirstFailureAt), nullTime(r.LockedUntil), r.LastAcceptedStep,
	)
	return err
}

// CompareAndSwap implements [opstore.TOTPStore]. The whole previous state
// goes into the WHERE clause, so a concurrent writer that already moved
// the row makes this update match zero rows.
func (s *mysqlTOTPStore) CompareAndSwap(ctx context.Context, previous, next *opstore.TOTPRecord) error {
	if previous == nil || next == nil {
		return errors.New("sample: totp compare-and-swap needs both records")
	}
	if previous.Subject != next.Subject {
		return errors.New("sample: totp compare-and-swap across subjects")
	}
	const q = `UPDATE member_totp SET
	     secret_ciphertext  = ?,
	     confirmed_at       = ?,
	     failed_count       = ?,
	     first_failure_at   = ?,
	     locked_until       = ?,
	     last_accepted_step = ?
	   WHERE subject = ?
	     AND failed_count = ?
	     AND last_accepted_step = ?
	     AND confirmed_at <=> ?
	     AND first_failure_at <=> ?
	     AND locked_until <=> ?`
	res, err := s.db.ExecContext(ctx, q,
		next.SecretCiphertext, nullTime(next.ConfirmedAt), next.FailedCount,
		nullTime(next.FirstFailureAt), nullTime(next.LockedUntil), next.LastAcceptedStep,
		previous.Subject, previous.FailedCount, previous.LastAcceptedStep,
		nullTime(previous.ConfirmedAt), nullTime(previous.FirstFailureAt),
		nullTime(previous.LockedUntil),
	)
	if err != nil {
		return err
	}
	return oneWinner(ctx, s, previous.Subject, res)
}

// Accept implements [opstore.TOTPStore]. The guard is the step counter
// alone: a code from a step already redeemed must not be accepted again,
// which is what makes a replayed code inside the same window fail.
func (s *mysqlTOTPStore) Accept(ctx context.Context, r *opstore.TOTPRecord) error {
	if r == nil {
		return errors.New("sample: totp accept needs a record")
	}
	const q = `UPDATE member_totp SET
	     confirmed_at       = ?,
	     failed_count       = ?,
	     first_failure_at   = ?,
	     locked_until       = ?,
	     last_accepted_step = ?
	   WHERE subject = ? AND last_accepted_step < ?`
	res, err := s.db.ExecContext(ctx, q,
		nullTime(r.ConfirmedAt), r.FailedCount, nullTime(r.FirstFailureAt),
		nullTime(r.LockedUntil), r.LastAcceptedStep,
		r.Subject, r.LastAcceptedStep,
	)
	if err != nil {
		return err
	}
	return oneWinner(ctx, s, r.Subject, res)
}

// oneWinner turns "no rows changed" into the right sentinel. A missing row
// is ErrNotFound; a present row that did not match the guard means another
// caller won the transition, which is ErrAlreadyConsumed.
func oneWinner(ctx context.Context, s *mysqlTOTPStore, subject string, res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	if _, err := s.Get(ctx, subject); errors.Is(err, opstore.ErrNotFound) {
		return opstore.ErrNotFound
	} else if err != nil {
		return err
	}
	return opstore.ErrAlreadyConsumed
}

// Delete implements [opstore.TOTPStore].
func (s *mysqlTOTPStore) Delete(ctx context.Context, subject string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM member_totp WHERE subject = ?`, subject)
	if err != nil {
		return err
	}
	return expectOneRow(res)
}
