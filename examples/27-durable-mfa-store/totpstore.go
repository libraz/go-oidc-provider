package main

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// sqliteTOTPStore is a persistent reference implementation of
// [store.TOTPStore] backed by a single SQLite table. It is deliberately
// shipped inside an example rather than the library: the SQL storage
// adapter (op/storeadapter/sql) persists the OIDC core tables (clients,
// authorization codes, tokens, sessions, ...) but does NOT bundle
// authentication-factor stores. Factor persistence is the embedder's
// responsibility because the factor schema, encryption-at-rest key
// management, and enrolment lifecycle are deployment decisions.
//
// This file is the pattern an embedder copies for TOTP and adapts for
// the sibling factor stores the login flow may require: passkey
// (store.PasskeyStore), recovery codes (store.RecoveryStore), email OTP
// (store.EmailOTPStore), and the authentication lockout counter
// (store.AuthnLockoutStore). Each has the same shape — a small table
// keyed by subject, opaque blobs the library owns, and upsert / atomic
// single-use semantics defined by the store contract.
//
// The table lives in the same *sql.DB as the core adapter's tables, so
// one connection pool and one migration entry point serve both. Mixing
// a persistent factor store with an in-memory core (or vice versa) is
// not supported: the two must agree on durability.
//
// SecretCiphertext is stored verbatim as an opaque BLOB. It is the
// AES-256-GCM envelope (nonce || ciphertext || tag) the library
// produces; this store never inspects, parses, re-encodes, or logs it.
type sqliteTOTPStore struct {
	db *sql.DB
}

// newSQLiteTOTPStore returns a store bound to db. Call [sqliteTOTPStore.migrate]
// once before first use to create the backing table.
func newSQLiteTOTPStore(db *sql.DB) *sqliteTOTPStore {
	return &sqliteTOTPStore{db: db}
}

// migrate creates the enrolment table if it does not already exist.
// Production embedders run this DDL through their own migration tooling
// alongside the core adapter's schema; the example applies it inline so
// the demo is self-contained.
func (s *sqliteTOTPStore) migrate(ctx context.Context) error {
	const ddl = `CREATE TABLE IF NOT EXISTS mfa_totp_enrolments (
	subject            TEXT PRIMARY KEY,
	secret_ciphertext  BLOB NOT NULL,
	confirmed_at       INTEGER NOT NULL DEFAULT 0,
	failed_count       INTEGER NOT NULL DEFAULT 0,
	first_failure_at   INTEGER NOT NULL DEFAULT 0,
	locked_until       INTEGER NOT NULL DEFAULT 0,
	last_accepted_step INTEGER NOT NULL DEFAULT 0
)`
	_, err := s.db.ExecContext(ctx, ddl)
	return err
}

// Get implements [store.TOTPStore]. It returns [store.ErrNotFound] when
// no enrolment exists for subject.
func (s *sqliteTOTPStore) Get(ctx context.Context, subject string) (*store.TOTPRecord, error) {
	const q = `SELECT secret_ciphertext, confirmed_at, failed_count, first_failure_at, locked_until, last_accepted_step
	FROM mfa_totp_enrolments WHERE subject = ?`
	var (
		secret         []byte
		confirmedAt    int64
		failedCount    int64
		firstFailureAt int64
		lockedUntil    int64
		lastStep       int64
	)
	err := s.db.QueryRowContext(ctx, q, subject).Scan(
		&secret, &confirmedAt, &failedCount, &firstFailureAt, &lockedUntil, &lastStep,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &store.TOTPRecord{
		Subject:          subject,
		SecretCiphertext: secret,
		ConfirmedAt:      unixNanosToTime(confirmedAt),
		FailedCount:      int(failedCount),
		FirstFailureAt:   unixNanosToTime(firstFailureAt),
		LockedUntil:      unixNanosToTime(lockedUntil),
		LastAcceptedStep: lastStep,
	}, nil
}

// Put implements [store.TOTPStore] with upsert semantics: an existing
// row for r.Subject is overwritten in full. The library calls Put for
// the initial confirmation, every brute-force counter update, and the
// post-success counter reset.
func (s *sqliteTOTPStore) Put(ctx context.Context, r *store.TOTPRecord) error {
	if r == nil {
		return errors.New("sqliteTOTPStore: nil totp record")
	}
	const q = `INSERT INTO mfa_totp_enrolments
	(subject, secret_ciphertext, confirmed_at, failed_count, first_failure_at, locked_until, last_accepted_step)
	VALUES (?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(subject) DO UPDATE SET
		secret_ciphertext  = excluded.secret_ciphertext,
		confirmed_at       = excluded.confirmed_at,
		failed_count       = excluded.failed_count,
		first_failure_at   = excluded.first_failure_at,
		locked_until       = excluded.locked_until,
		last_accepted_step = excluded.last_accepted_step`
	_, err := s.db.ExecContext(ctx, q,
		r.Subject,
		r.SecretCiphertext,
		timeToUnixNanos(r.ConfirmedAt),
		int64(r.FailedCount),
		timeToUnixNanos(r.FirstFailureAt),
		timeToUnixNanos(r.LockedUntil),
		r.LastAcceptedStep,
	)
	return err
}

// Accept implements [store.TOTPStore]. It persists a successful
// verification only if the stored last_accepted_step is strictly less
// than r.LastAcceptedStep, giving the single-use guarantee the contract
// requires: a network-level replay of the same 30-second code cannot
// redeem twice. The comparison and the write happen in one UPDATE so
// the check is atomic against concurrent callers.
//
// It returns [store.ErrAlreadyConsumed] when r.LastAcceptedStep is zero
// or when the stored step is already at or beyond it, and
// [store.ErrNotFound] when no enrolment exists for r.Subject.
func (s *sqliteTOTPStore) Accept(ctx context.Context, r *store.TOTPRecord) error {
	if r == nil {
		return errors.New("sqliteTOTPStore: nil totp record")
	}
	// A zero step never advances the replay guard; short-circuit before
	// touching the row so the semantics match the reference in-memory
	// store exactly.
	if r.LastAcceptedStep == 0 {
		return store.ErrAlreadyConsumed
	}
	const q = `UPDATE mfa_totp_enrolments SET
		secret_ciphertext  = ?,
		confirmed_at       = ?,
		failed_count       = ?,
		first_failure_at   = ?,
		locked_until       = ?,
		last_accepted_step = ?
	WHERE subject = ? AND last_accepted_step < ?`
	res, err := s.db.ExecContext(ctx, q,
		r.SecretCiphertext,
		timeToUnixNanos(r.ConfirmedAt),
		int64(r.FailedCount),
		timeToUnixNanos(r.FirstFailureAt),
		timeToUnixNanos(r.LockedUntil),
		r.LastAcceptedStep,
		r.Subject,
		r.LastAcceptedStep,
	)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 1 {
		return nil
	}
	// No row advanced: either the subject is absent, or the stored step
	// already caught up. Distinguish the two so callers can tell a
	// missing enrolment from a replayed one.
	var exists int
	err = s.db.QueryRowContext(ctx,
		`SELECT 1 FROM mfa_totp_enrolments WHERE subject = ?`, r.Subject,
	).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	if err != nil {
		return err
	}
	return store.ErrAlreadyConsumed
}

// Delete implements [store.TOTPStore]. It returns [store.ErrNotFound]
// when no enrolment exists for subject so callers can tell a no-op
// delete from a successful one.
func (s *sqliteTOTPStore) Delete(ctx context.Context, subject string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM mfa_totp_enrolments WHERE subject = ?`, subject,
	)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return store.ErrNotFound
	}
	return nil
}

// timeToUnixNanos encodes t as unix nanoseconds, mapping the zero time
// to 0 so a never-set timestamp round-trips as the sentinel the schema
// defaults to.
func timeToUnixNanos(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

// unixNanosToTime is the inverse of [timeToUnixNanos]: 0 decodes to the
// zero time, any other value to the corresponding instant.
func unixNanosToTime(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n)
}
