package oidcsql

import (
	"bytes"
	"context"
	databasesql "database/sql"
	"errors"

	"github.com/libraz/go-oidc-provider/op/store"
)

// totpStore is the SQL-backed [store.TOTPStore]. Unlike the substores
// reachable through [store.Store], TOTP enrolments are handed straight
// to the login flow, so this handle never participates in a
// transaction: every transition is one conditional statement.
type totpStore struct {
	parent *Store
}

func newTOTPStore(s *Store) *totpStore { return &totpStore{parent: s} }

func (s *totpStore) Get(ctx context.Context, subject string) (*store.TOTPRecord, error) {
	rec, err := s.scanOne(ctx, subject)
	if err != nil {
		return nil, err
	}
	return rec, nil
}

func (s *totpStore) Put(ctx context.Context, r *store.TOTPRecord) error {
	if r == nil {
		return errors.New("oidcsql: nil totp record")
	}
	if r.Subject == "" {
		return errors.New("oidcsql: totp record missing Subject")
	}
	args := append([]any{r.Subject}, totpValues(r)...)
	if _, err := s.parent.db.ExecContext(ctx, s.parent.queries.totpPut, args...); err != nil {
		return wrapErr("totp.Put", err)
	}
	return nil
}

func (s *totpStore) CompareAndSwap(ctx context.Context, previous, next *store.TOTPRecord) error {
	if previous == nil || next == nil || previous.Subject == "" || next.Subject != previous.Subject {
		return errors.New("oidcsql: invalid totp compare-and-swap record")
	}
	args := totpValues(next)
	args = append(args, previous.Subject)
	args = append(args, totpValues(previous)...)
	res, err := s.parent.db.ExecContext(ctx, s.parent.queries.totpCompareAndSwap, args...)
	if err != nil {
		return wrapErr("totp.CompareAndSwap", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return wrapErr("totp.CompareAndSwap.RowsAffected", err)
	}
	if n > 0 {
		return nil
	}
	return s.settleNoOp(ctx, next)
}

func (s *totpStore) Accept(ctx context.Context, r *store.TOTPRecord) error {
	if r == nil {
		return errors.New("oidcsql: nil totp record")
	}
	if r.Subject == "" {
		return errors.New("oidcsql: totp record missing Subject")
	}
	// A zero step carries no replay protection, so it can never be the
	// value a success transition advances to.
	if r.LastAcceptedStep == 0 {
		return store.ErrAlreadyConsumed
	}
	args := totpValues(r)
	args = append(args, r.Subject, r.LastAcceptedStep)
	res, err := s.parent.db.ExecContext(ctx, s.parent.queries.totpAccept, args...)
	if err != nil {
		return wrapErr("totp.Accept", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return wrapErr("totp.Accept.RowsAffected", err)
	}
	if n > 0 {
		return nil
	}
	if _, err := s.scanOne(ctx, r.Subject); errors.Is(err, store.ErrNotFound) {
		return store.ErrNotFound
	} else if err != nil {
		return err
	}
	return store.ErrAlreadyConsumed
}

func (s *totpStore) Delete(ctx context.Context, subject string) error {
	res, err := s.parent.db.ExecContext(ctx, s.parent.queries.totpDelete, subject)
	if err != nil {
		return wrapErr("totp.Delete", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return wrapErr("totp.Delete.RowsAffected", err)
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// settleNoOp resolves a compare-and-swap that reported zero affected
// rows. MySQL reports zero when an UPDATE matched a row but left every
// column at its existing value, so "no rows changed" is not by itself
// proof that the swap lost: the stored row is re-read and a row that
// already equals next is reported as a success. Anything else means
// another transition won the race.
func (s *totpStore) settleNoOp(ctx context.Context, next *store.TOTPRecord) error {
	current, err := s.scanOne(ctx, next.Subject)
	if errors.Is(err, store.ErrNotFound) {
		return store.ErrAlreadyConsumed
	}
	if err != nil {
		return err
	}
	if totpEqual(current, next) {
		return nil
	}
	return store.ErrAlreadyConsumed
}

func (s *totpStore) scanOne(ctx context.Context, subject string) (*store.TOTPRecord, error) {
	var (
		rec       store.TOTPRecord
		secret    []byte
		confirmed int64
		firstFail int64
		locked    int64
	)
	err := s.parent.db.QueryRowContext(ctx, s.parent.queries.totpGet, subject).Scan(
		&rec.Subject, &secret, &rec.FailedCount, &rec.LastAcceptedStep,
		&confirmed, &firstFail, &locked)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, wrapErr("totp.Get", err)
	}
	rec.SecretCiphertext = append([]byte(nil), secret...)
	rec.ConfirmedAt = int64ToTime(confirmed)
	rec.FirstFailureAt = int64ToTime(firstFail)
	rec.LockedUntil = int64ToTime(locked)
	return &rec, nil
}

// totpValues renders the record's value columns in the order declared
// by [totpValueColumns].
func totpValues(r *store.TOTPRecord) []any {
	return []any{
		nonNilBytes(r.SecretCiphertext),
		r.FailedCount,
		r.LastAcceptedStep,
		timeToInt64(r.ConfirmedAt),
		timeToInt64(r.FirstFailureAt),
		timeToInt64(r.LockedUntil),
	}
}

func totpEqual(a, b *store.TOTPRecord) bool {
	return a.Subject == b.Subject &&
		bytes.Equal(a.SecretCiphertext, b.SecretCiphertext) &&
		a.FailedCount == b.FailedCount &&
		a.LastAcceptedStep == b.LastAcceptedStep &&
		a.ConfirmedAt.Equal(b.ConfirmedAt) &&
		a.FirstFailureAt.Equal(b.FirstFailureAt) &&
		a.LockedUntil.Equal(b.LockedUntil)
}

// nonNilBytes normalises a nil slice to an empty one. The columns are
// declared NOT NULL so a nil would otherwise be rejected by the engine,
// and a nil / empty round-trip difference would surface as a spurious
// compare-and-swap mismatch.
func nonNilBytes(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}
