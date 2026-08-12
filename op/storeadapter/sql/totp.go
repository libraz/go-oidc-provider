package oidcsql

import (
	"context"
	databasesql "database/sql"
	"errors"
	"fmt"
	"math"

	internalkeys "github.com/libraz/go-oidc-provider/internal/keys"
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
	version, err := internalkeys.RandomInt63Except(0)
	if err != nil {
		return fmt.Errorf("oidcsql: totp.Put: generate Version: %w", err)
	}
	args := append([]any{r.Subject, version}, totpValues(r)...)
	if _, err := s.parent.db.ExecContext(ctx, s.parent.queries.totpPut, args...); err != nil {
		return wrapErr("totp.Put", err)
	}
	return nil
}

func (s *totpStore) CompareAndSwap(ctx context.Context, previous, next *store.TOTPRecord) error {
	if previous == nil || next == nil || previous.Subject == "" || next.Subject != previous.Subject {
		return errors.New("oidcsql: invalid totp compare-and-swap record")
	}
	if previous.Version == 0 || previous.Version >= math.MaxInt64 || next.Version != previous.Version {
		return store.ErrAlreadyConsumed
	}
	version, err := internalkeys.RandomInt63Except(int64(previous.Version))
	if err != nil {
		return fmt.Errorf("oidcsql: totp.CompareAndSwap: generate Version: %w", err)
	}
	args := totpValues(next)
	args = append(args, version, previous.Subject)
	args = append(args, int64(previous.Version))
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
	return store.ErrAlreadyConsumed
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
	if r.Version == 0 || r.Version >= math.MaxInt64 {
		return store.ErrAlreadyConsumed
	}
	version, err := internalkeys.RandomInt63Except(int64(r.Version))
	if err != nil {
		return fmt.Errorf("oidcsql: totp.Accept: generate Version: %w", err)
	}
	args := totpValues(r)
	args = append(args, version, r.Subject, r.LastAcceptedStep,
		nonNilBytes(r.SecretCiphertext), timeToInt64(r.ConfirmedAt), int64(r.Version))
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

func (s *totpStore) scanOne(ctx context.Context, subject string) (*store.TOTPRecord, error) {
	var (
		rec       store.TOTPRecord
		secret    []byte
		version   int64
		confirmed int64
		firstFail int64
		locked    int64
	)
	err := s.parent.db.QueryRowContext(ctx, s.parent.queries.totpGet, subject).Scan(
		&rec.Subject, &version, &secret, &rec.FailedCount, &rec.LastAcceptedStep,
		&confirmed, &firstFail, &locked,
	)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, wrapErr("totp.Get", err)
	}
	if version <= 0 {
		return nil, fmt.Errorf("oidcsql: totp.Get: invalid row_version %d", version)
	}
	rec.SecretCiphertext = append([]byte(nil), secret...)
	rec.Version = uint64(version)
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
