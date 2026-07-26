package oidcsql

import (
	"bytes"
	"context"
	databasesql "database/sql"
	"errors"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// emailOTPStore is the SQL-backed [store.EmailOTPStore].
//
// Retention is the part worth reading carefully: a row stays readable
// until RetainUntil, which the library stamps to the far edge of the
// longest live window rather than to the code's own ExpiresAt. Dropping
// the row when the code expires would reset the resend cap and the
// brute-force counter, so an attacker pacing to the code TTL would
// never accumulate either. Get therefore honours RetainUntil, while
// Consume separately refuses an expired code.
type emailOTPStore struct {
	parent *Store
}

func newEmailOTPStore(s *Store) *emailOTPStore { return &emailOTPStore{parent: s} }

func (s *emailOTPStore) Get(ctx context.Context, subject string) (*store.EmailOTPRecord, error) {
	rec, err := s.scanOne(ctx, subject)
	if err != nil {
		return nil, err
	}
	if emailOTPRetentionElapsed(rec, s.parent.clock.Now()) {
		return nil, store.ErrNotFound
	}
	return rec, nil
}

func (s *emailOTPStore) Put(ctx context.Context, r *store.EmailOTPRecord) error {
	if r == nil {
		return errors.New("oidcsql: nil email otp record")
	}
	if r.Subject == "" {
		return errors.New("oidcsql: email otp record missing Subject")
	}
	args := append([]any{r.Subject}, emailOTPValues(r)...)
	if _, err := s.parent.db.ExecContext(ctx, s.parent.queries.emailOTPPut, args...); err != nil {
		return wrapErr("emailOTPs.Put", err)
	}
	return nil
}

func (s *emailOTPStore) CompareAndSwap(ctx context.Context, previous, next *store.EmailOTPRecord) error {
	if next == nil || next.Subject == "" {
		return errors.New("oidcsql: invalid email otp compare-and-swap record")
	}
	if previous == nil {
		return s.createIfAbsent(ctx, next)
	}
	if previous.Subject != next.Subject {
		return errors.New("oidcsql: invalid email otp compare-and-swap record")
	}
	args := emailOTPValues(next)
	args = append(args, previous.Subject)
	args = append(args, emailOTPValues(previous)...)
	res, err := s.parent.db.ExecContext(ctx, s.parent.queries.emailOTPCompareAndSwap, args...)
	if err != nil {
		return wrapErr("emailOTPs.CompareAndSwap", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return wrapErr("emailOTPs.CompareAndSwap.RowsAffected", err)
	}
	if n > 0 {
		return nil
	}
	return s.settleNoOp(ctx, next)
}

// createIfAbsent handles the nil-previous form of CompareAndSwap, which
// reserves the first challenge for a subject. A live record already
// present means another send won the race.
func (s *emailOTPStore) createIfAbsent(ctx context.Context, next *store.EmailOTPRecord) error {
	current, err := s.scanOne(ctx, next.Subject)
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		return err
	case !emailOTPRetentionElapsed(current, s.parent.clock.Now()):
		return store.ErrAlreadyConsumed
	}
	return s.Put(ctx, next)
}

func (s *emailOTPStore) Consume(ctx context.Context, r *store.EmailOTPRecord) error {
	if r == nil {
		return errors.New("oidcsql: nil email otp record")
	}
	if r.Subject == "" {
		return errors.New("oidcsql: email otp record missing Subject")
	}
	args := emailOTPValues(r)
	args = append(args,
		r.Subject,
		nonNilBytes(r.CodeSalt),
		nonNilBytes(r.CodeHash),
		timeToInt64(s.parent.clock.Now()))
	res, err := s.parent.db.ExecContext(ctx, s.parent.queries.emailOTPConsume, args...)
	if err != nil {
		return wrapErr("emailOTPs.Consume", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return wrapErr("emailOTPs.Consume.RowsAffected", err)
	}
	if n > 0 {
		return nil
	}
	return s.explainRejectedConsume(ctx, r)
}

// explainRejectedConsume separates the three ways a redemption can be
// refused. An absent or expired code reads as [store.ErrNotFound] —
// from the redemption path's point of view the code is gone — while an
// already-stamped record or one whose code material has moved on reads
// as [store.ErrAlreadyConsumed].
func (s *emailOTPStore) explainRejectedConsume(ctx context.Context, r *store.EmailOTPRecord) error {
	current, err := s.scanOne(ctx, r.Subject)
	if errors.Is(err, store.ErrNotFound) {
		return store.ErrNotFound
	}
	if err != nil {
		return err
	}
	now := s.parent.clock.Now()
	if !current.ExpiresAt.IsZero() && current.ExpiresAt.Before(now) {
		return store.ErrNotFound
	}
	return store.ErrAlreadyConsumed
}

func (s *emailOTPStore) Delete(ctx context.Context, subject string) error {
	res, err := s.parent.db.ExecContext(ctx, s.parent.queries.emailOTPDelete, subject)
	if err != nil {
		return wrapErr("emailOTPs.Delete", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return wrapErr("emailOTPs.Delete.RowsAffected", err)
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// settleNoOp mirrors [totpStore.settleNoOp]: MySQL reports zero
// affected rows for an UPDATE that matched but changed nothing, so a
// stored row already equal to next is a success rather than a lost
// race.
func (s *emailOTPStore) settleNoOp(ctx context.Context, next *store.EmailOTPRecord) error {
	current, err := s.scanOne(ctx, next.Subject)
	if errors.Is(err, store.ErrNotFound) {
		return store.ErrAlreadyConsumed
	}
	if err != nil {
		return err
	}
	if emailOTPEqual(current, next) {
		return nil
	}
	return store.ErrAlreadyConsumed
}

//nolint:funlen // one scan target per column; splitting it would only hide the mapping.
func (s *emailOTPStore) scanOne(ctx context.Context, subject string) (*store.EmailOTPRecord, error) {
	var (
		rec       store.EmailOTPRecord
		salt      []byte
		hash      []byte
		sent      int64
		expires   int64
		retain    int64
		firstFail int64
		locked    int64
		consumed  int64
		window    int64
		lastSend  int64
	)
	err := s.parent.db.QueryRowContext(ctx, s.parent.queries.emailOTPGet, subject).Scan(
		&rec.Subject, &salt, &hash, &rec.FailedCount, &rec.SendCount,
		&sent, &expires, &retain, &firstFail, &locked, &consumed, &window, &lastSend)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, wrapErr("emailOTPs.Get", err)
	}
	rec.CodeSalt = append([]byte(nil), salt...)
	rec.CodeHash = append([]byte(nil), hash...)
	rec.SentAt = int64ToTime(sent)
	rec.ExpiresAt = int64ToTime(expires)
	rec.RetainUntil = int64ToTime(retain)
	rec.FirstFailureAt = int64ToTime(firstFail)
	rec.LockedUntil = int64ToTime(locked)
	rec.ConsumedAt = int64ToTime(consumed)
	rec.SendWindowStart = int64ToTime(window)
	rec.LastSendAttemptAt = int64ToTime(lastSend)
	return &rec, nil
}

// emailOTPValues renders the record's value columns in the order
// declared by [emailOTPValueColumns].
func emailOTPValues(r *store.EmailOTPRecord) []any {
	return []any{
		nonNilBytes(r.CodeSalt),
		nonNilBytes(r.CodeHash),
		r.FailedCount,
		r.SendCount,
		timeToInt64(r.SentAt),
		timeToInt64(r.ExpiresAt),
		timeToInt64(r.RetainUntil),
		timeToInt64(r.FirstFailureAt),
		timeToInt64(r.LockedUntil),
		timeToInt64(r.ConsumedAt),
		timeToInt64(r.SendWindowStart),
		timeToInt64(r.LastSendAttemptAt),
	}
}

// emailOTPRetentionElapsed reports whether the record has fallen out of
// its retention window. RetainUntil governs; a zero value falls back to
// ExpiresAt so records written before the field existed keep their
// previous behaviour.
func emailOTPRetentionElapsed(rec *store.EmailOTPRecord, now time.Time) bool {
	horizon := rec.RetainUntil
	if horizon.IsZero() {
		horizon = rec.ExpiresAt
	}
	return !horizon.IsZero() && horizon.Before(now)
}

func emailOTPEqual(a, b *store.EmailOTPRecord) bool {
	return a.Subject == b.Subject &&
		bytes.Equal(a.CodeSalt, b.CodeSalt) &&
		bytes.Equal(a.CodeHash, b.CodeHash) &&
		a.FailedCount == b.FailedCount &&
		a.SendCount == b.SendCount &&
		a.SentAt.Equal(b.SentAt) &&
		a.ExpiresAt.Equal(b.ExpiresAt) &&
		a.RetainUntil.Equal(b.RetainUntil) &&
		a.FirstFailureAt.Equal(b.FirstFailureAt) &&
		a.LockedUntil.Equal(b.LockedUntil) &&
		a.ConsumedAt.Equal(b.ConsumedAt) &&
		a.SendWindowStart.Equal(b.SendWindowStart) &&
		a.LastSendAttemptAt.Equal(b.LastSendAttemptAt)
}

var _ store.EmailOTPStore = (*emailOTPStore)(nil)
