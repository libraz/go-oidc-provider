package oidcsql

import (
	"context"
	databasesql "database/sql"
	"errors"
	"fmt"
	"math"
	"time"

	internalkeys "github.com/libraz/go-oidc-provider/internal/keys"
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
	version, err := internalkeys.RandomInt63Except(0)
	if err != nil {
		return fmt.Errorf("oidcsql: emailOTPs.Put: generate Version: %w", err)
	}
	args := append([]any{r.Subject, version}, emailOTPValues(r)...)
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
	if previous.Version == 0 || previous.Version >= math.MaxInt64 || next.Version != previous.Version {
		return store.ErrAlreadyConsumed
	}
	version, err := internalkeys.RandomInt63Except(int64(previous.Version))
	if err != nil {
		return fmt.Errorf("oidcsql: emailOTPs.CompareAndSwap: generate Version: %w", err)
	}
	args := emailOTPValues(next)
	args = append(args, version, previous.Subject)
	args = append(args, int64(previous.Version))
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
	return store.ErrAlreadyConsumed
}

// createIfAbsent handles the nil-previous form of CompareAndSwap, which
// reserves the first challenge for a subject. A live record already
// present means another send won the race.
//
// The reservation is what caps how many messages a subject can be sent,
// so it is written conditionally rather than as a read followed by a
// Put: two first sends arriving together would otherwise both find the
// key empty and both deliver a code, rolling the send-count ceiling
// back to one. The two statements cover the two ways the key can be
// free — nothing stored, or a row whose retention horizon has passed —
// and each is atomic against a concurrent writer on its own.
func (s *emailOTPStore) createIfAbsent(ctx context.Context, next *store.EmailOTPRecord) error {
	version, err := internalkeys.RandomInt63Except(0)
	if err != nil {
		return fmt.Errorf("oidcsql: emailOTPs.CompareAndSwap: generate Version: %w", err)
	}
	insertArgs := append([]any{next.Subject, version}, emailOTPValues(next)...)
	placed, err := s.execAffects(ctx, s.parent.queries.emailOTPInsertIfAbsent, "emailOTPs.CompareAndSwap.insert", insertArgs)
	if err != nil {
		return err
	}
	if placed {
		return nil
	}
	// A row holds the key. It yields only while past its retention
	// horizon, which is re-checked as part of the UPDATE rather than
	// beforehand.
	now := timeToInt64(s.parent.clock.Now())
	version, err = internalkeys.RandomInt63Except(0)
	if err != nil {
		return fmt.Errorf("oidcsql: emailOTPs.CompareAndSwap: generate stale-reclaim Version: %w", err)
	}
	values := emailOTPValues(next)
	staleArgs := make([]any, 0, 1+len(values)+3)
	staleArgs = append(staleArgs, version)
	staleArgs = append(staleArgs, values...)
	staleArgs = append(staleArgs, next.Subject, now, now)
	replaced, err := s.execAffects(ctx, s.parent.queries.emailOTPReplaceStale, "emailOTPs.CompareAndSwap.replaceStale", staleArgs)
	if err != nil {
		return err
	}
	if replaced {
		return nil
	}
	// A live row (or a racer that already reclaimed the stale row) means
	// this nil-previous reservation lost. Never settle by reading values:
	// an identical next value is still a second writer.
	return store.ErrAlreadyConsumed
}

// execAffects runs a conditional statement and reports whether it
// changed a row. The label names the operation in a wrapped backend
// error.
func (s *emailOTPStore) execAffects(ctx context.Context, query, label string, args []any) (bool, error) {
	res, err := s.parent.db.ExecContext(ctx, query, args...)
	if err != nil {
		return false, wrapErr(label, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, wrapErr(label+".RowsAffected", err)
	}
	return n > 0, nil
}

func (s *emailOTPStore) Consume(ctx context.Context, r *store.EmailOTPRecord) error {
	if r == nil {
		return errors.New("oidcsql: nil email otp record")
	}
	if r.Subject == "" {
		return errors.New("oidcsql: email otp record missing Subject")
	}
	if r.Version == 0 || r.Version >= math.MaxInt64 {
		return store.ErrAlreadyConsumed
	}
	version, err := internalkeys.RandomInt63Except(int64(r.Version))
	if err != nil {
		return fmt.Errorf("oidcsql: emailOTPs.Consume: generate Version: %w", err)
	}
	args := emailOTPValues(r)
	args = append(args,
		version,
		r.Subject,
		nonNilBytes(r.CodeSalt),
		nonNilBytes(r.CodeHash),
		int64(r.Version),
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

//nolint:funlen // one scan target per column; splitting it would only hide the mapping.
func (s *emailOTPStore) scanOne(ctx context.Context, subject string) (*store.EmailOTPRecord, error) {
	var (
		rec       store.EmailOTPRecord
		version   int64
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
		&rec.Subject, &version, &salt, &hash, &rec.FailedCount, &rec.SendCount,
		&sent, &expires, &retain, &firstFail, &locked, &consumed, &window, &lastSend,
	)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, wrapErr("emailOTPs.Get", err)
	}
	if version <= 0 {
		return nil, fmt.Errorf("oidcsql: emailOTPs.Get: invalid row_version %d", version)
	}
	rec.CodeSalt = append([]byte(nil), salt...)
	rec.CodeHash = append([]byte(nil), hash...)
	rec.Version = uint64(version)
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

var _ store.EmailOTPStore = (*emailOTPStore)(nil)
