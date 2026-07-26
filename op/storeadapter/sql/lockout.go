package oidcsql

import (
	"context"
	databasesql "database/sql"
	"errors"
	"math"

	"github.com/libraz/go-oidc-provider/op/store"
)

// authnLockoutStore is the SQL-backed [store.AuthnLockoutStore]. The
// counter is guarded by an explicit version column rather than by the
// full-tuple predicate the other factor substores use, because the
// record type carries a Version the library reads back.
type authnLockoutStore struct {
	parent *Store
}

func newAuthnLockoutStore(s *Store) *authnLockoutStore { return &authnLockoutStore{parent: s} }

func (s *authnLockoutStore) Get(ctx context.Context, subject string) (*store.AuthnLockoutRecord, error) {
	var (
		rec       store.AuthnLockoutRecord
		version   int64
		firstFail int64
		locked    int64
	)
	err := s.parent.db.QueryRowContext(ctx, s.parent.queries.lockoutGet, subject).Scan(
		&rec.Subject, &rec.FailedCount, &version, &firstFail, &locked)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, wrapErr("authnLockouts.Get", err)
	}
	rec.Version = uint64(version) //nolint:gosec // the column only ever holds values this adapter wrote, starting at 1 and incrementing.
	rec.FirstFailureAt = int64ToTime(firstFail)
	rec.LockedUntil = int64ToTime(locked)
	return &rec, nil
}

// CompareAndSwap implements [store.AuthnLockoutStore]. expectedVersion
// zero means "create": it succeeds only when no row exists yet, so two
// racing first failures cannot both install a fresh counter. A non-zero
// expectation updates in place and only when the stored version still
// matches, which is what stops a stale snapshot from erasing a lock
// another request just stamped.
func (s *authnLockoutStore) CompareAndSwap(
	ctx context.Context,
	expectedVersion uint64,
	next *store.AuthnLockoutRecord,
) (bool, error) {
	if next == nil {
		return false, errors.New("oidcsql: nil authn lockout record")
	}
	if next.Subject == "" {
		return false, errors.New("oidcsql: authn lockout record missing Subject")
	}
	if expectedVersion == math.MaxUint64 {
		return false, errors.New("oidcsql: authn lockout version overflow")
	}
	nextVersion := int64(expectedVersion + 1) //nolint:gosec // bounded by the MaxUint64 guard above.

	if expectedVersion == 0 {
		res, err := s.parent.db.ExecContext(ctx, s.parent.queries.lockoutInsert,
			next.Subject, next.FailedCount, nextVersion,
			timeToInt64(next.FirstFailureAt), timeToInt64(next.LockedUntil))
		if err != nil {
			if isDuplicate(err) {
				return false, nil
			}
			return false, wrapErr("authnLockouts.CompareAndSwap.insert", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return false, wrapErr("authnLockouts.CompareAndSwap.RowsAffected", err)
		}
		return n > 0, nil
	}

	res, err := s.parent.db.ExecContext(ctx, s.parent.queries.lockoutUpdate,
		next.FailedCount, nextVersion,
		timeToInt64(next.FirstFailureAt), timeToInt64(next.LockedUntil),
		next.Subject, int64(expectedVersion)) //nolint:gosec // versions originate from this adapter's own column.
	if err != nil {
		return false, wrapErr("authnLockouts.CompareAndSwap.update", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, wrapErr("authnLockouts.CompareAndSwap.RowsAffected", err)
	}
	return n > 0, nil
}
