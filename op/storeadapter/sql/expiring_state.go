package oidcsql

import (
	"context"
	databasesql "database/sql"
	"errors"
	"sync/atomic"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/patterns"
)

// Helpers shared by the device-code and CIBA substores, whose rows are
// short-lived, keyed on a digest, and move through the same
// pending → approved/denied → consumed state machine.

// expiredSweepSaveInterval is how many Saves pass between full sweeps
// of expired rows. The sweep keeps the table bounded without a
// scheduler; a Save that collides with a dead row reclaims it at once
// (see [insertReclaimingExpired]), so the interval only paces
// housekeeping.
const expiredSweepSaveInterval = 64

// saveSweeper paces the housekeeping sweep of a substore across Saves.
type saveSweeper struct {
	saves atomic.Uint32
}

// due reports whether this Save should run a full sweep: the first Save
// after construction and every [expiredSweepSaveInterval]th after it.
func (w *saveSweeper) due() bool {
	return (w.saves.Add(1)-1)%expiredSweepSaveInterval == 0
}

// insertReclaimingExpired runs insert, sweeping expired rows first when
// the pacing says so. A duplicate-key failure may be an expired row still
// holding a unique slot (the digest key or user_code), so it sweeps and
// retries once; a duplicate that survives the sweep is genuine. The raw
// insert error is returned for the caller to map.
func insertReclaimingExpired(
	ctx context.Context,
	w *saveSweeper,
	sweep func(context.Context) error,
	insert func() error,
) error {
	if w.due() {
		if err := sweep(ctx); err != nil {
			return err
		}
	}
	err := insert()
	if !isDuplicate(err) {
		return err
	}
	if err := sweep(ctx); err != nil {
		return err
	}
	return insert()
}

// transitionMiss maps the RowsAffected of a state-transition CAS onto
// the documented error set: a hit returns nil; a miss is ErrNotFound
// when the record is absent or expired and ErrConflict otherwise (the
// status did not match, or a concurrent transition won the race).
// expiry reads the record's ExpiresAt for the miss case.
func transitionMiss(res databasesql.Result, op string, clock Clock, expiry func() (time.Time, error)) error {
	n, err := res.RowsAffected()
	if err != nil {
		return wrapErr(op+".RowsAffected", err)
	}
	if n > 0 {
		return nil
	}
	expiresAt, err := expiry()
	if err != nil {
		return err
	}
	if isExpired(expiresAt, clock) {
		return store.ErrNotFound
	}
	return store.ErrConflict
}

// findByDigest reads a record through scan and applies the checks every
// digest-keyed lookup shares: the stored digest must match idDigest and
// the record must not be expired. The caller swaps the stored digest for
// the wire id.
func findByDigest[T any](clock Clock, idDigest string, expiresAt func(*T) time.Time, scan func() (*T, string, error)) (*T, error) {
	rec, stored, err := scan()
	if err != nil {
		return nil, err
	}
	// Constant-time compare against the stored digest so a future
	// refactor that swaps the equality predicate for a slice scan
	// still fails closed in the presence of a timing oracle.
	if !patterns.ConstantTimeKeyMatch(stored, idDigest) {
		return nil, store.ErrNotFound
	}
	if isExpired(expiresAt(rec), clock) {
		return nil, store.ErrNotFound
	}
	return rec, nil
}

// consumeApproved reads a record through scan, requires it to be live
// and approved, and runs cas, the approved to consumed compare-and-swap.
// An already consumed record reports ErrAlreadyConsumed and any other
// status ErrConflict. The caller stamps the returned record.
func consumeApproved[T any, S comparable](
	clock Clock,
	expiresAt func(*T) time.Time,
	statusOf func(*T) S,
	approved, consumed S,
	scan func() (*T, string, error),
	cas func() error,
) (*T, error) {
	rec, _, err := scan()
	if err != nil {
		return nil, err
	}
	if isExpired(expiresAt(rec), clock) {
		return nil, store.ErrNotFound
	}
	switch statusOf(rec) {
	case consumed:
		return nil, store.ErrAlreadyConsumed
	case approved:
	default:
		return nil, store.ErrConflict
	}
	if err := cas(); err != nil {
		return nil, err
	}
	return rec, nil
}

// recordPollUpdate runs the RecordPoll UPDATE and resolves a zero-row
// result. MySQL reports zero affected rows when a valid poll repeats the
// exact same timestamp and interval, so find (the substore's own
// lookup) distinguishes that no-op from a missing or expired record,
// which the library treats alike as ErrNotFound.
func recordPollUpdate(
	ctx context.Context,
	r runner,
	query, op, key string,
	when time.Time,
	nextInterval time.Duration,
	now int64,
	find func() error,
) error {
	n, err := execCount(ctx, r, op, query, timeToInt64(when), int64(nextInterval), int64(nextInterval), key, now)
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	if findErr := find(); findErr != nil {
		if errors.Is(findErr, store.ErrNotFound) {
			return store.ErrNotFound
		}
		return findErr
	}
	return nil
}

// consumeUpdate runs the approved → consumed compare-and-swap. A lost
// race reports ErrAlreadyConsumed when replayConsumed finds the record
// consumed and ErrConflict otherwise.
func consumeUpdate(
	ctx context.Context,
	r runner,
	query, op, key string,
	consumed, approved int64,
	now int64,
	replayConsumed func() bool,
) error {
	n, err := execCount(ctx, r, op, query, consumed, key, approved, now)
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	if replayConsumed() {
		return store.ErrAlreadyConsumed
	}
	return store.ErrConflict
}

// bumpSaturatingCounter runs the +1 update (saturating at 255 via the
// query's WHERE guard) keyed on key and reads the resulting value back.
// A missing or expired record surfaces as ErrNotFound; a saturated
// counter reports 255.
func bumpSaturatingCounter(ctx context.Context, r runner, updateQ, readQ, op, key string, now int64) (uint8, error) {
	if _, err := r.ExecContext(ctx, updateQ, key, now); err != nil {
		return 0, wrapErr(op, err)
	}
	var v int64
	err := r.QueryRowContext(ctx, readQ, key, now).Scan(&v)
	if errors.Is(err, databasesql.ErrNoRows) {
		return 0, store.ErrNotFound
	}
	if err != nil {
		return 0, wrapErr(op+".read", err)
	}
	return uint8(v), nil //nolint:gosec // counter is capped at 255 by the update guard.
}
