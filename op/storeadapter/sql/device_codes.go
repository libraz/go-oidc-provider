package oidcsql

import (
	"context"
	databasesql "database/sql"
	"errors"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/patterns"
)

// deviceCodeStore is the SQL implementation of
// [store.DeviceCodeStore]. The substore is intentionally outside the
// atomic-routing cluster (see the interface godoc): the approve→consume
// compare-and-swap embedded in Consume provides the single-use
// guarantee on its own, so the handle never carries a *sql.Tx.
type deviceCodeStore struct {
	parent *Store
}

func newDeviceCodeStore(s *Store) *deviceCodeStore {
	return &deviceCodeStore{parent: s}
}

func (s *deviceCodeStore) runner() runner { return pickRunner(s.parent, nil) }

// now returns the adapter clock as unix nanoseconds, bound into the
// expiry guard of every state-transition query.
func (s *deviceCodeStore) now() int64 { return timeToInt64(s.parent.clock.Now()) }

// Save honours the hash-on-store contract: the raw device_code is the
// bearer secret the device polls with, so the row is keyed on its
// SHA-256 digest and the raw value never reaches the database. A
// UNIQUE constraint on user_code surfaces a collision as
// [store.ErrAlreadyExists] so the library retries with a fresh code.
func (s *deviceCodeStore) Save(ctx context.Context, code *store.DeviceCode) error {
	if code == nil {
		return errors.New("oidcsql: nil device code")
	}
	status := code.Status
	if status == 0 {
		status = store.DeviceCodeStatusPending
	}
	if err := s.gcExpired(ctx); err != nil {
		return err
	}
	idDigest := patterns.Digest(code.ID)
	_, err := s.runner().ExecContext(ctx, s.parent.queries.deviceCodeSave,
		idDigest, code.ClientID, code.UserCode, code.Subject,
		encodeStrings(code.Scope), encodeStrings(code.Resource),
		code.DPoPJKT, code.MTLSCertS256, int64(code.Interval), int64(status),
		timeToInt64(code.AuthTime), code.DenyReason,
		int64(code.UserCodeStrikes), int64(code.PollViolations),
		timePtrToInt64Ptr(code.LastPolledAt), timeToInt64(code.ExpiresAt), timeToInt64(code.IssuedAt))
	if err != nil {
		if isDuplicate(err) {
			return store.ErrAlreadyExists
		}
		return wrapErr("deviceCodes.Save", err)
	}
	return nil
}

func (s *deviceCodeStore) gcExpired(ctx context.Context) error {
	if _, err := s.runner().ExecContext(ctx, s.parent.queries.deviceCodeGC, s.now()); err != nil {
		return wrapErr("deviceCodes.GC", err)
	}
	return nil
}

func (s *deviceCodeStore) FindByDeviceCode(ctx context.Context, deviceCode string) (*store.DeviceCode, error) {
	idDigest := patterns.Digest(deviceCode)
	rec, stored, err := s.scanOne(ctx, s.parent.queries.deviceCodeFind, idDigest)
	if err != nil {
		return nil, err
	}
	// Constant-time compare against the stored digest so a future
	// refactor that swaps the equality predicate for a slice scan
	// still fails closed in the presence of a timing oracle.
	if !patterns.ConstantTimeKeyMatch(stored, idDigest) {
		return nil, store.ErrNotFound
	}
	if isExpired(rec.ExpiresAt, s.parent.clock) {
		return nil, store.ErrNotFound
	}
	rec.ID = deviceCode
	return rec, nil
}

func (s *deviceCodeStore) FindByUserCode(ctx context.Context, userCode string) (*store.DeviceCode, error) {
	rec, _, err := s.scanOne(ctx, s.parent.queries.deviceCodeFindByUserCode, userCode)
	if err != nil {
		return nil, err
	}
	if isExpired(rec.ExpiresAt, s.parent.clock) {
		return nil, store.ErrNotFound
	}
	// The user_code path never returns the wire device_code: the
	// verification page only needs the metadata, and the stored id is
	// a one-way digest the raw value cannot be recovered from anyway.
	rec.ID = ""
	return rec, nil
}

func (s *deviceCodeStore) Approve(ctx context.Context, deviceCode, subject string, authTime time.Time) error {
	idDigest := patterns.Digest(deviceCode)
	res, err := s.runner().ExecContext(ctx, s.parent.queries.deviceCodeApprove,
		int64(store.DeviceCodeStatusApproved), subject, timeToInt64(authTime),
		idDigest, int64(store.DeviceCodeStatusPending), s.now())
	if err != nil {
		return wrapErr("deviceCodes.Approve", err)
	}
	return s.afterTransition(ctx, idDigest, res)
}

func (s *deviceCodeStore) ApproveByUserCode(ctx context.Context, userCode, subject string, authTime time.Time) error {
	res, err := s.runner().ExecContext(ctx, s.parent.queries.deviceCodeApproveByUser,
		int64(store.DeviceCodeStatusApproved), subject, timeToInt64(authTime),
		userCode, int64(store.DeviceCodeStatusPending), s.now())
	if err != nil {
		return wrapErr("deviceCodes.ApproveByUserCode", err)
	}
	return s.afterTransitionByUserCode(ctx, userCode, res)
}

func (s *deviceCodeStore) Deny(ctx context.Context, deviceCode, reason string) error {
	idDigest := patterns.Digest(deviceCode)
	res, err := s.runner().ExecContext(ctx, s.parent.queries.deviceCodeDeny,
		int64(store.DeviceCodeStatusDenied), reason,
		idDigest, int64(store.DeviceCodeStatusPending), s.now())
	if err != nil {
		return wrapErr("deviceCodes.Deny", err)
	}
	return s.afterTransition(ctx, idDigest, res)
}

func (s *deviceCodeStore) DenyByUserCode(ctx context.Context, userCode, reason string) error {
	res, err := s.runner().ExecContext(ctx, s.parent.queries.deviceCodeDenyByUser,
		int64(store.DeviceCodeStatusDenied), reason,
		userCode, int64(store.DeviceCodeStatusPending), s.now())
	if err != nil {
		return wrapErr("deviceCodes.DenyByUserCode", err)
	}
	return s.afterTransitionByUserCode(ctx, userCode, res)
}

func (s *deviceCodeStore) Revoke(ctx context.Context, deviceCode, reason string) error {
	idDigest := patterns.Digest(deviceCode)
	res, err := s.runner().ExecContext(ctx, s.parent.queries.deviceCodeRevoke,
		int64(store.DeviceCodeStatusDenied), reason, idDigest,
		int64(store.DeviceCodeStatusPending), int64(store.DeviceCodeStatusApproved), s.now())
	if err != nil {
		return wrapErr("deviceCodes.Revoke", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return wrapErr("deviceCodes.Revoke.RowsAffected", err)
	}
	if n > 0 {
		return nil
	}
	rec, _, findErr := s.scanOne(ctx, s.parent.queries.deviceCodeFind, idDigest)
	if findErr != nil {
		return findErr
	}
	if isExpired(rec.ExpiresAt, s.parent.clock) {
		return store.ErrNotFound
	}
	switch rec.Status {
	case store.DeviceCodeStatusDenied, store.DeviceCodeStatusConsumed:
		return nil
	default:
		return store.ErrConflict
	}
}

func (s *deviceCodeStore) RecordPoll(ctx context.Context, deviceCode string, when time.Time, nextInterval time.Duration) error {
	idDigest := patterns.Digest(deviceCode)
	res, err := s.runner().ExecContext(ctx, s.parent.queries.deviceCodeRecordPoll,
		timeToInt64(when), int64(nextInterval), int64(nextInterval), idDigest, s.now())
	if err != nil {
		return wrapErr("deviceCodes.RecordPoll", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return wrapErr("deviceCodes.RecordPoll.RowsAffected", err)
	}
	if n == 0 {
		// MySQL reports zero affected rows when a valid poll repeats the
		// exact same timestamp and interval. Distinguish that no-op update
		// from a missing / expired row before returning ErrNotFound.
		if _, findErr := s.FindByDeviceCode(ctx, deviceCode); findErr == nil {
			return nil
		} else if !errors.Is(findErr, store.ErrNotFound) {
			return findErr
		}
		// Missing or expired; the library treats both as expired_token.
		return store.ErrNotFound
	}
	return nil
}

func (s *deviceCodeStore) IncrementUserCodeStrike(ctx context.Context, deviceCode string) (uint8, error) {
	return s.increment(ctx, deviceCode,
		s.parent.queries.deviceCodeStrikeIncrement, s.parent.queries.deviceCodeStrikeRead)
}

func (s *deviceCodeStore) IncrementUserCodeStrikeByUserCode(ctx context.Context, userCode string) (uint8, error) {
	return s.incrementByUserCode(ctx, userCode,
		s.parent.queries.deviceCodeStrikeIncrUser, s.parent.queries.deviceCodeStrikeReadUser)
}

func (s *deviceCodeStore) IncrementPollViolation(ctx context.Context, deviceCode string) (uint8, error) {
	return s.increment(ctx, deviceCode,
		s.parent.queries.deviceCodeViolationIncr, s.parent.queries.deviceCodeViolationRead)
}

func (s *deviceCodeStore) Consume(ctx context.Context, deviceCode string) (*store.DeviceCode, error) {
	idDigest := patterns.Digest(deviceCode)
	rec, _, err := s.scanOne(ctx, s.parent.queries.deviceCodeFind, idDigest)
	if err != nil {
		return nil, err
	}
	if isExpired(rec.ExpiresAt, s.parent.clock) {
		return nil, store.ErrNotFound
	}
	switch rec.Status {
	case store.DeviceCodeStatusConsumed:
		return nil, store.ErrAlreadyConsumed
	case store.DeviceCodeStatusApproved:
		// fall through to the compare-and-swap below.
	default:
		return nil, store.ErrConflict
	}
	res, err := s.runner().ExecContext(ctx, s.parent.queries.deviceCodeConsume,
		int64(store.DeviceCodeStatusConsumed), idDigest, int64(store.DeviceCodeStatusApproved), s.now())
	if err != nil {
		return nil, wrapErr("deviceCodes.Consume", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, wrapErr("deviceCodes.Consume.RowsAffected", err)
	}
	if n == 0 {
		// Lost the compare-and-swap to a concurrent Consume.
		if replay, _, findErr := s.scanOne(ctx, s.parent.queries.deviceCodeFind, idDigest); findErr == nil &&
			replay.Status == store.DeviceCodeStatusConsumed {
			return nil, store.ErrAlreadyConsumed
		}
		return nil, store.ErrConflict
	}
	rec.Status = store.DeviceCodeStatusConsumed
	rec.ID = deviceCode
	return rec, nil
}

// afterTransition maps the RowsAffected of an Approve/Deny CAS onto the
// documented error set: a hit returns nil; a miss is ErrNotFound when
// the record is absent or expired and ErrConflict otherwise (the status
// was not Pending, or a concurrent transition won the race).
func (s *deviceCodeStore) afterTransition(ctx context.Context, idDigest string, res databasesql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return wrapErr("deviceCodes.transition.RowsAffected", err)
	}
	if n > 0 {
		return nil
	}
	rec, _, findErr := s.scanOne(ctx, s.parent.queries.deviceCodeFind, idDigest)
	if findErr != nil {
		return findErr
	}
	if isExpired(rec.ExpiresAt, s.parent.clock) {
		return store.ErrNotFound
	}
	return store.ErrConflict
}

func (s *deviceCodeStore) afterTransitionByUserCode(ctx context.Context, userCode string, res databasesql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return wrapErr("deviceCodes.transitionByUserCode.RowsAffected", err)
	}
	if n > 0 {
		return nil
	}
	rec, _, findErr := s.scanOne(ctx, s.parent.queries.deviceCodeFindByUserCode, userCode)
	if findErr != nil {
		return findErr
	}
	if isExpired(rec.ExpiresAt, s.parent.clock) {
		return store.ErrNotFound
	}
	return store.ErrConflict
}

// increment runs the +1 update (saturating at 255 via the query's
// WHERE guard) and reads the resulting value back. Missing or expired
// records surface as ErrNotFound; a saturated counter reports 255.
func (s *deviceCodeStore) increment(ctx context.Context, deviceCode, updateQ, readQ string) (uint8, error) {
	idDigest := patterns.Digest(deviceCode)
	now := s.now()
	if _, err := s.runner().ExecContext(ctx, updateQ, idDigest, now); err != nil {
		return 0, wrapErr("deviceCodes.increment", err)
	}
	var v int64
	err := s.runner().QueryRowContext(ctx, readQ, idDigest, now).Scan(&v)
	if errors.Is(err, databasesql.ErrNoRows) {
		return 0, store.ErrNotFound
	}
	if err != nil {
		return 0, wrapErr("deviceCodes.increment.read", err)
	}
	return uint8(v), nil //nolint:gosec // counter is capped at 255 by the update guard.
}

func (s *deviceCodeStore) incrementByUserCode(ctx context.Context, userCode, updateQ, readQ string) (uint8, error) {
	now := s.now()
	if _, err := s.runner().ExecContext(ctx, updateQ, userCode, now); err != nil {
		return 0, wrapErr("deviceCodes.incrementByUserCode", err)
	}
	var v int64
	err := s.runner().QueryRowContext(ctx, readQ, userCode, now).Scan(&v)
	if errors.Is(err, databasesql.ErrNoRows) {
		return 0, store.ErrNotFound
	}
	if err != nil {
		return 0, wrapErr("deviceCodes.incrementByUserCode.read", err)
	}
	return uint8(v), nil //nolint:gosec // counter is capped at 255 by the update guard.
}

// scanOne runs query with args and decodes a single device-code row.
// It returns the decoded record (with ID left as the stored digest for
// the caller to swap), the raw stored digest, and ErrNotFound when no
// row matches. Expiry is NOT applied here: the find queries omit the
// SQL expiry guard so every caller applies the same Go isExpired
// helper, keeping the strict-less-than boundary byte-equivalent with
// the inmem reference rather than depending on the dialect's own
// comparison.
func (s *deviceCodeStore) scanOne(ctx context.Context, query string, args ...any) (*store.DeviceCode, string, error) {
	var (
		c          store.DeviceCode
		stored     string
		scope      []byte
		resource   []byte
		interval   int64
		status     int64
		authTime   int64
		strikes    int64
		violations int64
		lastPolled *int64
		expires    int64
		issued     int64
	)
	err := s.runner().QueryRowContext(ctx, query, args...).Scan(
		&stored, &c.ClientID, &c.UserCode, &c.Subject, &scope, &resource,
		&c.DPoPJKT, &c.MTLSCertS256, &interval, &status, &authTime, &c.DenyReason,
		&strikes, &violations, &lastPolled, &expires, &issued,
	)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, "", store.ErrNotFound
	}
	if err != nil {
		return nil, "", wrapErr("deviceCodes.scan", err)
	}
	sc, err := decodeStrings(scope)
	if err != nil {
		return nil, "", err
	}
	res, err := decodeStrings(resource)
	if err != nil {
		return nil, "", err
	}
	c.ID = stored
	c.Scope = sc
	c.Resource = res
	c.Interval = time.Duration(interval)
	c.Status = store.DeviceCodeStatus(uint8(status)) //nolint:gosec // status is a small enum bound by the writer.
	c.AuthTime = int64ToTime(authTime)
	c.UserCodeStrikes = uint8(strikes)   //nolint:gosec // capped at 255 by the update guard.
	c.PollViolations = uint8(violations) //nolint:gosec // capped at 255 by the update guard.
	c.LastPolledAt = int64PtrToTimePtr(lastPolled)
	c.ExpiresAt = int64ToTime(expires)
	c.IssuedAt = int64ToTime(issued)
	return &c, stored, nil
}
