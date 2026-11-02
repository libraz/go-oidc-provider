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
	parent  *Store
	sweeper saveSweeper
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
	idDigest := patterns.Digest(code.ID)
	err := insertReclaimingExpired(ctx, &s.sweeper, s.gcExpired, func() error {
		_, err := s.runner().ExecContext(ctx, s.parent.queries.deviceCodeSave,
			idDigest, code.ClientID, code.UserCode, code.Subject,
			encodeStrings(code.Scope), encodeStrings(code.Resource),
			code.DPoPJKT, code.MTLSCertS256, int64(code.Interval), int64(status),
			timeToInt64(code.AuthTime), code.DenyReason,
			int64(code.UserCodeStrikes), int64(code.PollViolations),
			timePtrToInt64Ptr(code.LastPolledAt), timeToInt64(code.ExpiresAt), timeToInt64(code.IssuedAt))
		return err
	})
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
	rec, err := findByDigest(s.parent.clock, idDigest, func(r *store.DeviceCode) time.Time { return r.ExpiresAt },
		func() (*store.DeviceCode, string, error) {
			return s.scanOne(ctx, s.parent.queries.deviceCodeFind, idDigest)
		})
	if err != nil {
		return nil, err
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
	return s.afterTransition(ctx, s.parent.queries.deviceCodeFind, idDigest, res)
}

func (s *deviceCodeStore) ApproveByUserCode(ctx context.Context, userCode, subject string, authTime time.Time) error {
	res, err := s.runner().ExecContext(ctx, s.parent.queries.deviceCodeApproveByUser,
		int64(store.DeviceCodeStatusApproved), subject, timeToInt64(authTime),
		userCode, int64(store.DeviceCodeStatusPending), s.now())
	if err != nil {
		return wrapErr("deviceCodes.ApproveByUserCode", err)
	}
	return s.afterTransition(ctx, s.parent.queries.deviceCodeFindByUserCode, userCode, res)
}

func (s *deviceCodeStore) Deny(ctx context.Context, deviceCode, reason string) error {
	idDigest := patterns.Digest(deviceCode)
	res, err := s.runner().ExecContext(ctx, s.parent.queries.deviceCodeDeny,
		int64(store.DeviceCodeStatusDenied), reason,
		idDigest, int64(store.DeviceCodeStatusPending), s.now())
	if err != nil {
		return wrapErr("deviceCodes.Deny", err)
	}
	return s.afterTransition(ctx, s.parent.queries.deviceCodeFind, idDigest, res)
}

func (s *deviceCodeStore) DenyByUserCode(ctx context.Context, userCode, reason string) error {
	res, err := s.runner().ExecContext(ctx, s.parent.queries.deviceCodeDenyByUser,
		int64(store.DeviceCodeStatusDenied), reason,
		userCode, int64(store.DeviceCodeStatusPending), s.now())
	if err != nil {
		return wrapErr("deviceCodes.DenyByUserCode", err)
	}
	return s.afterTransition(ctx, s.parent.queries.deviceCodeFindByUserCode, userCode, res)
}

func (s *deviceCodeStore) Revoke(ctx context.Context, deviceCode, reason string) error {
	idDigest := patterns.Digest(deviceCode)
	n, err := execCount(ctx, s.runner(), "deviceCodes.Revoke", s.parent.queries.deviceCodeRevoke,
		int64(store.DeviceCodeStatusDenied), reason, idDigest,
		int64(store.DeviceCodeStatusPending), int64(store.DeviceCodeStatusApproved), s.now())
	if err != nil {
		return err
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
	return recordPollUpdate(ctx, s.runner(), s.parent.queries.deviceCodeRecordPoll, "deviceCodes.RecordPoll",
		patterns.Digest(deviceCode), when, nextInterval, s.now(),
		func() error {
			_, err := s.FindByDeviceCode(ctx, deviceCode)
			return err
		})
}

func (s *deviceCodeStore) IncrementUserCodeStrike(ctx context.Context, deviceCode string) (uint8, error) {
	return s.increment(ctx, patterns.Digest(deviceCode),
		s.parent.queries.deviceCodeStrikeIncrement, s.parent.queries.deviceCodeStrikeRead)
}

func (s *deviceCodeStore) IncrementUserCodeStrikeByUserCode(ctx context.Context, userCode string) (uint8, error) {
	return s.increment(ctx, userCode,
		s.parent.queries.deviceCodeStrikeIncrUser, s.parent.queries.deviceCodeStrikeReadUser)
}

func (s *deviceCodeStore) IncrementPollViolation(ctx context.Context, deviceCode string) (uint8, error) {
	return s.increment(ctx, patterns.Digest(deviceCode),
		s.parent.queries.deviceCodeViolationIncr, s.parent.queries.deviceCodeViolationRead)
}

func (s *deviceCodeStore) Consume(ctx context.Context, deviceCode string) (*store.DeviceCode, error) {
	idDigest := patterns.Digest(deviceCode)
	scan := func() (*store.DeviceCode, string, error) {
		return s.scanOne(ctx, s.parent.queries.deviceCodeFind, idDigest)
	}
	rec, err := consumeApproved(s.parent.clock,
		func(r *store.DeviceCode) time.Time { return r.ExpiresAt },
		func(r *store.DeviceCode) store.DeviceCodeStatus { return r.Status },
		store.DeviceCodeStatusApproved, store.DeviceCodeStatusConsumed, scan,
		func() error {
			return consumeUpdate(ctx, s.runner(), s.parent.queries.deviceCodeConsume, "deviceCodes.Consume", idDigest,
				int64(store.DeviceCodeStatusConsumed), int64(store.DeviceCodeStatusApproved), s.now(),
				func() bool {
					replay, _, findErr := scan()
					return findErr == nil && replay.Status == store.DeviceCodeStatusConsumed
				})
		})
	if err != nil {
		return nil, err
	}
	rec.Status = store.DeviceCodeStatusConsumed
	rec.ID = deviceCode
	return rec, nil
}

// afterTransition resolves the outcome of an Approve/Deny CAS (see
// [transitionMiss]); findQ and key select the record the miss is
// diagnosed against.
func (s *deviceCodeStore) afterTransition(ctx context.Context, findQ, key string, res databasesql.Result) error {
	return transitionMiss(res, "deviceCodes.transition", s.parent.clock, func() (time.Time, error) {
		rec, _, err := s.scanOne(ctx, findQ, key)
		if err != nil {
			return time.Time{}, err
		}
		return rec.ExpiresAt, nil
	})
}

// increment bumps a saturating counter on the record selected by key,
// which is either the device-code digest or the user_code depending on
// which update/read pair the caller supplies.
func (s *deviceCodeStore) increment(ctx context.Context, key, updateQ, readQ string) (uint8, error) {
	return bumpSaturatingCounter(ctx, s.runner(), updateQ, readQ, "deviceCodes.increment", key, s.now())
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
