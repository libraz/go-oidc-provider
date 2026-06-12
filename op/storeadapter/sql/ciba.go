package oidcsql

import (
	"context"
	databasesql "database/sql"
	"errors"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/patterns"
)

// cibaRequestStore is the SQL implementation of
// [store.CIBARequestStore] (OpenID Connect CIBA Core 1.0). Like the
// device-code substore it sits outside the atomic-routing cluster: the
// approve→consume compare-and-swap embedded in Consume is the
// single-use guarantee, so the handle never carries a *sql.Tx.
type cibaRequestStore struct {
	parent *Store
}

func newCIBARequestStore(s *Store) *cibaRequestStore {
	return &cibaRequestStore{parent: s}
}

func (s *cibaRequestStore) runner() runner { return pickRunner(s.parent, nil) }

func (s *cibaRequestStore) now() int64 { return timeToInt64(s.parent.clock.Now()) }

// Save honours the hash-on-store contract: the raw auth_req_id is the
// bearer secret the client polls with, so the row is keyed on its
// SHA-256 digest and the raw value never reaches the database.
func (s *cibaRequestStore) Save(ctx context.Context, req *store.CIBARequest) error {
	if req == nil {
		return errors.New("oidcsql: nil CIBA request")
	}
	if req.Status == 0 {
		req.Status = store.CIBARequestStatusPending
	}
	idDigest := patterns.Digest(req.ID)
	_, err := s.runner().ExecContext(ctx, s.parent.queries.cibaSave,
		idDigest, req.ClientID, req.Subject,
		encodeStrings(req.Scope), encodeStrings(req.Resource), encodeStrings(req.ACRValues), req.ACR,
		req.BindingMessage, req.UserCode, req.DPoPJKT, req.MTLSCertS256,
		int64(req.Interval), int64(req.Status), timeToInt64(req.AuthTime), req.DenyReason,
		int64(req.PollViolations), timePtrToInt64Ptr(req.LastPolledAt),
		timeToInt64(req.ExpiresAt), timeToInt64(req.IssuedAt))
	if err != nil {
		if isDuplicate(err) {
			return store.ErrAlreadyExists
		}
		return wrapErr("ciba.Save", err)
	}
	return nil
}

func (s *cibaRequestStore) FindByAuthReqID(ctx context.Context, authReqID string) (*store.CIBARequest, error) {
	idDigest := patterns.Digest(authReqID)
	rec, stored, err := s.scanOne(ctx, s.parent.queries.cibaFind, idDigest)
	if err != nil {
		return nil, err
	}
	if !patterns.ConstantTimeKeyMatch(stored, idDigest) {
		return nil, store.ErrNotFound
	}
	if isExpired(rec.ExpiresAt, s.parent.clock) {
		return nil, store.ErrNotFound
	}
	rec.ID = authReqID
	return rec, nil
}

func (s *cibaRequestStore) Approve(ctx context.Context, authReqID, subject, acr string, authTime time.Time) error {
	idDigest := patterns.Digest(authReqID)
	res, err := s.runner().ExecContext(ctx, s.parent.queries.cibaApprove,
		int64(store.CIBARequestStatusApproved), subject, acr, timeToInt64(authTime),
		idDigest, int64(store.CIBARequestStatusPending), s.now())
	if err != nil {
		return wrapErr("ciba.Approve", err)
	}
	return s.afterTransition(ctx, idDigest, res)
}

func (s *cibaRequestStore) Deny(ctx context.Context, authReqID, reason string) error {
	idDigest := patterns.Digest(authReqID)
	res, err := s.runner().ExecContext(ctx, s.parent.queries.cibaDeny,
		int64(store.CIBARequestStatusDenied), reason,
		idDigest, int64(store.CIBARequestStatusPending), s.now())
	if err != nil {
		return wrapErr("ciba.Deny", err)
	}
	return s.afterTransition(ctx, idDigest, res)
}

func (s *cibaRequestStore) RecordPoll(ctx context.Context, authReqID string, when time.Time, nextInterval time.Duration) error {
	idDigest := patterns.Digest(authReqID)
	res, err := s.runner().ExecContext(ctx, s.parent.queries.cibaRecordPoll,
		timeToInt64(when), int64(nextInterval), int64(nextInterval), idDigest, s.now())
	if err != nil {
		return wrapErr("ciba.RecordPoll", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return wrapErr("ciba.RecordPoll.RowsAffected", err)
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *cibaRequestStore) IncrementPollViolation(ctx context.Context, authReqID string) (uint8, error) {
	idDigest := patterns.Digest(authReqID)
	now := s.now()
	if _, err := s.runner().ExecContext(ctx, s.parent.queries.cibaViolationIncr, idDigest, now); err != nil {
		return 0, wrapErr("ciba.IncrementPollViolation", err)
	}
	var v int64
	err := s.runner().QueryRowContext(ctx, s.parent.queries.cibaViolationRead, idDigest, now).Scan(&v)
	if errors.Is(err, databasesql.ErrNoRows) {
		return 0, store.ErrNotFound
	}
	if err != nil {
		return 0, wrapErr("ciba.IncrementPollViolation.read", err)
	}
	return uint8(v), nil //nolint:gosec // counter is capped at 255 by the update guard.
}

func (s *cibaRequestStore) Consume(ctx context.Context, authReqID string) (*store.CIBARequest, error) {
	idDigest := patterns.Digest(authReqID)
	rec, _, err := s.scanOne(ctx, s.parent.queries.cibaFind, idDigest)
	if err != nil {
		return nil, err
	}
	if isExpired(rec.ExpiresAt, s.parent.clock) {
		return nil, store.ErrNotFound
	}
	switch rec.Status {
	case store.CIBARequestStatusConsumed:
		return nil, store.ErrAlreadyConsumed
	case store.CIBARequestStatusApproved:
		// fall through to the compare-and-swap below.
	default:
		return nil, store.ErrConflict
	}
	res, err := s.runner().ExecContext(ctx, s.parent.queries.cibaConsume,
		int64(store.CIBARequestStatusConsumed), idDigest, int64(store.CIBARequestStatusApproved), s.now())
	if err != nil {
		return nil, wrapErr("ciba.Consume", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, wrapErr("ciba.Consume.RowsAffected", err)
	}
	if n == 0 {
		if replay, _, findErr := s.scanOne(ctx, s.parent.queries.cibaFind, idDigest); findErr == nil &&
			replay.Status == store.CIBARequestStatusConsumed {
			return nil, store.ErrAlreadyConsumed
		}
		return nil, store.ErrConflict
	}
	rec.Status = store.CIBARequestStatusConsumed
	rec.ID = authReqID
	return rec, nil
}

// afterTransition maps the RowsAffected of an Approve/Deny CAS onto the
// documented error set, identically to the device-code substore.
func (s *cibaRequestStore) afterTransition(ctx context.Context, idDigest string, res databasesql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return wrapErr("ciba.transition.RowsAffected", err)
	}
	if n > 0 {
		return nil
	}
	rec, _, findErr := s.scanOne(ctx, s.parent.queries.cibaFind, idDigest)
	if findErr != nil {
		return findErr
	}
	if isExpired(rec.ExpiresAt, s.parent.clock) {
		return store.ErrNotFound
	}
	return store.ErrConflict
}

// scanOne runs query with args and decodes a single CIBA row. Expiry
// is NOT applied here: the find queries omit the SQL expiry guard so
// every caller applies the same Go isExpired helper, keeping the
// strict-less-than boundary byte-equivalent with the inmem reference
// rather than depending on the dialect's own comparison.
func (s *cibaRequestStore) scanOne(ctx context.Context, query string, args ...any) (*store.CIBARequest, string, error) {
	var (
		c          store.CIBARequest
		stored     string
		scope      []byte
		resource   []byte
		acrValues  []byte
		interval   int64
		status     int64
		authTime   int64
		violations int64
		lastPolled *int64
		expires    int64
		issued     int64
	)
	err := s.runner().QueryRowContext(ctx, query, args...).Scan(
		&stored, &c.ClientID, &c.Subject, &scope, &resource, &acrValues, &c.ACR,
		&c.BindingMessage, &c.UserCode, &c.DPoPJKT, &c.MTLSCertS256,
		&interval, &status, &authTime, &c.DenyReason, &violations,
		&lastPolled, &expires, &issued)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, "", store.ErrNotFound
	}
	if err != nil {
		return nil, "", wrapErr("ciba.scan", err)
	}
	sc, err := decodeStrings(scope)
	if err != nil {
		return nil, "", err
	}
	rs, err := decodeStrings(resource)
	if err != nil {
		return nil, "", err
	}
	acr, err := decodeStrings(acrValues)
	if err != nil {
		return nil, "", err
	}
	c.ID = stored
	c.Scope = sc
	c.Resource = rs
	c.ACRValues = acr
	c.Interval = time.Duration(interval)
	c.Status = store.CIBARequestStatus(uint8(status)) //nolint:gosec // status is a small enum bound by the writer.
	c.AuthTime = int64ToTime(authTime)
	c.PollViolations = uint8(violations) //nolint:gosec // capped at 255 by the update guard.
	c.LastPolledAt = int64PtrToTimePtr(lastPolled)
	c.ExpiresAt = int64ToTime(expires)
	c.IssuedAt = int64ToTime(issued)
	return &c, stored, nil
}
