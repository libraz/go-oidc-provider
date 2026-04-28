package oidcsql

import (
	"context"
	databasesql "database/sql"
	"errors"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

type sessionStore struct {
	parent *Store
	tx     *databasesql.Tx
}

func newSessionStore(s *Store, tx *databasesql.Tx) *sessionStore {
	return &sessionStore{parent: s, tx: tx}
}

func (s *sessionStore) runner() runner { return pickRunner(s.parent, s.tx) }

func (s *sessionStore) Save(ctx context.Context, sess *store.Session) error {
	_, err := s.runner().ExecContext(ctx, s.parent.queries.sessionSave,
		sess.ID, sess.Subject,
		timeToInt64(sess.AuthTime), encodeStrings(sess.AMR),
		sess.ACR, sess.ChooserGroupID,
		timeToInt64(sess.ExpiresAt), timeToInt64(sess.CreatedAt), timeToInt64(sess.UpdatedAt))
	if err != nil {
		return wrapErr("sessions.Save", err)
	}
	return nil
}

func (s *sessionStore) Find(ctx context.Context, id string) (*store.Session, error) {
	rec, err := s.scan(s.runner().QueryRowContext(ctx, s.parent.queries.sessionFind, id))
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, wrapErr("sessions.Find", err)
	}
	if isExpired(rec.ExpiresAt, s.parent.clock) {
		return nil, store.ErrNotFound
	}
	return rec, nil
}

func (s *sessionStore) Touch(ctx context.Context, id string, expiresAt, updatedAt time.Time) error {
	// Validate the row exists and is not expired before applying
	// the update so the contract returns ErrNotFound for an absent
	// or expired session even when the UPDATE itself would have
	// succeeded.
	cur, err := s.find(ctx, id)
	if err != nil {
		return err
	}
	if isExpired(cur.ExpiresAt, s.parent.clock) {
		return store.ErrNotFound
	}
	res, err := s.runner().ExecContext(ctx, s.parent.queries.sessionTouch,
		timeToInt64(expiresAt), timeToInt64(updatedAt), id)
	if err != nil {
		return wrapErr("sessions.Touch", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return wrapErr("sessions.Touch.RowsAffected", err)
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *sessionStore) Delete(ctx context.Context, id string) error {
	res, err := s.runner().ExecContext(ctx, s.parent.queries.sessionDelete, id)
	if err != nil {
		return wrapErr("sessions.Delete", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return wrapErr("sessions.Delete.RowsAffected", err)
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *sessionStore) ListByChooserGroup(ctx context.Context, groupID string) ([]*store.Session, error) {
	rows, err := s.runner().QueryContext(ctx, s.parent.queries.sessionListByChooserGroup, groupID)
	if err != nil {
		return nil, wrapErr("sessions.ListByChooserGroup", err)
	}
	defer rows.Close() //nolint:errcheck // best-effort close; the explicit error path inside the loop already handles failure.
	var out []*store.Session
	for rows.Next() {
		rec, err := s.scan(rowProxy{rows})
		if err != nil {
			return nil, wrapErr("sessions.ListByChooserGroup.scan", err)
		}
		if isExpired(rec.ExpiresAt, s.parent.clock) {
			continue
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapErr("sessions.ListByChooserGroup.iter", err)
	}
	return out, nil
}

// find is the no-expiry-filter helper used by Touch.
func (s *sessionStore) find(ctx context.Context, id string) (*store.Session, error) {
	rec, err := s.scan(s.runner().QueryRowContext(ctx, s.parent.queries.sessionFind, id))
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return rec, nil
}

func (s *sessionStore) scan(sc scanner) (*store.Session, error) {
	var (
		sess     store.Session
		amrRaw   []byte
		authTime int64
		expires  int64
		created  int64
		updated  int64
	)
	if err := sc.Scan(
		&sess.ID, &sess.Subject,
		&authTime, &amrRaw, &sess.ACR, &sess.ChooserGroupID,
		&expires, &created, &updated,
	); err != nil {
		return nil, err
	}
	amr, err := decodeStrings(amrRaw)
	if err != nil {
		return nil, err
	}
	sess.AMR = amr
	sess.AuthTime = int64ToTime(authTime)
	sess.ExpiresAt = int64ToTime(expires)
	sess.CreatedAt = int64ToTime(created)
	sess.UpdatedAt = int64ToTime(updated)
	return &sess, nil
}
