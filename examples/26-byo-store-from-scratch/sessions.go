//go:build example

// sessions.go — store.SessionStore against vault_browser_seats. Outside
// the atomic-routing cluster: session writes are not coordinated with
// token-endpoint commits. Save upserts; Find / ListByChooserGroup honour
// ExpiresAt regardless of any sweep.

package main

import (
	"context"
	databasesql "database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

type sessionStore struct {
	q   querier
	now func() time.Time
}

const (
	sessionUpsert = `
INSERT INTO vault_browser_seats
  (seat_id, principal, auth_epoch, amr_methods, acr_class, chooser_band,
   expires_epoch, issued_epoch, touched_epoch)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(seat_id) DO UPDATE SET
  principal     = excluded.principal,
  auth_epoch    = excluded.auth_epoch,
  amr_methods   = excluded.amr_methods,
  acr_class     = excluded.acr_class,
  chooser_band  = excluded.chooser_band,
  expires_epoch = excluded.expires_epoch,
  touched_epoch = excluded.touched_epoch`

	sessionSelect = `
SELECT seat_id, principal, auth_epoch, amr_methods, acr_class, chooser_band,
       expires_epoch, issued_epoch, touched_epoch
FROM vault_browser_seats WHERE seat_id = ?`

	sessionTouch  = `UPDATE vault_browser_seats SET expires_epoch = ?, touched_epoch = ? WHERE seat_id = ?`
	sessionDelete = `DELETE FROM vault_browser_seats WHERE seat_id = ?`

	sessionByBand = `
SELECT seat_id, principal, auth_epoch, amr_methods, acr_class, chooser_band,
       expires_epoch, issued_epoch, touched_epoch
FROM vault_browser_seats WHERE chooser_band = ?`
)

func (s *sessionStore) Save(ctx context.Context, sess *store.Session) error {
	_, err := s.q.ExecContext(ctx, sessionUpsert,
		sess.ID, sess.Subject, epochOf(sess.AuthTime), encodeStrings(sess.AMR),
		sess.ACR, sess.ChooserGroupID,
		epochOf(sess.ExpiresAt), epochOf(sess.CreatedAt), epochOf(sess.UpdatedAt))
	if err != nil {
		return fmt.Errorf("sessions.Save: %w", err)
	}
	return nil
}

func (s *sessionStore) Find(ctx context.Context, id string) (*store.Session, error) {
	rec, err := s.find(ctx, id)
	if err != nil {
		return nil, err
	}
	if expiredStrict(rec.ExpiresAt, s.now()) {
		return nil, store.ErrNotFound
	}
	return rec, nil
}

func (s *sessionStore) find(ctx context.Context, id string) (*store.Session, error) {
	rec, err := s.scan(s.q.QueryRowContext(ctx, sessionSelect, id))
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("sessions.find: %w", err)
	}
	return rec, nil
}

func (s *sessionStore) Touch(ctx context.Context, id string, expiresAt, updatedAt time.Time) error {
	cur, err := s.find(ctx, id)
	if err != nil {
		return err
	}
	if expiredStrict(cur.ExpiresAt, s.now()) {
		return store.ErrNotFound
	}
	res, err := s.q.ExecContext(ctx, sessionTouch, epochOf(expiresAt), epochOf(updatedAt), id)
	if err != nil {
		return fmt.Errorf("sessions.Touch: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("sessions.Touch.RowsAffected: %w", err)
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// Delete removes the seat and reports whether what it removed was live.
// The DELETE statement alone cannot tell a live row from an expired one
// still awaiting collection, so the read comes first: an expired session
// is absent on every path, and the row is reclaimed regardless.
func (s *sessionStore) Delete(ctx context.Context, id string) error {
	_, findErr := s.Find(ctx, id)
	absent := errors.Is(findErr, store.ErrNotFound)
	if findErr != nil && !absent {
		return findErr
	}
	res, err := s.q.ExecContext(ctx, sessionDelete, id)
	if err != nil {
		return fmt.Errorf("sessions.Delete: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("sessions.Delete.RowsAffected: %w", err)
	}
	if n == 0 || absent {
		return store.ErrNotFound
	}
	return nil
}

func (s *sessionStore) ListByChooserGroup(ctx context.Context, groupID string) ([]*store.Session, error) {
	rows, err := s.q.QueryContext(ctx, sessionByBand, groupID)
	if err != nil {
		return nil, fmt.Errorf("sessions.ListByChooserGroup: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*store.Session
	for rows.Next() {
		rec, err := s.scan(rows)
		if err != nil {
			return nil, fmt.Errorf("sessions.ListByChooserGroup.scan: %w", err)
		}
		if expiredStrict(rec.ExpiresAt, s.now()) {
			continue
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sessions.ListByChooserGroup.iter: %w", err)
	}
	return out, nil
}

func (s *sessionStore) scan(sc scanner) (*store.Session, error) {
	var (
		sess    store.Session
		amr     string
		authE   int64
		expires int64
		created int64
		touched int64
	)
	if err := sc.Scan(
		&sess.ID, &sess.Subject, &authE, &amr, &sess.ACR, &sess.ChooserGroupID,
		&expires, &created, &touched,
	); err != nil {
		return nil, err
	}
	sess.AMR = decodeStrings(amr)
	sess.AuthTime = timeOf(authE)
	sess.ExpiresAt = timeOf(expires)
	sess.CreatedAt = timeOf(created)
	sess.UpdatedAt = timeOf(touched)
	return &sess, nil
}
