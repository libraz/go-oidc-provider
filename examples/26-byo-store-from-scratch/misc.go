//go:build example

// misc.go — the three small substores outside the transactional
// cluster: store.InteractionStore (vault_flow_scratch),
// store.ConsumedJTIStore (vault_seen_tickets), and store.MetadataStore
// (vault_op_notes).

package main

import (
	"context"
	databasesql "database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// --- interactions --------------------------------------------------------

type interactionStore struct {
	q   querier
	now func() time.Time
}

const (
	interactionUpsert = `
INSERT INTO vault_flow_scratch
  (scratch_id, relying_party, flow_step, driver_blob, expires_epoch, issued_epoch, touched_epoch)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(scratch_id) DO UPDATE SET
  relying_party = excluded.relying_party,
  flow_step     = excluded.flow_step,
  driver_blob   = excluded.driver_blob,
  expires_epoch = excluded.expires_epoch,
  touched_epoch = excluded.touched_epoch`

	interactionSelect = `
SELECT scratch_id, relying_party, flow_step, driver_blob, expires_epoch, issued_epoch, touched_epoch
FROM vault_flow_scratch WHERE scratch_id = ?`

	interactionDelete = `DELETE FROM vault_flow_scratch WHERE scratch_id = ?`
)

func (s *interactionStore) Save(ctx context.Context, i *store.Interaction) error {
	_, err := s.q.ExecContext(ctx, interactionUpsert,
		i.ID, i.ClientID, i.Step, i.RawState,
		epochOf(i.ExpiresAt), epochOf(i.CreatedAt), epochOf(i.UpdatedAt))
	if err != nil {
		return fmt.Errorf("interactions.Save: %w", err)
	}
	return nil
}

func (s *interactionStore) Find(ctx context.Context, id string) (*store.Interaction, error) {
	var (
		i       store.Interaction
		raw     []byte
		expires int64
		created int64
		touched int64
	)
	err := s.q.QueryRowContext(ctx, interactionSelect, id).Scan(
		&i.ID, &i.ClientID, &i.Step, &raw, &expires, &created, &touched)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("interactions.Find: %w", err)
	}
	i.RawState = append([]byte(nil), raw...)
	i.ExpiresAt = timeOf(expires)
	i.CreatedAt = timeOf(created)
	i.UpdatedAt = timeOf(touched)
	if expiredStrict(i.ExpiresAt, s.now()) {
		return nil, store.ErrNotFound
	}
	return &i, nil
}

func (s *interactionStore) Delete(ctx context.Context, id string) error {
	res, err := s.q.ExecContext(ctx, interactionDelete, id)
	if err != nil {
		return fmt.Errorf("interactions.Delete: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("interactions.Delete.RowsAffected: %w", err)
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// --- consumed JTIs -------------------------------------------------------

type jtiStore struct {
	q   querier
	now func() time.Time
}

const (
	jtiInsert = `
INSERT INTO vault_seen_tickets (ticket_digest, expires_epoch) VALUES (?, ?)
ON CONFLICT(ticket_digest) DO UPDATE SET expires_epoch = excluded.expires_epoch
WHERE vault_seen_tickets.expires_epoch <> 0 AND vault_seen_tickets.expires_epoch <= ?`
	jtiSelect = `SELECT expires_epoch FROM vault_seen_tickets WHERE ticket_digest = ?`
)

// Mark records jti as consumed. The raw jti is hashed before storage so
// driver logs / replicas only ever see the digest, and a duplicate Mark
// surfaces as ErrAlreadyConsumed.
func (s *jtiStore) Mark(ctx context.Context, jti string, expiresAt time.Time) error {
	res, err := s.q.ExecContext(ctx, jtiInsert, digest(jti), epochOf(expiresAt), s.now().Unix())
	if err != nil {
		return fmt.Errorf("jtis.Mark: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("jtis.Mark.RowsAffected: %w", err)
	}
	if n == 0 {
		return store.ErrAlreadyConsumed
	}
	return nil
}

func (s *jtiStore) Has(ctx context.Context, jti string) (bool, error) {
	var exp int64
	err := s.q.QueryRowContext(ctx, jtiSelect, digest(jti)).Scan(&exp)
	if errors.Is(err, databasesql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("jtis.Has: %w", err)
	}
	if exp != 0 && !s.now().Before(time.Unix(exp, 0)) {
		// Treat expired entries as absent; the contract permits this.
		return false, nil
	}
	return true, nil
}

// --- metadata ------------------------------------------------------------

type metadataStore struct{ q querier }

const (
	metadataGet = `SELECT note_value FROM vault_op_notes WHERE note_key = ?`
	metadataSet = `
INSERT INTO vault_op_notes (note_key, note_value) VALUES (?, ?)
ON CONFLICT(note_key) DO UPDATE SET note_value = excluded.note_value`
)

func (s *metadataStore) Get(ctx context.Context, key string) (string, error) {
	var value string
	err := s.q.QueryRowContext(ctx, metadataGet, key).Scan(&value)
	if errors.Is(err, databasesql.ErrNoRows) {
		return "", store.ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("metadata.Get: %w", err)
	}
	return value, nil
}

func (s *metadataStore) Set(ctx context.Context, key, value string) error {
	if _, err := s.q.ExecContext(ctx, metadataSet, key, value); err != nil {
		return fmt.Errorf("metadata.Set: %w", err)
	}
	return nil
}
