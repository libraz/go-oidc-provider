package oidcsql

import (
	"context"
	"errors"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// recoveryStore is the SQL-backed [store.RecoveryStore]. A batch is
// stored as one row per slot rather than as a single serialised blob:
// redeeming a code is then a conditional UPDATE against that one slot,
// so two concurrent redemptions of the same code cannot both succeed
// and a redemption of a different slot is not forced to lose the race.
type recoveryStore struct {
	parent *Store
}

func newRecoveryStore(s *Store) *recoveryStore { return &recoveryStore{parent: s} }

func (s *recoveryStore) Get(ctx context.Context, subject string) (*store.RecoveryBatch, error) {
	rows, err := s.parent.db.QueryContext(ctx, s.parent.queries.recoveryList, subject)
	if err != nil {
		return nil, wrapErr("recoveryCodes.Get", err)
	}
	defer func() { _ = rows.Close() }()

	batch := &store.RecoveryBatch{Subject: subject}
	for rows.Next() {
		var (
			slot      int
			hash      string
			consumed  int64
			generated int64
		)
		if err := rows.Scan(&slot, &hash, &consumed, &generated); err != nil {
			return nil, wrapErr("recoveryCodes.Get.Scan", err)
		}
		batch.GeneratedAt = int64ToTime(generated)
		batch.Codes = append(batch.Codes, store.RecoveryCode{
			Hash:       hash,
			ConsumedAt: int64ToTime(consumed),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, wrapErr("recoveryCodes.Get.Rows", err)
	}
	if len(batch.Codes) == 0 {
		return nil, store.ErrNotFound
	}
	return batch, nil
}

// Put replaces the batch wholesale. The delete and the re-insert run in
// one transaction so a regeneration can never leave a partially
// replaced slot list behind — a reader that observed one would be able
// to redeem a slot from a batch the user believes they revoked.
func (s *recoveryStore) Put(ctx context.Context, b *store.RecoveryBatch) error {
	if b == nil {
		return errors.New("oidcsql: nil recovery batch")
	}
	if b.Subject == "" {
		return errors.New("oidcsql: recovery batch missing Subject")
	}
	tx, err := s.parent.db.BeginTx(ctx, nil)
	if err != nil {
		return wrapErr("recoveryCodes.Put.BeginTx", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, s.parent.queries.recoveryDeleteAll, b.Subject); err != nil {
		return wrapErr("recoveryCodes.Put.clear", err)
	}
	generated := timeToInt64(b.GeneratedAt)
	for i, code := range b.Codes {
		if _, err := tx.ExecContext(ctx, s.parent.queries.recoveryInsert,
			b.Subject, i, code.Hash, timeToInt64(code.ConsumedAt), generated); err != nil {
			return wrapErr("recoveryCodes.Put.insert", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return wrapErr("recoveryCodes.Put.Commit", err)
	}
	return nil
}

func (s *recoveryStore) Consume(ctx context.Context, b *store.RecoveryBatch, index int) error {
	if b == nil {
		return errors.New("oidcsql: nil recovery batch")
	}
	if index < 0 || index >= len(b.Codes) {
		return store.ErrNotFound
	}
	slot := b.Codes[index]
	res, err := s.parent.db.ExecContext(ctx, s.parent.queries.recoveryConsume,
		timeToInt64(s.stampFor(slot)), b.Subject, index, slot.Hash)
	if err != nil {
		return wrapErr("recoveryCodes.Consume", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return wrapErr("recoveryCodes.Consume.RowsAffected", err)
	}
	if n > 0 {
		return nil
	}
	return s.explainRejectedConsume(ctx, b.Subject, index)
}

// stampFor resolves the timestamp a redemption writes onto the slot.
// A slot the caller already stamped keeps that value — it is the OP's
// own clock reading for the verification that just succeeded — while an
// unstamped one is stamped here from the adapter's clock.
//
// A zero value must never reach the UPDATE. The statement's predicate is
// "consumed_at = 0", so writing zero sets the column to the value it is
// required to already hold: the row matches, nothing changes, and the
// slot stays redeemable. Whether that surfaces as one affected row or
// none is then a per-engine choice — MySQL counts changed rows while
// SQLite and PostgreSQL count matched ones — so the same call reports
// success on one engine and refusal on another, and the success is the
// dangerous half: a single-use code the caller was told it had spent.
// Stamping makes the write a real transition on every engine, which
// collapses matched-rows and changed-rows onto the same answer and
// makes a nil return mean the slot is spent.
func (s *recoveryStore) stampFor(slot store.RecoveryCode) time.Time {
	if !slot.ConsumedAt.IsZero() {
		return slot.ConsumedAt
	}
	return s.parent.clock.Now()
}

// explainRejectedConsume distinguishes "no batch at all" from "the slot
// refused the redemption". The latter covers both an already-consumed
// slot and a hash that has moved on because the batch was regenerated;
// both are reported as [store.ErrAlreadyConsumed] because from the
// caller's point of view the code it is holding is spent.
func (s *recoveryStore) explainRejectedConsume(ctx context.Context, subject string, index int) error {
	current, err := s.Get(ctx, subject)
	if errors.Is(err, store.ErrNotFound) {
		return store.ErrNotFound
	}
	if err != nil {
		return err
	}
	if index >= len(current.Codes) {
		return store.ErrNotFound
	}
	return store.ErrAlreadyConsumed
}

func (s *recoveryStore) Delete(ctx context.Context, subject string) error {
	res, err := s.parent.db.ExecContext(ctx, s.parent.queries.recoveryDeleteAll, subject)
	if err != nil {
		return wrapErr("recoveryCodes.Delete", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return wrapErr("recoveryCodes.Delete.RowsAffected", err)
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

var _ store.RecoveryStore = (*recoveryStore)(nil)
