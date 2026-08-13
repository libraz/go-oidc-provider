//go:build example

// tx.go — store.Transactional support. BeginTx opens one *sql.Tx and
// returns a store.Tx whose substore accessors are all bound to it. The OP
// runtime does not require this extension, but it is useful for embedders
// that perform their own maintenance or migration writes.
//
// store.Tx exposes AuthorizationCodes, Grants, RefreshTokens,
// PushedAuthRequests, AccessTokens, OpaqueAccessTokens, and
// GrantRevocations, plus Commit / Rollback. This minimal example does not
// implement opaque access tokens or grant-revocation tombstones, so those two
// transaction accessors return nil just like their parent-store accessors.
//
// Once Commit or Rollback has run, store.Tx requires every further call
// through the handle — reads included — to fail with an error satisfying
// errors.Is(err, store.ErrTxRequired). The substores need no check of
// their own for it: they reach the database only through the querier
// scratchTx hands them, and txQuerier translates the driver's
// closed-transaction error into that sentinel.

package main

import (
	"context"
	databasesql "database/sql"
	"errors"
	"fmt"

	"github.com/libraz/go-oidc-provider/op/store"
)

// BeginTx implements store.Transactional. Every substore the returned
// Tx hands out is bound to the single underlying *sql.Tx.
//
// Only one transaction runs at a time. A grant is amended rather than
// replaced — the OP reads the record, adds to it, and writes it back —
// and store.GrantStore.Save requires a backend to hold that basis under
// a lock or to refuse a write whose basis moved. SQLite has no row lock
// to hold: a transaction that read before it writes cannot take the
// write lock while another connection is still reading, and the engine
// refuses it rather than waiting. Several such cycles retrying together
// then refuse each other indefinitely. Admitting one at a time is the
// lock the engine does not offer, and it costs nothing here because
// SQLite already permits a single writer.
func (s *scratchStore) BeginTx(ctx context.Context) (store.Tx, error) {
	select {
	case s.txGate <- struct{}{}:
	case <-ctx.Done():
		return nil, fmt.Errorf("scratch: begin transaction: %w", ctx.Err())
	}
	dbtx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		<-s.txGate
		return nil, fmt.Errorf("scratch: begin transaction: %w", err)
	}
	return &scratchTx{parent: s, tx: dbtx}, nil
}

type scratchTx struct {
	parent *scratchStore
	tx     *databasesql.Tx
	done   bool
}

// release hands the transaction slot back. Commit and Rollback both
// call it, and the done flag they share makes sure only the first of
// them does — so the deferred-Rollback cleanup pattern stays safe.
func (t *scratchTx) release() { <-t.parent.txGate }

// q is the querier every tx-bound substore runs on. It is the only way
// those substores reach the database, so a substore added here later
// inherits the settled-transaction guard without restating it.
func (t *scratchTx) q() querier { return txQuerier{tx: t.tx} }

func (t *scratchTx) AuthorizationCodes() store.AuthorizationCodeStore {
	return &authCodeStore{q: t.q(), now: t.parent.now}
}

func (t *scratchTx) Grants() store.GrantStore {
	return &grantStore{q: t.q(), now: t.parent.now}
}

func (t *scratchTx) RefreshTokens() store.RefreshTokenStore {
	return &refreshStore{q: t.q(), now: t.parent.now}
}

func (t *scratchTx) PushedAuthRequests() store.PushedAuthRequestStore {
	return &parStore{q: t.q(), now: t.parent.now}
}

// AccessTokens returns the tx-bound registry.
func (t *scratchTx) AccessTokens() store.AccessTokenRegistry {
	return &accessTokenStore{q: t.q()}
}

// OpaqueAccessTokens returns nil because this minimal store does not support
// opaque access tokens. A complete adapter returns its tx-bound substore here.
func (t *scratchTx) OpaqueAccessTokens() store.OpaqueAccessTokenStore { return nil }

// GrantRevocations returns nil because this minimal store does not persist
// JWT grant tombstones. A complete adapter returns its tx-bound substore here.
func (t *scratchTx) GrantRevocations() store.GrantRevocationStore { return nil }

func (t *scratchTx) Commit() error {
	if t.done {
		return errTxClosed
	}
	t.done = true
	defer t.release()
	if err := t.tx.Commit(); err != nil {
		return fmt.Errorf("scratch: commit transaction: %w", err)
	}
	return nil
}

func (t *scratchTx) Rollback() error {
	if t.done {
		return nil
	}
	t.done = true
	defer t.release()
	if err := t.tx.Rollback(); err != nil && !errors.Is(err, databasesql.ErrTxDone) {
		return fmt.Errorf("scratch: rollback transaction: %w", err)
	}
	return nil
}

var _ store.Tx = (*scratchTx)(nil)

// errTxClosed is what a substore bound to a settled transaction reports.
// The sentinel is what callers match on: a bare driver error leaves an
// embedder unable to tell a leaked handle (a programming error) from a
// transport fault (worth retrying), and the retry loop then re-drives a
// request that can never succeed.
var errTxClosed = fmt.Errorf("scratch: transaction already closed: %w", store.ErrTxRequired)

// txQuerier adapts *sql.Tx to querier and translates the driver's
// settled-transaction failure into errTxClosed.
//
// database/sql already refuses every statement on a committed or
// rolled-back *sql.Tx, so nothing here reaches stale data; what it
// refuses with is sql.ErrTxDone, which satisfies no store sentinel.
// Translating at this seam covers reads as well as writes, because both
// come through the same querier.
type txQuerier struct{ tx *databasesql.Tx }

func (q txQuerier) ExecContext(ctx context.Context, query string, args ...any) (databasesql.Result, error) {
	res, err := q.tx.ExecContext(ctx, query, args...)
	return res, translateTxDone(err)
}

func (q txQuerier) QueryContext(ctx context.Context, query string, args ...any) (*databasesql.Rows, error) {
	rows, err := q.tx.QueryContext(ctx, query, args...)
	return rows, translateTxDone(err)
}

// QueryRowContext hands back a row that translates on Scan, because that
// is where *sql.Row reports the failure it is holding.
func (q txQuerier) QueryRowContext(ctx context.Context, query string, args ...any) scanner {
	return txRow{row: q.tx.QueryRowContext(ctx, query, args...)}
}

// txRow carries txQuerier's translation to the deferred error of a
// single-row query.
type txRow struct{ row *databasesql.Row }

func (r txRow) Scan(dest ...any) error { return translateTxDone(r.row.Scan(dest...)) }

// translateTxDone maps the driver's closed-transaction error onto the
// sentinel callers match on and leaves every other error untouched.
func translateTxDone(err error) error {
	if errors.Is(err, databasesql.ErrTxDone) {
		return errTxClosed
	}
	return err
}
