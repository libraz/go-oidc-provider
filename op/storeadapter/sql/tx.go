package oidcsql

import (
	"context"
	databasesql "database/sql"
	"errors"
	"fmt"
	"sync"

	"github.com/libraz/go-oidc-provider/op/store"
)

// BeginTx implements [store.Transactional]. The returned [store.Tx]
// holds a single underlying [databasesql.Tx]; every substore handle
// the Tx returns is bound to that transaction so the call site does
// not need to wire it manually.
func (s *Store) BeginTx(ctx context.Context) (store.Tx, error) {
	release, err := s.acquireTxGate(ctx)
	if err != nil {
		return nil, err
	}
	dbtx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		release()
		return nil, fmt.Errorf("oidcsql: begin transaction: %w", err)
	}
	tx := &sqlTx{
		store:              s,
		tx:                 dbtx,
		release:            release,
		authCodes:          newAuthCodeStore(s, dbtx),
		refreshes:          newRefreshStore(s, dbtx),
		grants:             newGrantStore(s, dbtx),
		pars:               newParStore(s, dbtx),
		accessTokens:       newAccessTokenStore(s, dbtx),
		opaqueAccessTokens: newOpaqueAccessTokenStore(s, dbtx),
		grantRevocations:   newGrantRevocationStore(s, dbtx),
	}
	return tx, nil
}

// acquireTxGate waits until this Store may open a transaction and
// returns the release the settled handle calls. On engines that take a
// real row lock the gate is absent and the release is a no-op.
//
// Waiting honours the caller's context so a request that was abandoned
// while queued fails as a cancellation rather than holding a slot the
// handler no longer wants.
func (s *Store) acquireTxGate(ctx context.Context) (func(), error) {
	if s.txGate == nil {
		return func() {}, nil
	}
	select {
	case s.txGate <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-s.txGate }) }, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("oidcsql: begin transaction: %w", ctx.Err())
	}
}

// sqlTx is the [store.Tx] handle returned by [Store.BeginTx]. It is
// not safe for concurrent use across goroutines; callers MUST drive
// the transaction from a single goroutine and call Commit or Rollback
// before the handle is dropped.
type sqlTx struct {
	store *Store
	tx    *databasesql.Tx

	authCodes          *authCodeStore
	refreshes          *refreshStore
	grants             *grantStore
	pars               *parStore
	accessTokens       *accessTokenStore
	opaqueAccessTokens *opaqueAccessTokenStore
	grantRevocations   *grantRevocationStore

	// release hands the transaction slot back to the Store. It is
	// idempotent, so the deferred-Rollback cleanup pattern cannot
	// release a slot a Commit already gave up.
	release func()

	done bool
}

// AuthorizationCodes returns the tx-bound [store.AuthorizationCodeStore].
func (t *sqlTx) AuthorizationCodes() store.AuthorizationCodeStore { return t.authCodes }

// Grants returns the tx-bound [store.GrantStore].
func (t *sqlTx) Grants() store.GrantStore { return t.grants }

// RefreshTokens returns the tx-bound [store.RefreshTokenStore].
func (t *sqlTx) RefreshTokens() store.RefreshTokenStore { return t.refreshes }

// PushedAuthRequests returns the tx-bound [store.PushedAuthRequestStore].
func (t *sqlTx) PushedAuthRequests() store.PushedAuthRequestStore { return t.pars }

// AccessTokens returns the tx-bound access-token registry. Although
// [store.Tx] does not expose this method directly, callers that hold a
// concrete *sqlTx may use it for manual cross-substore transactions.
//
// This method is exported on the concrete *sqlTx type for embedders
// who hold a typed handle and need to reach the registry inside a
// transaction.
func (t *sqlTx) AccessTokens() store.AccessTokenRegistry { return t.accessTokens }

// OpaqueAccessTokens returns the tx-bound opaque-AT substore. As with
// [sqlTx.AccessTokens], [store.Tx] does not expose this method
// directly; callers that hold a concrete *sqlTx may use it for manual
// cross-substore transactions.
func (t *sqlTx) OpaqueAccessTokens() store.OpaqueAccessTokenStore {
	return t.opaqueAccessTokens
}

// GrantRevocations returns the tx-bound grant-revocation substore. As
// with [sqlTx.AccessTokens] and [sqlTx.OpaqueAccessTokens],
// [store.Tx] does not expose this method directly; callers that hold
// a concrete *sqlTx may use it for manual cross-substore
// transactions.
func (t *sqlTx) GrantRevocations() store.GrantRevocationStore {
	return t.grantRevocations
}

// Commit finalises the transaction. After Commit returns the handle
// MUST NOT be used; further calls — reads, writes, and a second Commit
// alike — return [errTxClosed].
func (t *sqlTx) Commit() error {
	if t.done {
		return errTxClosed
	}
	t.done = true
	defer t.release()
	if err := t.tx.Commit(); err != nil {
		return fmt.Errorf("oidcsql: commit transaction: %w", err)
	}
	return nil
}

// Rollback discards every change. Rollback is safe to call after
// Commit; it is a no-op in that case so a deferred Rollback can be
// used as a cleanup pattern.
func (t *sqlTx) Rollback() error {
	if t.done {
		return nil
	}
	t.done = true
	defer t.release()
	if err := t.tx.Rollback(); err != nil && !errors.Is(err, databasesql.ErrTxDone) {
		return fmt.Errorf("oidcsql: rollback transaction: %w", err)
	}
	return nil
}

// pickRunner returns the runner the substore should use. tx wins when
// the substore was constructed with a non-nil transaction; otherwise
// the parent Store's *sql.DB is returned. This helper is the sole
// gateway through which substores reach a runner, so tx propagation —
// and with it the settled-transaction guard [txRunner] carries — is
// centralised here instead of being restated by each substore.
func pickRunner(store *Store, tx *databasesql.Tx) runner {
	if tx != nil {
		return txRunner{tx: tx}
	}
	return dbRunner{db: store.db}
}

// errTxClosed is what a substore bound to a settled transaction
// reports. [store.Tx] requires every call made through a committed or
// rolled-back handle to fail with an error satisfying errors.Is(err,
// [store.ErrTxRequired]): holding onto the handle is a programming
// error, and an embedder that cannot tell it from a transport fault
// retries it forever.
var errTxClosed = fmt.Errorf("oidcsql: transaction already closed: %w", store.ErrTxRequired)

// dbRunner adapts *sql.DB to [runner]. Outside a transaction there is
// nothing to guard; the wrapper exists so that a single-row query
// returns the same [scanner] on both paths.
type dbRunner struct{ db *databasesql.DB }

func (r dbRunner) ExecContext(ctx context.Context, query string, args ...any) (databasesql.Result, error) {
	return r.db.ExecContext(ctx, query, args...)
}

func (r dbRunner) QueryContext(ctx context.Context, query string, args ...any) (*databasesql.Rows, error) {
	return r.db.QueryContext(ctx, query, args...)
}

func (r dbRunner) QueryRowContext(ctx context.Context, query string, args ...any) scanner {
	return r.db.QueryRowContext(ctx, query, args...)
}

// txRunner adapts *sql.Tx to [runner] and translates the driver's
// settled-transaction failure into [errTxClosed].
//
// A substore handed out by a [store.Tx] keeps its *sql.Tx after the
// transaction settles. database/sql refuses every statement on it with
// [databasesql.ErrTxDone], which satisfies no store sentinel and so
// reaches an embedder as an ordinary storage fault. Translating at this
// seam rather than in each substore covers reads as well as writes, and
// covers substores added later: reaching the database at all means
// coming through [pickRunner].
type txRunner struct{ tx *databasesql.Tx }

func (r txRunner) ExecContext(ctx context.Context, query string, args ...any) (databasesql.Result, error) {
	res, err := r.tx.ExecContext(ctx, query, args...)
	return res, translateTxDone(err)
}

func (r txRunner) QueryContext(ctx context.Context, query string, args ...any) (*databasesql.Rows, error) {
	rows, err := r.tx.QueryContext(ctx, query, args...)
	return rows, translateTxDone(err)
}

// QueryRowContext hands back a row that translates on Scan, because
// that is where *sql.Row reports the failure it is holding.
func (r txRunner) QueryRowContext(ctx context.Context, query string, args ...any) scanner {
	return txRow{row: r.tx.QueryRowContext(ctx, query, args...)}
}

// txRow carries [txRunner]'s translation to the deferred error of a
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
