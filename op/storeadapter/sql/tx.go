package oidcsql

import (
	"context"
	databasesql "database/sql"
	"errors"
	"fmt"

	"github.com/libraz/go-oidc-provider/op/store"
)

// BeginTx implements [store.Transactional]. The returned [store.Tx]
// holds a single underlying [databasesql.Tx]; every substore handle
// the Tx returns is bound to that transaction so the call site does
// not need to wire it manually.
func (s *Store) BeginTx(ctx context.Context) (store.Tx, error) {
	dbtx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("oidcsql: begin transaction: %w", err)
	}
	tx := &sqlTx{
		store:              s,
		tx:                 dbtx,
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
// MUST NOT be used; further calls return [store.ErrTxRequired].
func (t *sqlTx) Commit() error {
	if t.done {
		return store.ErrTxRequired
	}
	t.done = true
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
	if err := t.tx.Rollback(); err != nil && !errors.Is(err, databasesql.ErrTxDone) {
		return fmt.Errorf("oidcsql: rollback transaction: %w", err)
	}
	return nil
}

// pickRunner returns the runner the substore should use. tx wins when
// the substore was constructed with a non-nil transaction; otherwise
// the parent Store's *sql.DB is returned. This helper is the sole
// gateway through which substores reach a runner so tx propagation is
// centralised.
func pickRunner(store *Store, tx *databasesql.Tx) runner {
	if tx != nil {
		return tx
	}
	return store.db
}
