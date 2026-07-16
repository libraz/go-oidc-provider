package composite

import "github.com/libraz/go-oidc-provider/op/store"

// compositeTx is the [store.Tx] returned by [Store.BeginTx]. Because the
// composite adapter funnels every [TxClusterKinds] member through the same
// anchor, the wrapper has no routing work to do at the substore level: each
// accessor delegates to the anchor's own [store.Tx]. The wrapper exists so
// that future composite-level concerns (per-tx telemetry, panic recovery on
// Commit, etc.) have a stable seam without changing the anchor adapters.
type compositeTx struct {
	inner store.Tx
}

// AuthorizationCodes returns the transactional [store.AuthorizationCodeStore]
// bound to the anchor's underlying transaction.
func (t *compositeTx) AuthorizationCodes() store.AuthorizationCodeStore {
	return t.inner.AuthorizationCodes()
}

// RefreshTokens returns the transactional [store.RefreshTokenStore] bound to
// the anchor's underlying transaction.
func (t *compositeTx) RefreshTokens() store.RefreshTokenStore {
	return t.inner.RefreshTokens()
}

// Grants returns the transactional [store.GrantStore] bound to the anchor's
// underlying transaction.
func (t *compositeTx) Grants() store.GrantStore {
	return t.inner.Grants()
}

// PushedAuthRequests returns the transactional
// [store.PushedAuthRequestStore] bound to the anchor's underlying
// transaction.
func (t *compositeTx) PushedAuthRequests() store.PushedAuthRequestStore {
	return t.inner.PushedAuthRequests()
}

func (t *compositeTx) AccessTokens() store.AccessTokenRegistry { return t.inner.AccessTokens() }

func (t *compositeTx) OpaqueAccessTokens() store.OpaqueAccessTokenStore {
	return t.inner.OpaqueAccessTokens()
}

func (t *compositeTx) GrantRevocations() store.GrantRevocationStore {
	return t.inner.GrantRevocations()
}

// Commit finalises the underlying anchor transaction. The error is returned
// verbatim so callers can match adapter-specific sentinels (for example
// [store.ErrConflict] from a SQL backend's optimistic-locking probe).
func (t *compositeTx) Commit() error {
	return t.inner.Commit()
}

// Rollback discards every change made through the substore handles. As with
// [store.Tx.Rollback], it is safe to call after [compositeTx.Commit]; the
// anchor adapter is responsible for the no-op behaviour.
func (t *compositeTx) Rollback() error {
	return t.inner.Rollback()
}
