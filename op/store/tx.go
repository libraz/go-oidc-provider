package store

import "context"

// Transactional is the opt-in extension a backend implements when it can
// expose explicit transaction handles for the atomic-routing cluster of
// substores. The OP runtime does not require this extension; it relies on the
// atomicity documented on each substore operation. Embedders and contract
// tests may still call [Transactional.BeginTx] directly when they need to
// coordinate manual writes across several substores.
//
// Backends that are not transactional simply do not implement this interface.
// The composite adapter still checks at construction time that every
// atomic-routing-cluster Kind is routed to one backend, but it does not require
// that backend to implement Transactional. Calling BeginTx through such a
// composite returns the adapter's ErrTxAnchorNotTx sentinel.
//
// Note that [SessionStore] is intentionally outside the cluster: the OP
// does not coordinate Session writes with token-endpoint transactions.
// Embedders MAY route Sessions to a volatile cache independently of
// the cluster anchor.
type Transactional interface {
	// BeginTx starts a new transaction and returns a [Tx] handle. The
	// transaction is aborted if the caller fails to call either
	// [Tx.Commit] or [Tx.Rollback]; backends SHOULD also abort on
	// context cancellation. BeginTx MUST NOT be nested: each handler
	// path opens at most one transaction.
	BeginTx(ctx context.Context) (Tx, error)
}

// Tx is the transaction handle returned by [Transactional.BeginTx]. The
// substore accessors return handles bound to the same underlying
// transaction; mutations performed through them become visible to other
// readers only after [Tx.Commit] succeeds.
//
// Note that [SessionStore], [InteractionStore], and [ConsumedJTIStore] are
// intentionally absent from Tx. Sessions because the OP tolerates session
// loss as a re-login event and does not pair Session writes with
// token-endpoint commits; interactions because losing them is
// recoverable; JTIs because the operation is idempotent and benefits from
// being a single round trip. Exposing them here would invite buggy
// callers to enrol them by reflex.
type Tx interface {
	// AuthorizationCodes returns an [AuthorizationCodeStore] bound to
	// this transaction.
	AuthorizationCodes() AuthorizationCodeStore

	// Grants returns a [GrantStore] bound to this transaction.
	Grants() GrantStore

	// RefreshTokens returns a [RefreshTokenStore] bound to this
	// transaction.
	RefreshTokens() RefreshTokenStore

	// PushedAuthRequests returns a [PushedAuthRequestStore] bound to
	// this transaction.
	PushedAuthRequests() PushedAuthRequestStore

	// Commit finalises every change made through the substore handles
	// returned by this Tx. After Commit returns successfully the Tx
	// MUST NOT be used; further calls return an implementation-defined
	// error (commonly [ErrTxRequired]).
	Commit() error

	// Rollback discards every change made through the substore handles
	// returned by this Tx. Rollback is safe to call after Commit; it
	// MUST be a no-op in that case so that a deferred Rollback can be
	// used as a cleanup pattern.
	Rollback() error
}
