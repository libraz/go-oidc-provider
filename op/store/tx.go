package store

import "context"

// Transactional is the opt-in extension a backend implements when it can
// host the transactional cluster of substores. The library invokes
// [Transactional.BeginTx] whenever it needs to coordinate updates that span
// more than one substore -- principally authorization-code exchange,
// refresh-token rotation, and pushed-authorization-request consumption --
// and uses the returned [Tx] to obtain substore handles bound to that
// transaction.
//
// Backends that are not transactional simply do not implement this
// interface. The composite adapter checks at construction time that every
// transactional-cluster Kind ([AuthorizationCodes], [RefreshTokens],
// [Grants], [Sessions], [PushedAuthRequests]) is routed to a backend that
// implements Transactional, and rejects configurations that violate the
// invariant (see [op/storeadapter/composite] for the construction-time
// check). This makes the "single backend per transactional cluster" rule
// structural rather than a runtime warning.
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
// Note that [InteractionStore] and [ConsumedJTIStore] are intentionally
// absent from Tx. Both are designed to operate outside any transaction --
// interactions because losing them is recoverable, JTIs because the
// operation is idempotent and benefits from being a single round trip --
// and exposing them here would invite buggy callers to enrol them by
// reflex.
type Tx interface {
	// AuthorizationCodes returns an [AuthorizationCodeStore] bound to
	// this transaction.
	AuthorizationCodes() AuthorizationCodeStore

	// Grants returns a [GrantStore] bound to this transaction.
	Grants() GrantStore

	// RefreshTokens returns a [RefreshTokenStore] bound to this
	// transaction.
	RefreshTokens() RefreshTokenStore

	// Sessions returns a [SessionStore] bound to this transaction.
	Sessions() SessionStore

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
