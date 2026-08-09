package store

import "context"

// Transactional is the extension a backend implements to expose explicit
// transaction handles for the atomic-routing cluster of substores. The OP
// runtime requires this extension when the browser authorization-code flow is
// enabled so grant creation, PAR consumption, and authorization-code
// persistence commit as one durable operation.
//
// Backends used only for grant types that do not mount the browser authorize
// endpoint may omit this interface.
// Adapters whose concrete method set includes BeginTx MUST reject
// non-transactional backing stores at construction time; returning a value
// that satisfies Transactional but cannot begin a transaction is a capability
// contract violation. The composite adapter follows this rule.
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
// A transaction MUST read its own writes. Every lookup made through a
// substore handle of this Tx sees the mutations already performed through
// this Tx, down to individual fields: after
// [RefreshTokenStore.RevokeChain], a Find issued on the same Tx MUST
// report the affected records with [RefreshToken.Revoked] set, not merely
// with ConsumedAt stamped. Deferring part of the effect to Commit lets a
// handler that revokes and then re-reads inside one transaction act on
// state the store has already invalidated.
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

	AccessTokens() AccessTokenRegistry

	OpaqueAccessTokens() OpaqueAccessTokenStore

	GrantRevocations() GrantRevocationStore

	// Commit finalises every change made through the substore handles
	// returned by this Tx. After Commit returns successfully the Tx
	// MUST NOT be used; every further call through it — including a
	// second Commit — MUST fail with an error satisfying
	// errors.Is(err, [ErrTxRequired]). The message MAY name the
	// backend; the sentinel is what callers match on, so a bare
	// backend-specific error leaves an embedder unable to tell a closed
	// handle from a transport fault.
	Commit() error

	// Rollback discards every change made through the substore handles
	// returned by this Tx. Rollback is safe to call after Commit; it
	// MUST be a no-op in that case so that a deferred Rollback can be
	// used as a cleanup pattern.
	Rollback() error
}
