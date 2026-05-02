// Package customgrant dispatches embedder-supplied grant_type
// implementations registered through op.WithCustomGrant. The
// dispatcher owns the policy gates that the public op.CustomGrantHandler
// surface must not be allowed to bypass: parameter parsing under
// op.ParamPolicy, duplicate-value caps, panic recovery, TTL
// truncation, and scope / audience subset enforcement.
//
// # Why an internal package
//
// The op package cannot host the dispatcher because the dispatcher
// needs to invoke handlers from inside the token endpoint, and
// internal/* packages are forbidden from importing op (it would
// create an import cycle and widen the embedder-visible surface).
// The package therefore defines its own narrow [Handler] interface
// that mirrors op.CustomGrantHandler structurally; the op layer
// supplies an adapter wrapping each registered embedder handler.
//
// # Security boundary
//
// Every gate the package documents is a *pre-issuance* gate the OP
// applies before any state is mutated. A handler that returns a
// 1-day access-token TTL when the global cap is 1 hour sees the TTL
// truncated and an audit warning emitted; a handler that returns a
// scope outside the client's registered set sees the request rejected
// with invalid_scope. The OP never mints tokens "the handler asked
// for" — it mints tokens the response shape *and* policy both admit.
package customgrant
