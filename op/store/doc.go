// Package store defines the storage contracts that an OpenID Connect Provider
// built with go-oidc-provider relies on. The library itself never opens a
// database connection or speaks any wire protocol; instead, every persistent
// effect crosses one of the small interfaces declared here, and a backend
// (in-memory, SQL, Redis, DynamoDB, or a bespoke implementation) is supplied
// by the embedding application.
//
// # Design principles
//
// Each substore interface owns a single record kind and exposes between one
// and five methods (typically Save / Find / Consume or Save / Find / Delete).
// This makes the obligations on a backend implementor explicit and keeps each
// interface small enough to satisfy without a code generator. Write-side
// capabilities that are not needed by every backend (for example, dynamic
// client registration) live on opt-in extension interfaces such as
// [ClientRegistry] rather than being bolted onto the core read-only contract.
//
// # Transactional vs single-operation clusters
//
// A subset of substores must be coordinated atomically because exchanging an
// authorization code, rotating a refresh token, or consuming a pushed
// authorization request crosses several record kinds and a partial commit
// would open a replay window. Backends that wish to serve those kinds
// implement the optional [Transactional] extension; the [Tx] type then
// vends substore handles that share a single underlying transaction.
//
// The transactional cluster is fixed and consists of [AuthorizationCodeStore],
// [RefreshTokenStore], [GrantStore], [SessionStore], and
// [PushedAuthRequestStore]. The remaining substores -- [ConsumedJTIStore]
// and [InteractionStore] -- are intentionally outside the cluster: they are
// idempotent or recoverable and operating them inside a transaction would
// pessimise hot paths without improving safety.
//
// # Godoc is normative
//
// The interfaces declared here are tiny on purpose; their semantics are
// carried by the godoc on each method. In particular, the sentinel errors in
// [errors.go] (for example [ErrNotFound], [ErrAlreadyExists],
// [ErrAlreadyConsumed], [ErrConflict], [ErrTxRequired]) form part of the
// contract: a backend that returns a different error for one of the listed
// failure modes does not satisfy the interface even if it compiles.
//
// # Hash-on-store contract for opaque bearer tokens
//
// Authorization codes ([AuthorizationCode.ID]), refresh tokens
// ([RefreshToken.ID]), and pushed-authorization-request URIs
// ([PushedAuthRequest.URI]) are opaque bearer secrets: possession of
// the value alone authorises the holder to redeem the artefact at the
// token endpoint. Backend implementations therefore MUST hash the
// presented token before persisting it (SHA-256 with a server-side
// pepper is the recommended construction) and MUST NOT store the raw
// value. Save records the hash; Find / Consume hash the presented
// token and look the digest up; comparison against the stored hash
// SHOULD be performed in constant time so a database leak compounded
// by a timing oracle still fails closed.
//
// The contract is enforced by every backend in this repository (the
// reference [github.com/libraz/go-oidc-provider/op/storeadapter/inmem]
// implementation hashes via SHA-256 without a pepper, intentionally
// trading the additional defence for transparency in tests). External
// backends — SQL, Redis, DynamoDB — are responsible for honouring the
// same invariant.
//
// # Stability
//
// The store package is part of the public API of go-oidc-provider and follows
// the same SemVer policy as the root [github.com/libraz/go-oidc-provider/op]
// package. Until v1.0 minor releases may evolve the surface; CHANGELOG.md
// records every break.
package store
