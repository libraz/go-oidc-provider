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
// interface small enough to satisfy without a code generator.
//
// # Capability placement
//
// Where a capability lives decides whether adding a feature to the OP breaks
// every existing backend, so the placement rule is normative:
//
//   - A capability belongs on a core substore interface if and only if every
//     OP the library can construct requires it. [RefreshTokenStore.RevokeByGrant]
//     qualifies: replay-detection cascades and grant-management revocation run
//     regardless of which grants or features are enabled.
//   - Every other capability belongs on an opt-in extension interface that
//     embeds its substore and is detected by runtime type assertion. Dynamic
//     client registration ([ClientRegistry]) and the back-channel logout
//     audience view ([GrantClientLister]) are extensions for this reason.
//
// An extension whose absence would break a configured flow MUST be verified at
// op.New, not discovered at request time. The condition that makes an extension
// mandatory is derived from the grant set, the feature set, and the options
// already present; no extension gets an option of its own, so there is one
// predicate per capability rather than two that can disagree.
//
// # Capability requirement matrix
//
// Extensions that op.New requires, and what turns the requirement on:
//
//	Extension                  Asserted on            Required when
//	-------------------------  ---------------------  --------------------------------
//	Transactional              Store                  a grant mounts /authorize
//	InteractionStoreCAS        Store.Interactions()   a grant mounts /authorize
//	GrantClientLister          Store.Grants()         a grant mounts /authorize
//	RefreshRetryResponseStore  Store.RefreshTokens()  grant.RefreshToken is enabled
//	                                                  and cookie keys are configured
//	ClientRegistry             Store                  op.WithDynamicRegistration
//
// Only grant.AuthorizationCode currently mounts /authorize. When one of these
// is missing, op.New returns a configuration error naming both the interface
// and the condition, so a backend author can act on the message alone.
//
// Extensions that stay optional, and what the OP does without them:
//
//	Extension                Asserted on            Fallback when absent
//	-----------------------  ---------------------  ------------------------------------
//	StaticClientReconciler   Store                  seeded static clients are not
//	                                                reconciled against the backend
//	RevokeByClient           Store.RefreshTokens()  deleting a dynamically registered
//	                                                client skips the bulk credential
//	                                                cascade for that substore
//	RefreshChainResolver     Store.RefreshTokens()  chain nodes resolve through Find
//	                                                instead of the stored-handle lookup
//
// A backend can verify its own placement decisions against
// [github.com/libraz/go-oidc-provider/op/store/contract], which exercises the
// core contract and skips each extension the backend does not implement.
//
// # Atomic operations and authorization transactions
//
// Safety-critical single-use behaviour is expressed on individual substore
// methods:
// authorization codes, refresh tokens, PAR records, device codes, and CIBA
// requests all expose compare-and-set style Consume methods, and revocation
// substores expose idempotent cascade operations. A backend must make each
// documented operation atomic within its own storage engine.
//
// In addition, when the browser authorization-code flow is enabled, the OP
// opens [Transactional] transactions. Grant read/modify/write, PAR
// consumption, and authorization-code persistence use one [Tx] so a failure
// cannot leave partial consent or consume a request_uri without a code.
//
// The composite adapter additionally requires a closed atomic-routing cluster
// ([AuthorizationCodeStore], [RefreshTokenStore], [GrantStore],
// [PushedAuthRequestStore], [AccessTokenRegistry], [OpaqueAccessTokenStore],
// and [GrantRevocationStore]) to resolve to one backend. That keeps replay
// detection, refresh rotation, token registration, and revocation cascades in
// one consistency domain even though the OP core calls the substores directly.
//
// A backend serving the browser authorization-code flow MUST implement
// [Transactional], and its [InteractionStore] MUST implement
// [InteractionStoreCAS]. op.New rejects the configuration otherwise. Grant
// reads returned by Tx must provide row-locking, serializable isolation, or an
// equivalent conflict mechanism for read/modify/write updates; merely grouping
// an unlocked SELECT and unconditional Save in one transaction can still lose
// concurrent consent updates.
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
