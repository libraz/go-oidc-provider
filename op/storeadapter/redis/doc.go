// Package oidcredis is the Redis storage adapter for go-oidc-provider. It
// is published as a sub-module so its single client dependency
// (github.com/redis/go-redis/v9) does not bleed into the host module's
// go.sum.
//
// # Scope
//
// The adapter implements only the volatile, non-transactional substores
// that benefit from a fast in-memory tier with native TTL semantics:
//
//   - [github.com/libraz/go-oidc-provider/op/store.ConsumedJTIStore] — DPoP
//     and private_key_jwt replay protection. Every protected request
//     performs a SETNX on the jti.
//   - [github.com/libraz/go-oidc-provider/op/store.InteractionStore] —
//     short-lived UI state surviving redirects across login / consent /
//     step-up screens.
//   - [github.com/libraz/go-oidc-provider/op/store.SessionStore] — browser
//     session state with Redis TTL. It is intentionally non-transactional:
//     compose it with a durable backend for grants and credentials.
//
// The transactional cluster substores (AuthorizationCodes, RefreshTokens,
// Grants, PushedAuthRequests, AccessTokens) and the long-lived
// substores (Clients, Users, IATs, RATs) are deliberately out of scope.
// The first-cut canonical deployment is therefore SQL durable + Redis
// volatile, composed through
// [github.com/libraz/go-oidc-provider/op/storeadapter/composite] —
// example 09-redis-volatile demonstrates the wiring end-to-end. Direct
// use of the [Store] without composite is not supported: every
// out-of-scope substore accessor returns nil. For feature-gated substores
// (AccessTokens, GrantRevocations, DeviceCodes, CIBARequests, IATs, RATs)
// op.New rejects that nil at construction time when the matching feature
// is enabled, so misconfiguration surfaces loudly rather than silently
// corrupting state; the composite layer routes those accessors to the
// durable backend before they ever reach the OP.
//
// # Security defaults
//
// The adapter refuses to start in obviously insecure configurations:
//
//   - TLS is required. The DSN scheme MUST be rediss://. Plaintext
//     redis:// is rejected at construction time. [WithDevModeAllowPlaintext]
//     is the documented escape hatch for local development; it logs a
//     loud warning and is named verbosely on purpose.
//   - Authentication is required. [WithRedisAuth] MUST be supplied
//     unless dev mode is enabled. The adapter does not support anonymous
//     access against production deployments.
//   - Value size is capped at 64 KiB. Save / Mark calls whose serialised
//     payload exceeds the cap fail rather than letting an attacker pin
//     unbounded RAM into the cache.
//   - Keys are namespaced under a fixed "oidc:" prefix. Multiple OPs
//     sharing a Redis instance MUST use the [WithKeyPrefix] override so
//     their keyspaces do not collide.
//
// # Test strategy
//
// Unit tests run in-process and exercise option validation and the
// keying scheme. The testcontainers-gated suite (run with
// `go test -tags=testcontainers ./...`) boots a real Redis 7 container
// with TLS + AUTH and exercises the substores end-to-end against the
// shared contract assertions in
// [github.com/libraz/go-oidc-provider/op/store/contract].
package oidcredis
