package op

import "github.com/libraz/go-oidc-provider/op/store"

// AccessTokenFormat selects the wire encoding of issued access
// tokens. It is a type alias of [store.AccessTokenFormat] so the
// public option layer and the internal handlers can converge on a
// single enum without internal/* taking a dependency on op/.
//
// The zero value is [AccessTokenFormatJWT]. Embedders flip the value
// through [WithAccessTokenFormat] (global) or
// [WithAccessTokenFormatPerAudience] (RFC 8707 per-resource). When
// neither option is invoked the OP issues RFC 9068 JWT-shaped tokens.
//
// Stable since v1.0.
type AccessTokenFormat = store.AccessTokenFormat

// AccessTokenFormatJWT issues RFC 9068 JWT-shaped access tokens. This
// is the default for v1.0; chosen when the embedder calls neither
// [WithAccessTokenFormat] nor [WithAccessTokenFormatPerAudience].
const AccessTokenFormatJWT = store.AccessTokenFormatJWT

// AccessTokenFormatOpaque issues 32-byte random bearer tokens backed by
// a hashed shadow row in the [store.OpaqueAccessTokenStore] substore.
// Resource servers MUST consult /oidc/introspect to resolve the token;
// the bytes carry no claims. The opaque path requires the configured
// [Store] to return a non-nil [store.OpaqueAccessTokenStore]; [New]
// rejects the configuration at construction time when the substore is
// absent.
const AccessTokenFormatOpaque = store.AccessTokenFormatOpaque
