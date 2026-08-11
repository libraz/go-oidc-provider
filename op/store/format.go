package store

import "fmt"

// AccessTokenFormat selects the wire encoding of issued access
// tokens. The type lives in this package so internal handlers
// can reference it without taking a dependency on the op public
// package; the public alias [op.AccessTokenFormat] re-exports it for
// embedders.
//
// The zero value is [AccessTokenFormatJWT] (RFC 9068 JWT-shaped tokens).
// Embedders flip the value through [op.WithAccessTokenFormat] /
// [op.WithAccessTokenFormatPerAudience]; the library uses the value at
// issuance time to dispatch between the JWT mint path and the opaque
// mint path, and at verification time to decide which substore to
// consult.
type AccessTokenFormat int

const (
	// AccessTokenFormatJWT issues RFC 9068 JWT-shaped access tokens.
	// This is the default for v1.0; chosen when the embedder calls
	// neither [op.WithAccessTokenFormat] nor
	// [op.WithAccessTokenFormatPerAudience].
	AccessTokenFormatJWT AccessTokenFormat = iota

	// AccessTokenFormatOpaque issues 32-byte random bearer tokens
	// backed by a hashed shadow row in the [OpaqueAccessTokenStore]
	// substore. Resource servers MUST consult /oidc/introspect to
	// resolve the token; the bytes carry no claims.
	AccessTokenFormatOpaque
)

// IsValid reports whether f is one of the documented constants. The
// option layer rejects unknown values at construction time so a caller
// passing AccessTokenFormat(99) gets a fail-fast error instead of a
// silent fall-through to the JWT default.
func (f AccessTokenFormat) IsValid() bool {
	switch f {
	case AccessTokenFormatJWT, AccessTokenFormatOpaque:
		return true
	}
	return false
}

// String returns the canonical lowercase identifier ("jwt" / "opaque")
// for the format. Unknown values stringify as
// "AccessTokenFormat(<int>)" so a regression in the option-layer
// validator surfaces in audit / log lines without crashing.
func (f AccessTokenFormat) String() string {
	switch f {
	case AccessTokenFormatJWT:
		return "jwt"
	case AccessTokenFormatOpaque:
		return "opaque"
	}
	return fmt.Sprintf("AccessTokenFormat(%d)", int(f))
}
