// Package jwks owns the /jwks HTTP endpoint. It serves the public JSON Web
// Key Set produced by [internal/keys.Set] with cache headers tuned for the
// OP rotation policy from docs/plans/002-product-design.md §F.6.
//
// The package is HTTP-only: every other concern (signature, key rotation,
// alg policy) lives in internal/keys.
package jwks
