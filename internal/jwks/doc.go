// Package jwks owns the /jwks HTTP endpoint. It serves the public JSON Web
// Key Set produced by internal/keys.Set with cache headers tuned for the
// OP's key-rotation policy: a long cacheable window normally, shortened
// while a rotation overlap is in flight so RPs re-fetch the new key
// promptly.
// The package is HTTP-only: every other concern (signature, key rotation,
// alg policy) lives in internal/keys.
package jwks
