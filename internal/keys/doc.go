// Package keys owns the OP signing material at runtime. It accepts the
// caller-supplied [SigningKey] entries from op.Keyset, validates the
// alg policy (ES256-only in v1.0), and exposes:
//
//   - the active signer used to mint ID tokens, access JWTs, and DPoP
//     attestations
//   - the public JWKS published at /jwks for relying parties
//
// Package keys is the single internal package authorised to import
// crypto/rand and the go-jose v4 key-marshalling helpers; every other
// caller routes through this layer.
package keys
