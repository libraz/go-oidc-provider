// Package keys owns the OP signing material at runtime. It accepts the
// caller-supplied [SigningKey] entries from op.Keyset, validates the
// alg policy (ES256-only, permanently), and exposes:
//
//   - the active signer used to mint ID tokens, access JWTs, and DPoP
//     attestations
//   - the public JWKS published at /jwks for relying parties
//
// Package keys is the single internal package authorised to import
// crypto/rand and the go-jose v4 key-marshalling helpers; every other
// caller routes through this layer.
//
// # Entropy-failure policy
//
// The OP runs on multiple identifier-minting paths that read from
// [crypto/rand]: signing-key derivation here, session / chooser_group
// IDs in [internal/sessions], DPoP nonce rotation in
// [op.InMemoryDPoPNonceSource], CSRF / state token derivation, etc.
// Read failures are exceedingly rare on supported platforms, but
// [crypto/rand] does report errors and the codebase MUST handle each
// occurrence consistently. The single central rule is:
//
//   - Critical mints — values that authenticate a request or bind a
//     credential (token IDs, session IDs, chooser_group IDs, signing
//     material, CSRF tokens, opaque secrets) — fail closed by
//     propagating the [crypto/rand] error to the caller. The
//     in-flight transaction surfaces a typed failure (HTTP 500 /
//     internal_error / op.Error) so the operator sees the entropy
//     outage instead of admitting an attacker-influenced or
//     predictable value. [internal/sessions.newID] is the
//     reference implementation.
//
//   - Best-effort rotations — values whose previous reading remains
//     acceptable for a bounded window (DPoP nonce ticks, periodic
//     cache key rotations) — degrade gracefully. The previous value
//     stays live, a counter increments, and (when wired) a logger
//     emits a WARN line so an operator can correlate the outage
//     without the OP rejecting otherwise-valid requests.
//     [op.InMemoryDPoPNonceSource.run] is the reference implementation.
//
// The rule is asymmetric on purpose: a rotation-tick miss reduces
// the security margin for a few minutes, but rejecting in-flight
// proofs would convert the entropy outage into a full /token outage.
// A transactional mint miss has no equivalent fallback — admitting a
// session ID derived from a degenerate source is strictly worse than
// returning 500 — so the failure must propagate.
//
// New code that reads [crypto/rand] MUST classify itself against
// this rule before merging: if a single read failure can be papered
// over with a previous value, prefer the graceful path; otherwise,
// fail closed.
package keys
