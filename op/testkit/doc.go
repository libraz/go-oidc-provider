// Package testkit provides drop-in test helpers for code that integrates the
// go-oidc-provider library. It boots a fully wired [op.Provider] over an
// in-memory store, generates a deterministic ECDSA P-256 signing key per
// test, and exposes utilities for fabricating [store.Client] fixtures and
// signing JWTs the way an external party (a confidential RP, an MTLS peer)
// would.
//
// # Scope
//
// testkit targets two consumers:
//
//   - The library's own integration tests — the package lives next to the
//     code it exercises so test boot-up does not duplicate the
//     option-wiring boilerplate every test file would otherwise need.
//   - Embedding applications — third-party callers get the same helpers
//     under a stable import path so their tests don't have to learn the
//     internal packages or replicate the keyset / store wiring.
//
// # What testkit is NOT
//
// testkit is not a mock: every helper produces a real [op.Provider] backed
// by the real in-memory storeadapter. Tests that mock the OP miss the
// invariants the library enforces; this package gives them no excuse.
//
// # Stability
//
// testkit follows the same pre-v1.0 stability posture as the rest of the
// public surface: minor versions may rearrange options before v1.0. Once
// v1.0 ships, breaking changes are reserved for the next major.
package testkit
