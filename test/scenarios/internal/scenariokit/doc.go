// Package scenariokit collects RP-side helpers used only by the
// Spec Scenario Suite under test/scenarios/.
//
// It composes on top of the public op/testkit package, adding the
// wire-crafter pieces op/testkit deliberately omits because they
// belong to the RP, not the OP:
//
//   - PKCE verifier / challenge derivation ([NewPKCEPair])
//   - /authorize → /interaction (subject) → /interaction (consent) →
//     callback round-trip ([RunCodeFlow])
//   - /token authorization_code exchange ([ExchangeCode])
//
// Future revisions add JAR / DPoP / private_key_jwt / mTLS crafters
// as additional scenario domains come online; these are intentionally
// missing from the v0 surface so the package can grow incrementally
// alongside the catalog rows that exercise them.
//
// The package is internal by design. If embedders ask for an RP
// simulator, the v1.x re-evaluation may extract a public surface;
// until then, the API may change without notice.
package scenariokit
