// Package scenariokit collects helpers used only by the Spec Scenario
// Suite under test/scenarios/.
//
// It composes on top of the public op/testkit package, adding RP-side
// utilities (authorization-code round-trip simulator, JAR / DPoP /
// private_key_jwt crafters, mTLS peer fixtures) that op/testkit
// deliberately omits because they are wire-crafter helpers, not
// OP-boot helpers.
//
// The package is internal by design: if embedders ask for an RP
// simulator the v1.x re-evaluation may extract a public surface.
// Until then, the API may change without notice.
package scenariokit
