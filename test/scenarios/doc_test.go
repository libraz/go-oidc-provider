// Package scenarios_test hosts the Spec Scenario Suite — the
// black-box test layer that binds 1:1 to the catalog of RFC-bound
// scenario rows under test/scenarios/catalog/<feature>.yaml.
//
// Each *_test.go file in this directory mirrors one catalog file, and
// each test function name carries the catalog's stable scenario ID:
//
//	TestScenario_<PREFIX>_<NNN>_<Slug>(t *testing.T)
//
// Examples:
//
//	TestScenario_DIS_001_DiscoveryServedWith200JSON
//	TestScenario_REF_016_ParallelRotationRace
//	TestScenario_DPOP_021_AthRequiredAtResource
//
// The tree imports only the public op surface (op, op/feature,
// op/grant, op/profile, op/store, op/storeadapter/inmem,
// op/interaction, op/testkit) and the scenario-only helpers under
// test/scenarios/internal/scenariokit. Importing internal/... packages
// is disallowed by design to keep the suite black-box.
//
// Run the full suite with the rest of the repo: `go test ./...`.
// Heavy scenarios skip under -short (`go test -short ./...`).
//
// The mechanical 1:1 binding between catalog row IDs and Go test
// function names is enforced by `scripts/scenario.sh validate` and
// `scripts/scenario.sh coverage` (the latter is wired into
// `make scenario-coverage`).
package scenarios_test
