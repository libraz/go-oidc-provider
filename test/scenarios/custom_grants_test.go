package scenarios_test

// Catalog: test/scenarios/catalog/custom_grants.yaml (CG-NNN)
// Spec:
//   - RFC 6749 §4.5 — Extension Grants
//   - RFC 6749 §3.2 — Token Endpoint
//   - RFC 6749 §5.2 — Error Response
//   - RFC 8693 — OAuth 2.0 Token Exchange (informative)

import "testing"

func TestScenario_CG_001_RegisterGrantTypeAddsToRegistry(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CG-001")
}

func TestScenario_CG_002_RegisterGrantTypeWithoutParamNames(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CG-002")
}

func TestScenario_CG_003_RegisterGrantTypeAcceptsNullOrString(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CG-003")
}

// TestScenario_CG_004_DuplicateParameterRejectedByDefault is OOS — see
// catalog out_of_scope_reason.
func TestScenario_CG_004_DuplicateParameterRejectedByDefault(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CG-004 (see catalog out_of_scope_reason)")
}

func TestScenario_CG_005_WhitelistedParameterMayRepeat(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CG-005")
}

func TestScenario_CG_006_PartialExemptionStillRejectsOthers(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CG-006")
}

// TestScenario_CG_007_GrantTypeCannotBeExempted is OOS — see catalog
// out_of_scope_reason.
func TestScenario_CG_007_GrantTypeCannotBeExempted(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CG-007 (see catalog out_of_scope_reason)")
}

func TestScenario_CG_008_ClientOptInExecutesHandler(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CG-008")
}

func TestScenario_CG_009_HandlerReceivesClientEntityOnly(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CG-009")
}
