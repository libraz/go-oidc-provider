package scenarios_test

// Catalog: test/scenarios/catalog/registration_policies.yaml (RP-NNN)
// Spec:
//   - RFC 7591 §5.2 — Software Statement / Registration Policies
//   - OpenID Connect Dynamic Client Registration §3
//   - OP design — features.registration.policies map

import "testing"

// TestScenario_RP_CFG_01_RequiresAdapterIAT is OOS — see catalog out_of_scope_reason.
func TestScenario_RP_CFG_01_RequiresAdapterIAT(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RP-CFG-01 (see catalog out_of_scope_reason)")
}

// TestScenario_RP_CFG_02_FixedStringIATIncompatible is OOS — see catalog out_of_scope_reason.
func TestScenario_RP_CFG_02_FixedStringIATIncompatible(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RP-CFG-02 (see catalog out_of_scope_reason)")
}

// TestScenario_RP_CFG_03_PolicyFunctionMayBeAsync is OOS — see catalog out_of_scope_reason.
func TestScenario_RP_CFG_03_PolicyFunctionMayBeAsync(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RP-CFG-03 (see catalog out_of_scope_reason)")
}

// TestScenario_RP_IAT_01_IATSavePersistsPolicies is OOS — see catalog out_of_scope_reason.
func TestScenario_RP_IAT_01_IATSavePersistsPolicies(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RP-IAT-01 (see catalog out_of_scope_reason)")
}

// TestScenario_RP_IAT_02_PoliciesRunInDeclaredOrder is OOS — see catalog out_of_scope_reason.
func TestScenario_RP_IAT_02_PoliciesRunInDeclaredOrder(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RP-IAT-02 (see catalog out_of_scope_reason)")
}

// TestScenario_RP_IAT_03_PolicyAppliesDefaultValue is OOS — see catalog out_of_scope_reason.
func TestScenario_RP_IAT_03_PolicyAppliesDefaultValue(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RP-IAT-03 (see catalog out_of_scope_reason)")
}

// TestScenario_RP_IAT_04_PolicyEnforcesValue is OOS — see catalog out_of_scope_reason.
func TestScenario_RP_IAT_04_PolicyEnforcesValue(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RP-IAT-04 (see catalog out_of_scope_reason)")
}

// TestScenario_RP_IAT_05_InvalidClientMetadataThrown is OOS — see catalog out_of_scope_reason.
func TestScenario_RP_IAT_05_InvalidClientMetadataThrown(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RP-IAT-05 (see catalog out_of_scope_reason)")
}

// TestScenario_RP_IAT_06_PolicyMayRewriteRATPolicies is OOS — see catalog out_of_scope_reason.
func TestScenario_RP_IAT_06_PolicyMayRewriteRATPolicies(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RP-IAT-06 (see catalog out_of_scope_reason)")
}

// TestScenario_RP_IAT_07_IATPoliciesPropagateToRAT is OOS — see catalog out_of_scope_reason.
func TestScenario_RP_IAT_07_IATPoliciesPropagateToRAT(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RP-IAT-07 (see catalog out_of_scope_reason)")
}

// TestScenario_RP_RAT_01_PoliciesRunOnPUT is OOS — see catalog out_of_scope_reason.
func TestScenario_RP_RAT_01_PoliciesRunOnPUT(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RP-RAT-01 (see catalog out_of_scope_reason)")
}

// TestScenario_RP_RAT_02_RATSemanticsMirrorIAT is OOS — see catalog out_of_scope_reason.
func TestScenario_RP_RAT_02_RATSemanticsMirrorIAT(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RP-RAT-02 (see catalog out_of_scope_reason)")
}

// TestScenario_RP_RAT_03_RotatedRATInheritsPolicies is OOS — see catalog out_of_scope_reason.
func TestScenario_RP_RAT_03_RotatedRATInheritsPolicies(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RP-RAT-03 (see catalog out_of_scope_reason)")
}

// TestScenario_RP_RAT_04_PoliciesOnlyViaIAT is OOS — see catalog out_of_scope_reason.
func TestScenario_RP_RAT_04_PoliciesOnlyViaIAT(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RP-RAT-04 (see catalog out_of_scope_reason)")
}

// TestScenario_RP_VAL_01_NullPoliciesRejected is OOS — see catalog out_of_scope_reason.
func TestScenario_RP_VAL_01_NullPoliciesRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RP-VAL-01 (see catalog out_of_scope_reason)")
}

// TestScenario_RP_VAL_02_EmptyPoliciesRejected is OOS — see catalog out_of_scope_reason.
func TestScenario_RP_VAL_02_EmptyPoliciesRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RP-VAL-02 (see catalog out_of_scope_reason)")
}

// TestScenario_RP_VAL_03_NonStringElementRejected is OOS — see catalog out_of_scope_reason.
func TestScenario_RP_VAL_03_NonStringElementRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RP-VAL-03 (see catalog out_of_scope_reason)")
}

// TestScenario_RP_VAL_04_UnknownPolicyNameRejected is OOS — see catalog out_of_scope_reason.
func TestScenario_RP_VAL_04_UnknownPolicyNameRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RP-VAL-04 (see catalog out_of_scope_reason)")
}

// TestScenario_RP_VAL_05_ValidationRunsOnSaveAndFind is OOS — see catalog out_of_scope_reason.
func TestScenario_RP_VAL_05_ValidationRunsOnSaveAndFind(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RP-VAL-05 (see catalog out_of_scope_reason)")
}

// TestScenario_RP_ERR_01_InvalidClientMetadataMapped is OOS — see catalog out_of_scope_reason.
func TestScenario_RP_ERR_01_InvalidClientMetadataMapped(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RP-ERR-01 (see catalog out_of_scope_reason)")
}

// TestScenario_RP_ERR_02_InvalidRedirectURIMapped is OOS — see catalog out_of_scope_reason.
func TestScenario_RP_ERR_02_InvalidRedirectURIMapped(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RP-ERR-02 (see catalog out_of_scope_reason)")
}

// TestScenario_RP_ERR_03_UnexpectedExceptionToServerError is OOS — see catalog out_of_scope_reason.
func TestScenario_RP_ERR_03_UnexpectedExceptionToServerError(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RP-ERR-03 (see catalog out_of_scope_reason)")
}

// TestScenario_RP_ERR_04_PropertiesMutationNotShared is OOS — see catalog out_of_scope_reason.
func TestScenario_RP_ERR_04_PropertiesMutationNotShared(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RP-ERR-04 (see catalog out_of_scope_reason)")
}

// TestScenario_RP_LOG_01_AuditPayloadIncludesPolicyNames is OOS — see catalog out_of_scope_reason.
func TestScenario_RP_LOG_01_AuditPayloadIncludesPolicyNames(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RP-LOG-01 (see catalog out_of_scope_reason)")
}

// TestScenario_RP_LOG_02_PolicyValuesNotLogged is OOS — see catalog out_of_scope_reason.
func TestScenario_RP_LOG_02_PolicyValuesNotLogged(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RP-LOG-02 (see catalog out_of_scope_reason)")
}
