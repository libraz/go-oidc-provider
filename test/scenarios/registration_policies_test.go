package scenarios_test

// Catalog: test/scenarios/catalog/registration_policies.yaml (RP-NNN)
// Spec:
//   - RFC 7591 §5.2 — Software Statement / Registration Policies
//   - OpenID Connect Dynamic Client Registration §3
//   - OP design — features.registration.policies map

import "testing"

func TestScenario_RP_CFG_01_RequiresAdapterIAT(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RP-CFG-01")
}

func TestScenario_RP_CFG_02_FixedStringIATIncompatible(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RP-CFG-02")
}

func TestScenario_RP_CFG_03_PolicyFunctionMayBeAsync(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RP-CFG-03")
}

func TestScenario_RP_IAT_01_IATSavePersistsPolicies(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RP-IAT-01")
}

func TestScenario_RP_IAT_02_PoliciesRunInDeclaredOrder(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RP-IAT-02")
}

func TestScenario_RP_IAT_03_PolicyAppliesDefaultValue(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RP-IAT-03")
}

func TestScenario_RP_IAT_04_PolicyEnforcesValue(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RP-IAT-04")
}

func TestScenario_RP_IAT_05_InvalidClientMetadataThrown(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RP-IAT-05")
}

func TestScenario_RP_IAT_06_PolicyMayRewriteRATPolicies(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RP-IAT-06")
}

func TestScenario_RP_IAT_07_IATPoliciesPropagateToRAT(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RP-IAT-07")
}

func TestScenario_RP_RAT_01_PoliciesRunOnPUT(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RP-RAT-01")
}

func TestScenario_RP_RAT_02_RATSemanticsMirrorIAT(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RP-RAT-02")
}

func TestScenario_RP_RAT_03_RotatedRATInheritsPolicies(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RP-RAT-03")
}

func TestScenario_RP_RAT_04_PoliciesOnlyViaIAT(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RP-RAT-04")
}

func TestScenario_RP_VAL_01_NullPoliciesRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RP-VAL-01")
}

func TestScenario_RP_VAL_02_EmptyPoliciesRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RP-VAL-02")
}

func TestScenario_RP_VAL_03_NonStringElementRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RP-VAL-03")
}

func TestScenario_RP_VAL_04_UnknownPolicyNameRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RP-VAL-04")
}

func TestScenario_RP_VAL_05_ValidationRunsOnSaveAndFind(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RP-VAL-05")
}

func TestScenario_RP_ERR_01_InvalidClientMetadataMapped(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RP-ERR-01")
}

func TestScenario_RP_ERR_02_InvalidRedirectURIMapped(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RP-ERR-02")
}

func TestScenario_RP_ERR_03_UnexpectedExceptionToServerError(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RP-ERR-03")
}

func TestScenario_RP_ERR_04_PropertiesMutationNotShared(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RP-ERR-04")
}

func TestScenario_RP_LOG_01_AuditPayloadIncludesPolicyNames(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RP-LOG-01")
}

func TestScenario_RP_LOG_02_PolicyValuesNotLogged(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RP-LOG-02")
}
