package scenarios_test

// Catalog: test/scenarios/catalog/registration_management.yaml (RM-NNN)
// Spec:
//   - RFC 7592 — OAuth 2.0 Dynamic Client Registration Management Protocol
//   - RFC 7591 — Dynamic Client Registration (metadata)
//   - RFC 6750 — Bearer Token Usage
//   - OpenID Connect Core 1.0 §16

import "testing"

func TestScenario_RM_FF_01_RequiresDCREnabled(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RM-FF-01")
}

func TestScenario_RM_FF_02_RoutesHiddenWhenDisabled(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RM-FF-02")
}

func TestScenario_RM_PUT_01_RequiresBearerRAT(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RM-PUT-01")
}

func TestScenario_RM_PUT_02_InvalidRATIs401(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RM-PUT-02")
}

func TestScenario_RM_PUT_03_SuccessReturns200NoStore(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RM-PUT-03")
}

func TestScenario_RM_PUT_04_ResponseBodyShape(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RM-PUT-04")
}

func TestScenario_RM_PUT_05_BodyMustNotIncludeRAT(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RM-PUT-05")
}

func TestScenario_RM_PUT_06_BodyMustNotIncludeRegistrationClientURI(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RM-PUT-06")
}

func TestScenario_RM_PUT_07_BodyMustNotIncludeSecretExpiresAt(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RM-PUT-07")
}

func TestScenario_RM_PUT_08_BodyMustNotIncludeClientIDIssuedAt(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RM-PUT-08")
}

func TestScenario_RM_PUT_09_OmittedPropertyIsDeleted(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RM-PUT-09")
}

func TestScenario_RM_PUT_10_NullSecretRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RM-PUT-10")
}

func TestScenario_RM_PUT_11_AuthMethodSwitchMintsSecret(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RM-PUT-11")
}

func TestScenario_RM_PUT_12_RATRotationDestroysOld(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RM-PUT-12")
}

func TestScenario_RM_PUT_13_EntitiesCarryRotationPair(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RM-PUT-13")
}

func TestScenario_RM_PUT_14_UpdateAuditEmitted(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RM-PUT-14")
}

func TestScenario_RM_PUT_15_StaticClientForbidden(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RM-PUT-15")
}

func TestScenario_RM_PUT_16_ValidationFailsAsClientMetadata(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RM-PUT-16")
}

func TestScenario_RM_PUT_17_ClientIDMismatchRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RM-PUT-17")
}

func TestScenario_RM_DEL_01_RequiresRAT(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RM-DEL-01")
}

func TestScenario_RM_DEL_02_SuccessReturns204(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RM-DEL-02")
}

func TestScenario_RM_DEL_03_RATDestroyedOnSuccess(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RM-DEL-03")
}

func TestScenario_RM_DEL_04_AssociatedTokensInvalidated(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RM-DEL-04")
}

func TestScenario_RM_DEL_05_StaticClientForbidden(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RM-DEL-05")
}

func TestScenario_RM_DEL_06_DeleteAuditEmitted(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RM-DEL-06")
}

func TestScenario_RM_CTX_01_HandlersPopulateEntities(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RM-CTX-01")
}

func TestScenario_RM_EVT_01_RotationEmitsSavedAndDestroyed(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RM-EVT-01")
}

func TestScenario_RM_RAT_01_CrossClientRATAutoDestroyed(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RM-RAT-01")
}

func TestScenario_RM_RAT_02_RATPersistedWithUniqueJTI(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RM-RAT-02")
}

func TestScenario_RM_RAT_03_RATIsOpaqueToken(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RM-RAT-03")
}

func TestScenario_RM_RAT_04_RotationInheritsPolicies(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RM-RAT-04")
}
