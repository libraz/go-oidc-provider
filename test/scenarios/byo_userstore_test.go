package scenarios_test

// Catalog: test/scenarios/catalog/byo_userstore.yaml (BUS-NNN)
// Spec:
//   - OIDC Core 1.0 §5.3 — UserInfo Endpoint
//   - OIDC Core 1.0 §5.4 — Requesting Claims using Scope Values
//   - OIDC Core 1.0 §2 — ID Token
//   - RFC 6750 §3 — Bearer Token error responses
//   - implementation contract — store.UserStore consumed by the OP

import "testing"

func TestScenario_BUS_001_UserInfoCallsStoreUsers(t *testing.T) {
	t.Parallel()
	t.Skip("pending: BUS-001")
}

func TestScenario_BUS_002_IDTokenAssemblyCallsStoreUsers(t *testing.T) {
	t.Parallel()
	t.Skip("pending: BUS-002")
}

func TestScenario_BUS_003_EmbeddingOverrideShadowsBaseUsers(t *testing.T) {
	t.Parallel()
	t.Skip("pending: BUS-003")
}

func TestScenario_BUS_004_UserInfoNotFoundReturnsInvalidToken(t *testing.T) {
	t.Parallel()
	t.Skip("pending: BUS-004")
}

func TestScenario_BUS_005_IDTokenAssemblyNotFoundReturnsInvalidGrant(t *testing.T) {
	t.Parallel()
	t.Skip("pending: BUS-005")
}

func TestScenario_BUS_006_UnauthorisedClaimsAreFiltered(t *testing.T) {
	t.Parallel()
	t.Skip("pending: BUS-006")
}

func TestScenario_BUS_007_UpdatedAtMappedFromUserStruct(t *testing.T) {
	t.Parallel()
	t.Skip("pending: BUS-007")
}

func TestScenario_BUS_008_LibraryTreatsClaimsMapReadOnly(t *testing.T) {
	t.Parallel()
	t.Skip("pending: BUS-008")
}

func TestScenario_BUS_009_TxInterfaceDoesNotExposeUsers(t *testing.T) {
	t.Parallel()
	t.Skip("pending: BUS-009")
}

func TestScenario_BUS_010_PrimaryPasswordStoreIndependentOfUsers(t *testing.T) {
	t.Parallel()
	t.Skip("pending: BUS-010")
}

func TestScenario_BUS_011_EmptyClaimsYieldsBareSubResponse(t *testing.T) {
	t.Parallel()
	t.Skip("pending: BUS-011")
}

func TestScenario_BUS_012_CompositeUsersRouteEquivalentToEmbedding(t *testing.T) {
	t.Parallel()
	t.Skip("pending: BUS-012")
}
