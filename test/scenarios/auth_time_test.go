package scenarios_test

// Catalog: test/scenarios/catalog/auth_time.yaml (AT-NNN)
// Spec:
//   - OIDC Core 1.0 §2 (ID Token, `auth_time` claim)
//   - OIDC Core 1.0 §3.1.2.1 (`max_age`, `prompt`)
//   - OIDC Core 1.0 §5.5.1.1 (`auth_time` essential claim)
//   - OIDC Registration 1.0 §2 (`require_auth_time`, `default_max_age`)

import "testing"

func TestScenario_AT_001_RequestMaxAgeForcesAuthTime(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AT-001")
}

func TestScenario_AT_002_PromptLoginForcesAuthTime(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AT-002")
}

func TestScenario_AT_003_MaxAgeZeroForcesAuthTime(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AT-003")
}

func TestScenario_AT_004_ClientDefaultMaxAgeZeroForcesAuthTime(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AT-004")
}

func TestScenario_AT_005_ClientRequireAuthTimeForcesAuthTime(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AT-005")
}

func TestScenario_AT_006_ClientDefaultMaxAgePositiveForcesAuthTime(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AT-006")
}
