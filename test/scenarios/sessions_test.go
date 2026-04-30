package scenarios_test

// Catalog: test/scenarios/catalog/sessions.yaml (SES-NNN)
// Spec:
//   - OIDC Core 1.0 §3.1.2, §15
//   - OIDC Session Management 1.0
//   - RFC 6749 §3.1
//   - RFC 7519 §4.1.4

import "testing"

func TestScenario_SES_001_ExpiredSessionForcesFreshLogin(t *testing.T) {
	t.Parallel()
	t.Skip("pending: SES-001")
}

func TestScenario_SES_002_ClockToleranceAcceptsWithinSkewSession(t *testing.T) {
	t.Parallel()
	t.Skip("pending: SES-002")
}

func TestScenario_SES_003_ClockToleranceRejectsBeyondSkewSession(t *testing.T) {
	t.Parallel()
	t.Skip("pending: SES-003")
}
