package scenarios_test

// Catalog: test/scenarios/catalog/pkce.yaml (PKCE-NNN)
// Spec:
//   - RFC 7636 — Proof Key for Code Exchange by OAuth Public Clients
//   - RFC 6749 §4.1 — Authorization Code Grant
//   - OIDC Core 1.0 §3.1
//   - OAuth 2.1 §4.1.1
//   - RFC 8252 — OAuth 2.0 for Native Apps

import "testing"

func TestScenario_PKCE_001_ChallengeMethodWithoutChallengeRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PKCE-001")
}

func TestScenario_PKCE_002_ChallengeBelowMinLengthRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PKCE-002")
}

func TestScenario_PKCE_003_ChallengeAboveMaxLengthRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PKCE-003")
}

func TestScenario_PKCE_004_ChallengeInvalidCharsetRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PKCE-004")
}

func TestScenario_PKCE_005_ChallengeMethodNotSupportedRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PKCE-005")
}

func TestScenario_PKCE_006_PlainMethodDisabledRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PKCE-006")
}

func TestScenario_PKCE_007_PublicClientCodeRequiresPKCE(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PKCE-007")
}

func TestScenario_PKCE_008_PublicClientHybridRequiresPKCE(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PKCE-008")
}

func TestScenario_PKCE_009_ImplicitOnlyDoesNotRequirePKCE(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PKCE-009")
}

func TestScenario_PKCE_010_AuthCodePersistsPKCEParams(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PKCE-010")
}

func TestScenario_PKCE_011_VerifierMatchesS256ChallengeSucceeds(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PKCE-011")
}

func TestScenario_PKCE_012_TokenGrantWithoutVerifierRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PKCE-012")
}

func TestScenario_PKCE_013_VerifierHashMismatchRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PKCE-013")
}

func TestScenario_PKCE_014_VerifierBelowMinLengthRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PKCE-014")
}

func TestScenario_PKCE_015_VerifierAboveMaxLengthRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PKCE-015")
}

func TestScenario_PKCE_016_VerifierInvalidCharsetRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PKCE-016")
}

func TestScenario_PKCE_017_RedirectErrorPreservesState(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PKCE-017")
}
