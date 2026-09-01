package scenarios_test

// Catalog: test/scenarios/catalog/sessions.yaml (SES-NNN)
// Spec:
//   - OIDC Core 1.0 §3.1.2, §15
//   - OIDC Session Management 1.0
//   - RFC 6749 §3.1
//   - RFC 7519 §4.1.4

import "testing"

// TestScenario_SES_001_ExpiredSessionForcesFreshLogin is OOS — see
// catalog out_of_scope_reason.
func TestScenario_SES_001_ExpiredSessionForcesFreshLogin(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: SES-001 (see catalog out_of_scope_reason)")
}

// TestScenario_SES_002_ClockToleranceAcceptsWithinSkewSession is OOS — see catalog out_of_scope_reason.
func TestScenario_SES_002_ClockToleranceAcceptsWithinSkewSession(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: SES-002 (see catalog out_of_scope_reason)")
}

// TestScenario_SES_003_ClockToleranceRejectsBeyondSkewSession is OOS —
// see catalog out_of_scope_reason.
func TestScenario_SES_003_ClockToleranceRejectsBeyondSkewSession(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: SES-003 (see catalog out_of_scope_reason)")
}

// TestScenario_SES_004_AddAccountJoinsChooserGroup marks where the
// scenario-level test would go. Following the chooser's add-account link
// requires reading the link off the rendered prompt, which the black-box
// flow harness does not surface, so the row names its own coverage in
// `covered_by` and the gate resolves that name.
func TestScenario_SES_004_AddAccountJoinsChooserGroup(t *testing.T) {
	t.Parallel()
	t.Skip("covered outside the suite; see the sessions catalog row's covered_by")
}
