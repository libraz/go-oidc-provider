package authn

import (
	"net/netip"
	"testing"
	"time"
)

// TestLoginFlowContextProjectionRoundtripsState pins every populated
// State field that the projector is expected to surface on
// LoginFlowContext. The projector is the single seam between the
// orchestrator's persisted State and the predicate / Decider input
// rule logic sees on every evaluation pass; a forgotten field here is
// indistinguishable from the rule's predicate observing the empty
// default, which is how the original ACRValues drop slipped past the
// existing integration tests (none of them inspected ACRValues).
//
// The test lives in the package (not authn_test) because
// loginFlowContext is unexported; it MUST stay co-located with the
// projector so a future refactor that drops a field surfaces a failing
// assertion right next to the change.
func TestLoginFlowContextProjectionRoundtripsState(t *testing.T) {
	t.Parallel()

	st := State{
		Subject:            "user-7",
		ClientID:           "client-7",
		RequestedScopes:    []string{"openid", "profile"},
		LastFailures:       2,
		RiskScoreCached:    RiskScoreHigh,
		CompletedStepKinds: []string{"myorg.password"},
		ACRValues:          []string{"urn:test:silver", "urn:test:gold"},
		RemoteIP:           netip.MustParseAddr("203.0.113.10"),
		UserAgent:          "go-test/1.0",
		AuthTime:           time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC),
	}
	o := &Orchestrator{}

	lc := o.loginFlowContext(st)

	if lc.Subject != st.Subject {
		t.Errorf("Subject = %q, want %q", lc.Subject, st.Subject)
	}
	if lc.ClientID != st.ClientID {
		t.Errorf("ClientID = %q, want %q", lc.ClientID, st.ClientID)
	}
	if got, want := lc.RequestedScopes, st.RequestedScopes; !equalStrings(got, want) {
		t.Errorf("RequestedScopes = %v, want %v", got, want)
	}
	if lc.FailedAttempts != st.LastFailures {
		t.Errorf("FailedAttempts = %d, want %d", lc.FailedAttempts, st.LastFailures)
	}
	if lc.RiskScore != st.RiskScoreCached {
		t.Errorf("RiskScore = %v, want %v", lc.RiskScore, st.RiskScoreCached)
	}
	if got, want := lc.CompletedKinds, st.CompletedStepKinds; !equalStrings(got, want) {
		t.Errorf("CompletedKinds = %v, want %v", got, want)
	}
	if got, want := lc.ACRValues, st.ACRValues; !equalStrings(got, want) {
		t.Errorf("ACRValues = %v, want %v — the original projector dropped State.ACRValues; this is the regression guard", got, want)
	}
	if lc.RemoteIP != st.RemoteIP.String() {
		t.Errorf("RemoteIP = %q, want %q", lc.RemoteIP, st.RemoteIP.String())
	}
	if lc.UserAgent != st.UserAgent {
		t.Errorf("UserAgent = %q, want %q", lc.UserAgent, st.UserAgent)
	}
}

// TestLoginFlowContextProjectionDefensivelyCopiesSlices confirms the
// projector hands rule predicates a defensive copy of every slice field
// rather than aliasing State's backing array. A predicate that
// (incorrectly) mutates lc.ACRValues / lc.CompletedKinds /
// lc.RequestedScopes MUST NOT corrupt the orchestrator's State.
func TestLoginFlowContextProjectionDefensivelyCopiesSlices(t *testing.T) {
	t.Parallel()

	st := State{
		RequestedScopes:    []string{"openid"},
		CompletedStepKinds: []string{"myorg.password"},
		ACRValues:          []string{"urn:test:silver"},
	}
	o := &Orchestrator{}
	lc := o.loginFlowContext(st)

	// Mutate the projection; the State backing arrays must stay
	// unchanged.
	if len(lc.ACRValues) > 0 {
		lc.ACRValues[0] = "urn:test:tampered"
	}
	if len(lc.CompletedKinds) > 0 {
		lc.CompletedKinds[0] = "myorg.tampered"
	}
	if len(lc.RequestedScopes) > 0 {
		lc.RequestedScopes[0] = "tampered"
	}

	if st.ACRValues[0] != "urn:test:silver" {
		t.Errorf("State.ACRValues was mutated through the projection: %v", st.ACRValues)
	}
	if st.CompletedStepKinds[0] != "myorg.password" {
		t.Errorf("State.CompletedStepKinds was mutated through the projection: %v", st.CompletedStepKinds)
	}
	if st.RequestedScopes[0] != "openid" {
		t.Errorf("State.RequestedScopes was mutated through the projection: %v", st.RequestedScopes)
	}
}

// equalStrings is a shallow slice-equality helper. It exists so the
// regression test does not pull in slices.Equal (the surrounding
// package targets a Go version that already has it, but the project
// style keeps the comparison local for readability).
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
