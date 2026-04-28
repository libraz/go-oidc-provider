package op_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

// TestScopeSetHasInLoginContext covers ScopeSet membership through the
// canonical type declared in op/claim.go. The login-flow surface reuses
// it via [LoginContext.RequestedScopes]; this test is a regression
// pin so a future refactor that re-introduces a slice-shaped ScopeSet
// fails here.
func TestScopeSetHasInLoginContext(t *testing.T) {
	t.Parallel()
	s := op.ScopeSet{
		op.ScopeName("openid"):        {},
		op.ScopeName("profile"):       {},
		op.ScopeName("write:billing"): {},
	}
	cases := []struct {
		scope op.ScopeName
		want  bool
	}{
		{op.ScopeName("openid"), true},
		{op.ScopeName("profile"), true},
		{op.ScopeName("write:billing"), true},
		{op.ScopeName("email"), false},
		{op.ScopeName(""), false},
		{op.ScopeName("OPENID"), false}, // case-sensitive per RFC 6749 §3.3
	}
	for _, tc := range cases {
		if got := s.Has(tc.scope); got != tc.want {
			t.Errorf("ScopeSet.Has(%q) = %v, want %v", tc.scope, got, tc.want)
		}
	}
}

// TestScopeSetHasEmpty covers the nil / empty receivers.
func TestScopeSetHasEmpty(t *testing.T) {
	t.Parallel()
	if (op.ScopeSet{}).Has(op.ScopeName("openid")) {
		t.Error("empty ScopeSet should not contain any scope")
	}
	var nilSet op.ScopeSet
	if nilSet.Has(op.ScopeName("openid")) {
		t.Error("nil ScopeSet should not contain any scope")
	}
}

// TestRiskScoreOrdering pins the constants are ordered None < Low <
// Medium < High so `score >= threshold` comparison works as
// documented.
func TestRiskScoreOrdering(t *testing.T) {
	t.Parallel()
	if op.RiskScoreNone >= op.RiskScoreLow {
		t.Error("RiskScoreNone must be less than RiskScoreLow")
	}
	if op.RiskScoreLow >= op.RiskScoreMedium {
		t.Error("RiskScoreLow must be less than RiskScoreMedium")
	}
	if op.RiskScoreMedium >= op.RiskScoreHigh {
		t.Error("RiskScoreMedium must be less than RiskScoreHigh")
	}
	if op.RiskScoreHigh <= op.RiskScoreMedium {
		t.Error("RiskScoreHigh must be greater than RiskScoreMedium (symmetry check)")
	}
}
