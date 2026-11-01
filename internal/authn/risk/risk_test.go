package risk_test

import (
	"context"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authn/risk"
)

// stubAssessor lets each test return a caller-controlled outcome.
type stubAssessor struct {
	out risk.Outcome
	err error
}

func (s stubAssessor) Assess(_ context.Context, _ risk.Input) (risk.Outcome, error) {
	return s.out, s.err
}

// TestRunOnceForLoginFlowDecisionMapping verifies the Decision-only
// fallback fills Score with the documented defaults (Allow→Low,
// Require→High) when the assessor does not surface an explicit Score.
func TestRunOnceForLoginFlowDecisionMapping(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		out  risk.Outcome
		want risk.Score
	}{
		{name: "allow-no-score", out: risk.Outcome{Decision: risk.Allow}, want: risk.ScoreLow},
		{name: "allow-explicit-medium", out: risk.Outcome{Decision: risk.Allow, Score: risk.ScoreMedium}, want: risk.ScoreMedium},
		{name: "require-no-score", out: risk.Outcome{Decision: risk.Require}, want: risk.ScoreHigh},
		{name: "require-explicit-medium", out: risk.Outcome{Decision: risk.Require, Score: risk.ScoreMedium}, want: risk.ScoreMedium},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a := stubAssessor{out: tc.out}
			res, err := risk.RunOnceForLoginFlow(context.Background(), a, risk.Input{})
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if res.Score != tc.want {
				t.Errorf("Score = %v, want %v", res.Score, tc.want)
			}
			if res.Denied {
				t.Error("Denied should be false")
			}
		})
	}
}

// TestRunOnceForLoginFlowDeny asserts a Deny outcome flips the Denied
// flag without setting Score.
func TestRunOnceForLoginFlowDeny(t *testing.T) {
	t.Parallel()
	a := stubAssessor{out: risk.Outcome{Decision: risk.Deny}}
	res, err := risk.RunOnceForLoginFlow(context.Background(), a, risk.Input{})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !res.Denied {
		t.Error("Denied should be true")
	}
}
