package risk_test

import (
	"context"
	"errors"
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

// TestRunPreFactorNilAssessor asserts the helper short-circuits when
// the assessor is nil — the orchestrator does not need a nil guard
// at the call site.
func TestRunPreFactorNilAssessor(t *testing.T) {
	t.Parallel()
	res, err := risk.RunPreFactor(context.Background(), nil, risk.Input{})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if res.Denied || len(res.Required) != 0 {
		t.Errorf("res = %+v, want empty", res)
	}
}

// TestRunPreFactorDenyShortCircuits asserts a Deny decision flips the
// Denied flag and ignores any RequiredFactors that may have been set.
func TestRunPreFactorDenyShortCircuits(t *testing.T) {
	t.Parallel()
	a := stubAssessor{out: risk.Outcome{Decision: risk.Deny}}
	res, err := risk.RunPreFactor(context.Background(), a, risk.Input{})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !res.Denied {
		t.Error("Denied should be true")
	}
}

// TestRunPreFactorRequirePropagatesFactors asserts RequiredFactors are
// returned verbatim on a Require decision.
func TestRunPreFactorRequirePropagatesFactors(t *testing.T) {
	t.Parallel()
	a := stubAssessor{out: risk.Outcome{
		Decision:        risk.Require,
		RequiredFactors: []string{"passkey"},
	}}
	res, err := risk.RunPreFactor(context.Background(), a, risk.Input{})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(res.Required) != 1 || res.Required[0] != "passkey" {
		t.Errorf("Required = %+v", res.Required)
	}
}

// TestRunPostFactorErrorBubbles asserts an assessor error surfaces
// without being swallowed.
func TestRunPostFactorErrorBubbles(t *testing.T) {
	t.Parallel()
	wantErr := errors.New("backend down")
	a := stubAssessor{err: wantErr}
	_, err := risk.RunPostFactor(context.Background(), a, risk.Input{})
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
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
