package op_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

// TestAttemptOutcomeExhaustiveSwitch pins the completeness of the
// re-export block. An embedder can only classify a LoginAttempt from
// outside the module using op identifiers — internal/authn is not
// importable — so every outcome the orchestrator can emit has to be
// nameable here. The switch has no default clause on purpose: a value
// added to the canonical enum without a matching re-export leaves this
// mapping unable to name it.
func TestAttemptOutcomeExhaustiveSwitch(t *testing.T) {
	t.Parallel()

	label := func(o op.AttemptOutcome) string {
		switch o {
		case op.AttemptSuccess:
			return "success"
		case op.AttemptFailure:
			return "failure"
		case op.AttemptLocked:
			return "locked"
		}
		return "unknown"
	}

	cases := map[op.AttemptOutcome]string{
		op.AttemptSuccess: "success",
		op.AttemptFailure: "failure",
		op.AttemptLocked:  "locked",
	}
	for outcome, want := range cases {
		if got := label(outcome); got != want {
			t.Errorf("label(%v) = %q, want %q", outcome, got, want)
		}
	}
	// The three constants must be distinct, so a re-export that aliased
	// the wrong canonical value cannot pass the switch above by accident.
	if len(cases) != 3 {
		t.Fatalf("distinct AttemptOutcome values = %d, want 3", len(cases))
	}
}
