package op

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

// denyingAssessor answers every consult with RiskDeny and counts the
// calls, so a test can tell "consulted and honoured" from "never
// consulted".
type denyingAssessor struct{ calls int }

func (a *denyingAssessor) Assess(_ context.Context, _ RiskInput) (RiskOutcome, error) {
	a.calls++
	return RiskOutcome{Decision: RiskDeny, Reason: "policy.test"}, nil
}

// passwordOnlyStep wraps a minimal Authenticator as an ExternalStep so
// the flow compiles without any per-factor store wiring.
type passwordOnlyAuth struct{}

func (passwordOnlyAuth) Type() FactorType  { return FactorPassword }
func (passwordOnlyAuth) AAL() AAL          { return AAL1 }
func (passwordOnlyAuth) AMR() string       { return "pwd" }
func (passwordOnlyAuth) Prompts() []string { return []string{"auth.password"} }

func (passwordOnlyAuth) Begin(_ context.Context, _ BeginInput) (interaction.Step, error) {
	return interaction.Step{Prompt: &interaction.Prompt{
		Type: "auth.password",
		Data: interaction.PasswordPromptData{},
	}}, nil
}

func (passwordOnlyAuth) Continue(_ context.Context, _ ContinueInput) (interaction.Step, error) {
	return interaction.Step{Result: &interaction.Result{Subject: "user-1"}}, nil
}

// loginFlowRiskConfig assembles the minimum config buildOrchestrator
// needs to produce a LoginFlow-driven orchestrator.
func loginFlowRiskConfig(flow LoginFlow) *config {
	return &config{
		cookieKeys:   [][]byte{bytes.Repeat([]byte{0xCD}, 32)},
		loginFlow:    flow,
		loginFlowSet: true,
	}
}

// loginFlowRiskState is the per-attempt state the HTTP layer would hand
// to the first Tick.
func loginFlowRiskState() authn.State {
	return authn.State{
		InteractionUID:  "uid-risk",
		ClientID:        "client-risk",
		RemoteIP:        netip.MustParseAddr("203.0.113.7"),
		AuthTime:        time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC),
		ActiveFactorIdx: -1,
		Phase:           authn.PhaseBeforeAuthn,
	}
}

// TestLoginFlowRisk_UsedWhenOptionAbsent confirms LoginFlow.Risk drives
// the chain.
func TestLoginFlowRisk_UsedWhenOptionAbsent(t *testing.T) {
	t.Parallel()

	assessor := &denyingAssessor{}
	cfg := loginFlowRiskConfig(LoginFlow{
		Primary: ExternalStep{Authenticator: passwordOnlyAuth{}, KindLabel: StepKind("myorg.password")},
		Risk:    assessor,
	})

	orch, err := buildOrchestrator(cfg, nil)
	if err != nil {
		t.Fatalf("buildOrchestrator: %v", err)
	}
	st := loginFlowRiskState()
	if _, _, err := orch.Tick(context.Background(), st, authn.Input{Now: st.AuthTime}); !errors.Is(err, authn.ErrRiskDenied) {
		t.Fatalf("err = %v, want ErrRiskDenied from LoginFlow.Risk", err)
	}
	if assessor.calls == 0 {
		t.Error("LoginFlow.Risk was never consulted")
	}
}
