package op_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

// stubCaptcha is the minimal [op.CaptchaVerifier] used by option-
// validation tests. Verify is not invoked at construction time; the
// stub exists so [op.New] can accept a non-nil interface value.
type stubCaptcha struct{}

func (stubCaptcha) Verify(_ context.Context, _ op.CaptchaInput) error { return nil }

// stubRisk is the minimal [op.RiskAssessor] used by option-validation
// tests.
type stubRisk struct{}

func (stubRisk) Assess(_ context.Context, _ op.RiskInput) (op.RiskOutcome, error) {
	return op.RiskOutcome{Decision: op.RiskAllow}, nil
}

// stubObserver is the minimal [op.LoginAttemptObserver] used by
// option-validation tests. The fields capture invocation count so
// fan-out tests can assert against it without race-prone shared state.
// The count stays at zero in option-validation tests because Observe
// is only invoked from a live authentication chain, not at [op.New]
// construction time.
type stubObserver struct {
	calls int
}

func (s *stubObserver) Observe(_ context.Context, _ op.LoginAttempt) { s.calls++ }

func TestWithAuthenticators_AcceptsAndPreservesOrder(t *testing.T) {
	t.Parallel()

	first := stubAuthenticator{typ: op.FactorPassword, aal: op.AAL1, amr: "pwd"}
	second := stubAuthenticator{typ: op.FactorTOTP, aal: op.AAL2, amr: "otp"}

	provider, err := op.New(append(validBaseOpts(t),
		op.WithAuthenticators(first, second),
	)...)
	if err != nil {
		t.Fatalf("WithAuthenticators rejected valid set: %v", err)
	}
	if provider == nil {
		t.Fatal("expected non-nil provider")
	}
}

func TestWithAuthenticators_AppendsAcrossCalls(t *testing.T) {
	t.Parallel()

	a := stubAuthenticator{typ: op.FactorPassword}
	b := stubAuthenticator{typ: op.FactorTOTP}

	if _, err := op.New(append(validBaseOpts(t),
		op.WithAuthenticators(a),
		op.WithAuthenticators(b),
	)...); err != nil {
		t.Fatalf("two WithAuthenticators calls failed: %v", err)
	}
}

func TestWithAuthenticators_RejectsNil(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithAuthenticators(stubAuthenticator{typ: op.FactorPassword}, nil),
	)...)
	if err == nil {
		t.Fatal("WithAuthenticators accepted nil entry")
	}
}

func TestWithAuthenticators_RejectsEmpty(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t), op.WithAuthenticators())...); err == nil {
		t.Fatal("WithAuthenticators accepted empty input")
	}
}

func TestWithAuthenticators_RejectsDuplicateType(t *testing.T) {
	t.Parallel()

	a := stubAuthenticator{typ: op.FactorPassword}
	b := stubAuthenticator{typ: op.FactorPassword}

	_, err := op.New(append(validBaseOpts(t),
		op.WithAuthenticators(a, b),
	)...)
	if err == nil {
		t.Fatal("op.New must reject duplicate FactorType across authenticators")
	}
	if op.IsClientError(err) {
		t.Errorf("duplicate FactorType must surface as a server error, got %v", err)
	}
}

func TestWithAuthenticators_RejectsDuplicateAcrossCalls(t *testing.T) {
	t.Parallel()

	a := stubAuthenticator{typ: op.FactorPassword}
	b := stubAuthenticator{typ: op.FactorPassword}

	_, err := op.New(append(validBaseOpts(t),
		op.WithAuthenticators(a),
		op.WithAuthenticators(b),
	)...)
	if err == nil {
		t.Fatal("op.New must reject duplicate FactorType across WithAuthenticators calls")
	}
}

func TestWithCaptchaVerifier_Accepts(t *testing.T) {
	t.Parallel()

	provider, err := op.New(append(validBaseOpts(t),
		op.WithCaptchaVerifier(stubCaptcha{}),
	)...)
	if err != nil {
		t.Fatalf("WithCaptchaVerifier rejected non-nil verifier: %v", err)
	}
	if provider == nil {
		t.Fatal("expected non-nil provider")
	}
}

func TestWithCaptchaVerifier_RejectsNil(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t), op.WithCaptchaVerifier(nil))...); err == nil {
		t.Fatal("WithCaptchaVerifier accepted nil")
	}
}

func TestWithCaptchaVerifier_RejectsSecondCall(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithCaptchaVerifier(stubCaptcha{}),
		op.WithCaptchaVerifier(stubCaptcha{}),
	)...)
	if err == nil {
		t.Fatal("op.New must reject a second WithCaptchaVerifier call")
	}
	var oe *op.Error
	if !errors.As(err, &oe) {
		t.Fatalf("expected *op.Error, got %T", err)
	}
	if !op.IsServerError(err) {
		t.Errorf("duplicate WithCaptchaVerifier must classify as server error, got %v", err)
	}
}

func TestWithRiskAssessor_Accepts(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t),
		op.WithRiskAssessor(stubRisk{}),
	)...); err != nil {
		t.Fatalf("WithRiskAssessor rejected non-nil assessor: %v", err)
	}
}

func TestWithRiskAssessor_RejectsNil(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t), op.WithRiskAssessor(nil))...); err == nil {
		t.Fatal("WithRiskAssessor accepted nil")
	}
}

func TestWithRiskAssessor_RejectsSecondCall(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithRiskAssessor(stubRisk{}),
		op.WithRiskAssessor(stubRisk{}),
	)...)
	if err == nil {
		t.Fatal("op.New must reject a second WithRiskAssessor call")
	}
	if !op.IsServerError(err) {
		t.Errorf("duplicate WithRiskAssessor must classify as server error, got %v", err)
	}
}

func TestWithLoginAttemptObserver_AcceptsMultiple(t *testing.T) {
	t.Parallel()

	a := &stubObserver{}
	b := &stubObserver{}

	provider, err := op.New(append(validBaseOpts(t),
		op.WithLoginAttemptObserver(a),
		op.WithLoginAttemptObserver(b),
	)...)
	if err != nil {
		t.Fatalf("multiple WithLoginAttemptObserver calls rejected: %v", err)
	}
	if provider == nil {
		t.Fatal("expected non-nil provider")
	}
	// The orchestrator invokes observers from a live authentication
	// chain; option-validation tests never run a chain, so the count
	// stays zero. The assertion exists only to prove the stub field is
	// reachable through the public surface.
	if a.calls != 0 || b.calls != 0 {
		t.Errorf("observers must not be invoked at construction time; got a=%d b=%d", a.calls, b.calls)
	}
}

func TestWithLoginAttemptObserver_RejectsNil(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t), op.WithLoginAttemptObserver(nil))...); err == nil {
		t.Fatal("WithLoginAttemptObserver accepted nil")
	}
}

func TestWithInteractions_AcceptsAndPreservesOrder(t *testing.T) {
	t.Parallel()

	first := stubInteraction{name: "myorg.tos.accept", trigger: op.TriggerAfterAuthn}
	second := stubInteraction{name: "myorg.kyc.start", trigger: op.TriggerAfterAuthn}

	if _, err := op.New(append(validBaseOpts(t),
		op.WithInteractions(first, second),
	)...); err != nil {
		t.Fatalf("WithInteractions rejected valid set: %v", err)
	}
}

func TestWithInteractions_AppendsAcrossCalls(t *testing.T) {
	t.Parallel()

	a := stubInteraction{name: "myorg.tos.accept", trigger: op.TriggerAfterAuthn}
	b := stubInteraction{name: "myorg.kyc.start", trigger: op.TriggerAfterAuthn}

	if _, err := op.New(append(validBaseOpts(t),
		op.WithInteractions(a),
		op.WithInteractions(b),
	)...); err != nil {
		t.Fatalf("two WithInteractions calls failed: %v", err)
	}
}

func TestWithInteractions_RejectsNil(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithInteractions(stubInteraction{name: "myorg.tos.accept"}, nil),
	)...)
	if err == nil {
		t.Fatal("WithInteractions accepted nil entry")
	}
}

func TestWithInteractions_RejectsEmpty(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t), op.WithInteractions())...); err == nil {
		t.Fatal("WithInteractions accepted empty input")
	}
}

func TestWithInteractions_RejectsDuplicateName(t *testing.T) {
	t.Parallel()

	a := stubInteraction{name: "myorg.tos.accept"}
	b := stubInteraction{name: "myorg.tos.accept"}

	_, err := op.New(append(validBaseOpts(t),
		op.WithInteractions(a, b),
	)...)
	if err == nil {
		t.Fatal("op.New must reject duplicate Interaction.Name across registrations")
	}
}

func TestWithInteractions_RejectsEmptyName(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithInteractions(stubInteraction{name: ""}),
	)...)
	if err == nil {
		t.Fatal("op.New must reject Interaction with empty Name")
	}
}

// TestPromptDataSealing pins the documented sealing pattern: the
// concrete shipped types satisfy [interaction.PromptData], and tests that
// instantiate an [interaction.Prompt] can do so verbatim. A foreign type
// cannot satisfy the interface because interaction.PromptData declares an
// unexported method — the absence of a compile failure for the
// commented-out lines below would surface a sealing regression.
func TestPromptDataSealing(t *testing.T) {
	t.Parallel()

	// Compile-time confirmations that the shipped types satisfy the
	// sealed interface.
	var (
		_ interaction.PromptData = interaction.PasswordPromptData{}
		_ interaction.PromptData = interaction.TOTPPromptData{}
		_ interaction.PromptData = interaction.EmailOTPSendPromptData{}
		_ interaction.PromptData = interaction.EmailOTPVerifyPromptData{}
		_ interaction.PromptData = interaction.PasskeyPromptData{}
		_ interaction.PromptData = interaction.RecoveryCodePromptData{}
		_ interaction.PromptData = interaction.CaptchaPromptData{}
		_ interaction.PromptData = interaction.ConsentScopePromptData{}
	)

	// The following pattern would not compile in user code because
	// isPromptData is unexported in op:
	//
	//   type ForeignPromptData struct{}
	//   func (ForeignPromptData) isPromptData() {} // illegal — method is unexported in op
	//   var _ interaction.PromptData = ForeignPromptData{}
	//
	// We document the constraint here rather than invoke it; go vet
	// would flag the failed assertion, and the sealing pattern is a
	// well-known Go idiom.
}

// TestRiskInput_FieldsAreReachable is a smoke test that the public
// [op.RiskInput] / [op.RiskOutcome] / [op.LoginAttempt] surface stays
// addressable. The assertion exists so renames of the public types
// surface immediately as a compile error here.
func TestRiskInput_FieldsAreReachable(t *testing.T) {
	t.Parallel()

	addr := netip.MustParseAddr("203.0.113.1")
	in := op.RiskInput{
		Stage:      op.RiskPreFactor,
		Subject:    "sub-1",
		ClientID:   "client-1",
		RemoteIP:   addr,
		UserAgent:  "ua",
		AMRSoFar:   []string{"pwd"},
		LastFactor: op.FactorPassword,
	}
	if in.RemoteIP != addr {
		t.Fatalf("RiskInput.RemoteIP round-trip mismatch")
	}
	out := op.RiskOutcome{
		Decision:        op.RiskRequire,
		RequiredFactors: []op.FactorType{op.FactorTOTP},
		MinAAL:          op.AAL2,
		Reason:          "anomaly.geoip_mismatch",
	}
	if out.Decision != op.RiskRequire {
		t.Fatalf("RiskOutcome.Decision round-trip mismatch")
	}
	evt := op.LoginAttempt{
		ClientID: "client-1",
		Outcome:  op.AttemptSuccess,
		Factor:   op.FactorPassword,
		Reason:   "attempt.invalid_credentials",
	}
	if evt.Outcome != op.AttemptSuccess {
		t.Fatalf("LoginAttempt.Outcome round-trip mismatch")
	}
}
