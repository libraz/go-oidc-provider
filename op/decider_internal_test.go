package op

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/redact"
)

// stubDecider returns a fixed Decision, so a test can pin what the
// adapter does with each shape without building a login flow.
type stubDecider struct{ decision Decision }

func (s stubDecider) Decide(context.Context, LoginContext) Decision { //nolint:ireturn // Decision is a sealed sum type; returning it is the Decider contract.
	return s.decision
}

// TestDeciderAdapter_ProjectsEveryDecision pins the translation from the
// public [Decision] sum onto the orchestrator's internal one. The two
// sums are separate types on purpose — internal/authn cannot import op —
// so nothing but this table stops the adapter from quietly collapsing a
// case onto the wrong one. Pass is the safe default the adapter falls
// back to, which is exactly why a mistranslation is not loud: a Deny
// that arrived as a Pass would let a login the embedder refused proceed
// to the rules.
func TestDeciderAdapter_ProjectsEveryDecision(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   Decision
		want authn.LoginFlowDecision
	}{
		{"allow", Allow{}, authn.LoginFlowAllow{}},
		{"pass", Pass{}, authn.LoginFlowPass{}},
		{"deny", Deny{Reason: "policy"}, authn.LoginFlowDeny{Reason: "policy"}},
		{
			"require",
			Require{Kind: StepKindRecoveryCode},
			authn.LoginFlowRequire{Step: authn.LoginFlowStep{Kind: string(StepKindRecoveryCode)}},
		},
		// A Require naming nothing is not a step the orchestrator could
		// run, and treating it as one would fail the login on a
		// configuration slip. Deferring to the rules is the reading that
		// neither invents a factor nor drops one.
		{"require-empty-kind", Require{}, authn.LoginFlowPass{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a := &deciderAdapter{inner: stubDecider{decision: tc.in}}
			if got := a.Decide(context.Background(), authn.LoginFlowContext{}); got != tc.want {
				t.Errorf("Decide(%T) = %#v, want %#v", tc.in, got, tc.want)
			}
		})
	}
}

// TestDeciderAdapter_RequireCarriesOnlyTheKind pins the property the
// public godoc rests on: Require selects a declared step, it does not
// supply one. The adapter hands the orchestrator a kind and nothing
// else, so a step the flow never declared has no authenticator to run
// and is refused rather than silently constructed at decision time —
// which is what keeps the factors a login can demand enumerable from
// the LoginFlow alone.
func TestDeciderAdapter_RequireCarriesOnlyTheKind(t *testing.T) {
	t.Parallel()

	a := &deciderAdapter{inner: stubDecider{decision: Require{Kind: "myorg.sms_otp"}}}
	got, ok := a.Decide(context.Background(), authn.LoginFlowContext{}).(authn.LoginFlowRequire)
	if !ok {
		t.Fatalf("Decide returned %T, want authn.LoginFlowRequire", got)
	}
	if got.Step.Kind != "myorg.sms_otp" {
		t.Errorf("Step.Kind = %q, want %q", got.Step.Kind, "myorg.sms_otp")
	}
	if got.Step.Authenticator != nil {
		t.Errorf("Step.Authenticator = %#v, want nil; the adapter must not resolve a step the flow did not declare", got.Step.Authenticator)
	}
	if got.Step.IsCaptcha {
		t.Error("Step.IsCaptcha is set; the adapter carries no step configuration at all")
	}
}

// TestDenyReason_ReachesTheSinkVerbatim pins the property [Deny.Reason]
// documents: the value is not masked on its way to a log sink. The
// redactor matches a closed catalogue of credential-bearing attribute
// keys, and neither the "reason" attribute the orchestrator writes nor
// the reserved [AuditDenyReasonKey] is in it. The test exists because
// the field's godoc previously promised the opposite; an embedder
// reading it decides what is safe to put in Reason, so the real
// handling has to be pinned rather than assumed either way.
//
// The test lives in the internal test package because
// [AuditDenyReasonKey] is deprecated and the external test package
// cannot reference it without a lint suppression.
func TestDenyReason_ReachesTheSinkVerbatim(t *testing.T) {
	t.Parallel()

	if AuditDenyReasonKey != "audit.deny.reason" {
		t.Errorf("AuditDenyReasonKey = %q; the documented value is frozen", AuditDenyReasonKey)
	}
	for _, key := range []string{"reason", AuditDenyReasonKey} {
		if redact.IsSensitive(key) {
			t.Errorf("redact.IsSensitive(%q) = true, want false: Deny.Reason is documented as reaching the sink unmasked", key)
		}
	}

	var buf bytes.Buffer
	logger := slog.New(redact.WrapHandler(slog.NewJSONHandler(&buf, nil)))
	const reason = "policy.geo"
	logger.Info("authn: LoginFlow denied", slog.String("reason", reason))
	if !strings.Contains(buf.String(), reason) {
		t.Errorf("record = %s, want it to carry %q verbatim", buf.String(), reason)
	}
	if strings.Contains(buf.String(), redact.Sentinel) {
		t.Errorf("record = %s, want no redaction sentinel for the reason attribute", buf.String())
	}
}
