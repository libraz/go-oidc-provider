package authn_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

// inheritOrchestrator compiles a password-primary flow with one
// always-firing rule per step.
func inheritOrchestrator(t *testing.T, steps ...authn.LoginFlowStep) *authn.Orchestrator {
	t.Helper()
	spec := authn.LoginFlowSpec{Primary: passwordStep()}
	for _, s := range steps {
		spec.Rules = append(spec.Rules, alwaysRule(s))
	}
	flow, err := authn.CompileLoginFlow(spec)
	if err != nil {
		t.Fatalf("CompileLoginFlow: %v", err)
	}
	o, err := authn.New(authn.Config{LoginFlow: flow, StateRefSigner: newSigner(t)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return o
}

func factorStep(kind string, typ op.FactorType, amr string) authn.LoginFlowStep {
	return authn.LoginFlowStep{Kind: kind, Authenticator: successAuth(typ, op.AAL2, amr, "user-1")}
}

// reusedState is a chain started from a live session for user-1 with
// the given amr at level.
func reusedState(level op.AAL, amr ...string) authn.State {
	st := initialState()
	st.Subject = "user-1"
	st.EntryAuthn = &authn.EntryAuthn{Subject: "user-1", ACR: level.ACRURI(), AMR: amr}
	return st
}

func TestInheritedCompletedKinds_PasskeyUV(t *testing.T) {
	t.Parallel()

	uv := factorStep("passkey_uv", op.FactorPasskey, "hwk")
	uv.RequireUserVerification = true
	o := inheritOrchestrator(t, uv, factorStep("passkey_any", op.FactorPasskey, "hwk"))

	for _, tc := range []struct {
		amr  []string
		want []string
	}{
		{amr: []string{"hwk"}, want: []string{"password", "passkey_uv", "passkey_any"}},
		{amr: []string{"swk"}, want: []string{"password", "passkey_any"}},
	} {
		if got := o.InheritedCompletedKinds(authn.EntryAuthn{Subject: "user-1", AMR: tc.amr}); !slices.Equal(got, tc.want) {
			t.Errorf("amr %v: kinds = %v, want %v", tc.amr, got, tc.want)
		}
	}
}

func TestInheritedCompletedKinds_MFAIgnored(t *testing.T) {
	t.Parallel()

	o := inheritOrchestrator(t, factorStep("totp", op.FactorTOTP, "otp"))
	for _, amr := range [][]string{{"mfa"}, {"pwd", "mfa"}} {
		if got := o.InheritedCompletedKinds(authn.EntryAuthn{Subject: "user-1", AMR: amr}); !slices.Equal(got, []string{"password"}) {
			t.Errorf("amr %v: kinds = %v, want [password]", amr, got)
		}
	}
}

// TestInheritedCompletedKinds_ExternalStepNeverSatisfied pins that a
// factor whose type has no registered amr value, and a captcha, are
// never stood in for, whatever the session carries and whatever amr the
// authenticator itself declares.
func TestInheritedCompletedKinds_ExternalStepNeverSatisfied(t *testing.T) {
	t.Parallel()

	captcha := factorStep("captcha", "captcha", "")
	captcha.IsCaptcha = true
	o := inheritOrchestrator(t, factorStep("myorg.sms", "myorg.sms", "otp"), captcha)
	got := o.InheritedCompletedKinds(authn.EntryAuthn{Subject: "user-1", AMR: []string{"hwk", "mfa", "otp", "pwd", "sms", "swk"}})
	if !slices.Equal(got, []string{"password"}) {
		t.Errorf("kinds = %v, want [password]", got)
	}
}

func TestInheritedCompletedKinds_OneOf(t *testing.T) {
	t.Parallel()

	kind := "one_of(passkey,totp)"
	o := inheritOrchestrator(t, oneOfStep(kind, authn.UnenrolledDeny,
		factorStep("passkey", op.FactorPasskey, "hwk"),
		factorStep("totp", op.FactorTOTP, "otp"),
	))
	for _, tc := range []struct {
		amr  []string
		want []string
	}{
		{amr: []string{"otp", "pwd"}, want: []string{"password", kind}},
		{amr: []string{"pwd"}, want: []string{"password"}},
	} {
		if got := o.InheritedCompletedKinds(authn.EntryAuthn{Subject: "user-1", AMR: tc.amr}); !slices.Equal(got, tc.want) {
			t.Errorf("amr %v: kinds = %v, want %v", tc.amr, got, tc.want)
		}
	}
}

// TestInheritedCompletedKinds_SharedBySessionReuse pins that the pre-mint
// check, the auth context and the chain read completion the same way: a
// TOTP session needs no TOTP again, a password session does.
func TestInheritedCompletedKinds_SharedBySessionReuse(t *testing.T) {
	t.Parallel()

	o := inheritOrchestrator(t, factorStep("totp", op.FactorTOTP, "otp"))

	otpSession := reusedState(op.AAL2, "mfa", "otp", "pwd")
	if o.LoginFlowRequiresStep(context.Background(), otpSession) {
		t.Error("LoginFlowRequiresStep = true for a TOTP session, want false")
	}
	if got := o.AuthContext(otpSession).CompletedKinds; !slices.Equal(got, []string{"password", "totp"}) {
		t.Errorf("AuthContext.CompletedKinds = %v, want [password totp]", got)
	}
	if _, step, err := o.Tick(context.Background(), otpSession, authn.Input{Now: fakeNow()}); err != nil || step.Result == nil {
		t.Errorf("Tick on a TOTP session = %+v, %v; want the terminal Result without a prompt", step, err)
	}

	pwdSession := reusedState(op.AAL1, "pwd")
	if !o.LoginFlowRequiresStep(context.Background(), pwdSession) {
		t.Error("LoginFlowRequiresStep = false for a password session, want true")
	}
	if _, step, err := o.Tick(context.Background(), pwdSession, authn.Input{Now: fakeNow()}); err != nil || step.Prompt == nil || step.Prompt.Type != "auth.totp" {
		t.Errorf("Tick on a password session = %+v, %v; want the auth.totp prompt", step, err)
	}
}

func TestLoginFlowContext_AuthContext(t *testing.T) {
	t.Parallel()

	var (
		mu   sync.Mutex
		seen []authn.LoginFlowContext
	)
	flow, err := authn.CompileLoginFlow(authn.LoginFlowSpec{
		Primary: passwordStep(),
		Rules: []authn.LoginFlowRule{{
			When: func(lc authn.LoginFlowContext) bool {
				mu.Lock()
				seen = append(seen, lc)
				mu.Unlock()
				return false
			},
			// A step no session amr stands in for, so the predicate runs.
			Then: factorStep("myorg.sms", "myorg.sms", ""),
		}},
	})
	if err != nil {
		t.Fatalf("CompileLoginFlow: %v", err)
	}
	o, err := authn.New(authn.Config{LoginFlow: flow, StateRefSigner: newSigner(t)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	last := func() authn.LoginFlowContext {
		mu.Lock()
		defer mu.Unlock()
		if len(seen) == 0 {
			t.Fatal("rule predicate never ran")
		}
		return seen[len(seen)-1]
	}

	st, step, err := o.Tick(context.Background(), initialState(), authn.Input{Now: fakeNow()})
	if err != nil {
		t.Fatalf("primary: %v", err)
	}
	if _, _, err := submitValues(o, st, step.Prompt, map[string]string{"password": "x"}); err != nil {
		t.Fatalf("primary continue: %v", err)
	}
	fresh := last()
	if fresh.Inherited || fresh.Level != op.AAL1 || fresh.ACR != op.AAL1.ACRURI() ||
		!slices.Equal(fresh.AMR, []string{"pwd"}) || !fresh.AuthTime.IsZero() {
		t.Errorf("fresh context = inherited %v level %v acr %q amr %v auth_time %v; want false/AAL1/AAL1 URI/[pwd]/zero",
			fresh.Inherited, fresh.Level, fresh.ACR, fresh.AMR, fresh.AuthTime)
	}

	sessionAuthTime := fakeNow().Add(-time.Hour)
	reused := reusedState(op.AAL2, "otp", "pwd")
	reused.EntryAuthn.AuthTime = sessionAuthTime
	if o.LoginFlowRequiresStep(context.Background(), reused) {
		t.Fatal("LoginFlowRequiresStep = true, want false for a never-firing rule")
	}
	got := last()
	if !got.Inherited || got.Level != op.AAL2 || got.ACR != op.AAL2.ACRURI() ||
		!slices.Equal(got.AMR, []string{"mfa", "otp", "pwd"}) || !got.AuthTime.Equal(sessionAuthTime) {
		t.Errorf("reused context = inherited %v level %v acr %q amr %v auth_time %v; want true/AAL2/AAL2 URI/[mfa otp pwd]/%v",
			got.Inherited, got.Level, got.ACR, got.AMR, got.AuthTime, sessionAuthTime)
	}
}

func TestLoginFlowRequiresStep_SkipUnenrolled(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		policy   authn.UnenrolledPolicy
		enrolled bool
		probeErr error
		want     bool
	}{
		{name: "skip unenrolled", policy: authn.UnenrolledSkip, want: false},
		{name: "skip enrolled", policy: authn.UnenrolledSkip, enrolled: true, want: true},
		{name: "skip probe error", policy: authn.UnenrolledSkip, probeErr: errors.New("store unavailable"), want: true},
		{name: "deny unenrolled", policy: authn.UnenrolledDeny, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			totp := probed(op.FactorTOTP, tc.enrolled)
			totp.err = tc.probeErr
			emitter := &recordingAuditEmitter{}
			flow, err := authn.CompileLoginFlow(authn.LoginFlowSpec{
				Primary: passwordStep(),
				Rules: []authn.LoginFlowRule{alwaysRule(oneOfStep("one_of(totp)", tc.policy,
					authn.LoginFlowStep{Kind: "totp", Authenticator: totp}))},
			})
			if err != nil {
				t.Fatalf("CompileLoginFlow: %v", err)
			}
			o, err := authn.New(authn.Config{LoginFlow: flow, AuditEmitter: emitter, StateRefSigner: newSigner(t)})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if got := o.LoginFlowRequiresStep(context.Background(), reusedState(op.AAL1, "pwd")); got != tc.want {
				t.Errorf("LoginFlowRequiresStep = %v, want %v", got, tc.want)
			}
			if got := stepBeginFailedEvents(emitter.snapshot()); len(got) != 0 {
				t.Errorf("audit events = %+v, want none from the pre-mint check", got)
			}
		})
	}
}

func TestRunLoginFlowStep_BeginFailedAudit(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		primary bool
		err     error
		reason  string
	}{
		{name: "not enrolled", err: authn.ErrFactorNotEnrolled, reason: "not_enrolled"},
		{name: "aborted", err: fmt.Errorf("refused: %w", authn.ErrFactorAbort), reason: "aborted"},
		{name: "locked", err: fmt.Errorf("locked: %w", authn.ErrFactorLocked), reason: "locked"},
		{name: "error", err: errors.New("backend down"), reason: "error"},
		{name: "primary error", primary: true, err: errors.New("backend down"), reason: "error"},
		{name: "canceled", err: context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			failing := &stubAuthenticator{
				typeID:  op.FactorTOTP,
				aal:     op.AAL2,
				amr:     "otp",
				prompts: []string{"auth.totp"},
				beginFn: func(context.Context, op.BeginInput) (interaction.Step, error) {
					return interaction.Step{}, tc.err
				},
			}
			spec := authn.LoginFlowSpec{
				Primary: passwordStep(),
				Rules:   []authn.LoginFlowRule{alwaysRule(authn.LoginFlowStep{Kind: "totp", Authenticator: failing})},
			}
			kind, actor := "totp", "user-1"
			if tc.primary {
				spec = authn.LoginFlowSpec{Primary: authn.LoginFlowStep{Kind: "myorg.ldap", Authenticator: failing}}
				kind, actor = "myorg.ldap", ""
			}
			flow, err := authn.CompileLoginFlow(spec)
			if err != nil {
				t.Fatalf("CompileLoginFlow: %v", err)
			}
			emitter := &recordingAuditEmitter{}
			o, err := authn.New(authn.Config{LoginFlow: flow, AuditEmitter: emitter, StateRefSigner: newSigner(t)})
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			st, step, err := o.Tick(context.Background(), initialState(), authn.Input{Now: fakeNow()})
			if !tc.primary {
				if err != nil {
					t.Fatalf("primary: %v", err)
				}
				_, _, err = submitValues(o, st, step.Prompt, map[string]string{"password": "x"})
			}
			if !errors.Is(err, tc.err) {
				t.Fatalf("err = %v, want the Begin error unchanged", err)
			}

			events := stepBeginFailedEvents(emitter.snapshot())
			if tc.reason == "" {
				if len(events) != 0 {
					t.Errorf("events = %+v, want none for a cancelled request", events)
				}
				return
			}
			assertBeginFailed(t, events, kind, tc.reason)
			if events[0].ActorID != actor || events[0].ClientID != "client-test" {
				t.Errorf("actor/client = %q/%q, want %q/client-test", events[0].ActorID, events[0].ClientID, actor)
			}
		})
	}
}
