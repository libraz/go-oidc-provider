package authorizeendpoint_test

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
)

// completedStepsPolicy is the default ACR policy that records the
// CompletedSteps of every Resolve call.
type completedStepsPolicy struct {
	op.DefaultACRPolicy

	mu    sync.Mutex
	steps [][]op.StepKind
}

func (p *completedStepsPolicy) Resolve(ctx context.Context, lc op.LoginContext, internal op.AAL) (string, []string, bool) {
	p.mu.Lock()
	p.steps = append(p.steps, slices.Clone(lc.CompletedSteps))
	p.mu.Unlock()
	return p.DefaultACRPolicy.Resolve(ctx, lc, internal)
}

func (p *completedStepsPolicy) last() []op.StepKind {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.steps) == 0 {
		return nil
	}
	return p.steps[len(p.steps)-1]
}

// amrOf returns the id_token amr claim as a sorted string slice.
func amrOf(claims map[string]any) []string {
	raw, _ := claims["amr"].([]any)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	slices.Sort(out)
	return out
}

// TestEndToEnd_SessionReuseStepUpKeepsTheSessionAuthentication pins that
// a LoginFlow step-up run on top of an existing session adds to that
// session's authentication rather than replacing it. The session is
// established with the password Primary alone; a later request whose
// scope a rule guards runs the second factor with Primary inherited. The
// id_token for that request, and the one a following silent request
// reads off the session, must describe both factors — amr carries pwd,
// otp and mfa, and acr the AAL2 level — and the ACR policy must see
// Primary among the completed steps, exactly as after a fresh login that
// ran both.
func TestEndToEnd_SessionReuseStepUpKeepsTheSessionAuthentication(t *testing.T) {
	t.Parallel()

	clock := newMovableClock(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	policy := &completedStepsPolicy{}
	flow := op.WithLoginFlow(op.LoginFlow{
		Primary: op.ExternalStep{
			Authenticator: passwordEchoAuthenticator{clock: clock},
			KindLabel:     op.StepKind("test.primary"),
		},
		Rules: []op.Rule{
			op.RuleScope("email", op.ExternalStep{
				Authenticator: secondFactorEcho{clock: clock},
				KindLabel:     op.StepKind("test.second"),
			}),
		},
	})
	fix := buildFlowFixture(t, "LoginFlow+RuleScope", clock, flow, op.WithACRPolicy(policy))
	d := newReauthDriver(t, fix)

	login := d.authorize(url.Values{"scope": {"openid profile"}})
	first := d.exchange(d.codeFrom(d.completeCredentialLogin(login.Path, 0)))
	if got := amrOf(first); !slices.Equal(got, []string{"pwd"}) {
		t.Fatalf("primary login amr = %v, want [pwd]", got)
	}
	widenGrant(t, fix, reauthSubject, "email")

	clock.Advance(time.Minute)
	stepUp := d.authorize(url.Values{"scope": {"openid email"}})
	env, csrf := d.firstPrompt(stepUp.Path)
	if got, _ := env["type"].(string); got != secondFactorPromptType {
		t.Fatalf("first prompt=%q, want the rule's %q", got, secondFactorPromptType)
	}
	stateRef, _ := env["state_ref"].(string)
	resp := d.submit(stepUp.Path, csrf, stateRef, map[string]string{})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("after the rule's factor: status=%d body=%s", resp.StatusCode, dump)
	}
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	wantAMR := []string{"mfa", "otp", "pwd"}
	wantACR := op.AAL2.ACRURI()
	if got, want := policy.last(), []op.StepKind{"test.primary", "test.second"}; !slices.Equal(got, want) {
		t.Errorf("ACR policy CompletedSteps = %v, want %v", got, want)
	}
	stepped := d.exchange(d.codeFrom(loc))
	if got := amrOf(stepped); !slices.Equal(got, wantAMR) {
		t.Errorf("step-up amr = %v, want %v", got, wantAMR)
	}
	if got, _ := stepped["acr"].(string); got != wantACR {
		t.Errorf("step-up acr = %q, want %q", got, wantACR)
	}

	silent := d.exchange(d.codeFrom(d.authorize(url.Values{"scope": {"openid profile"}, "prompt": {"none"}})))
	if got := amrOf(silent); !slices.Equal(got, wantAMR) {
		t.Errorf("session amr after step-up = %v, want %v", got, wantAMR)
	}
	if got, _ := silent["acr"].(string); got != wantACR {
		t.Errorf("session acr after step-up = %q, want %q", got, wantACR)
	}
}
