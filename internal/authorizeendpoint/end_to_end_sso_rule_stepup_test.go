package authorizeendpoint_test

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

// secondFactorPromptType is the prompt the rule-triggered factor emits.
const secondFactorPromptType = "test.second"

// secondFactorEcho is a test-only TOTP-typed factor that accepts any
// submission for the subject the chain already bound.
type secondFactorEcho struct {
	clock *movableClock
}

func (secondFactorEcho) Type() op.FactorType { return op.FactorTOTP }
func (secondFactorEcho) AAL() op.AAL         { return op.AAL2 }
func (secondFactorEcho) AMR() string         { return "otp" }
func (secondFactorEcho) Prompts() []string   { return []string{secondFactorPromptType} }

func (secondFactorEcho) Begin(context.Context, op.BeginInput) (interaction.Step, error) {
	return interaction.Step{Prompt: &interaction.Prompt{Type: secondFactorPromptType}}, nil
}

func (a secondFactorEcho) Continue(_ context.Context, in op.ContinueInput) (interaction.Step, error) {
	return interaction.Step{Result: &interaction.Result{Subject: in.Subject, AuthTime: a.clock.Now()}}, nil
}

// widenGrant adds scope to every grant subject holds, standing in for a
// consent given before the rule guarding scope was configured.
func widenGrant(t *testing.T, fix *flowFixture, subject, scope string) {
	t.Helper()
	ctx := context.Background()
	grants, err := fix.store.Grants().ListBySubject(ctx, subject)
	if err != nil || len(grants) == 0 {
		t.Fatalf("ListBySubject: grants=%d err=%v", len(grants), err)
	}
	for _, g := range grants {
		g.Scope = append(g.Scope, scope)
		if err := fix.store.Grants().Save(ctx, g); err != nil {
			t.Fatalf("Save grant: %v", err)
		}
	}
}

// TestEndToEnd_SessionReuseStillEvaluatesLoginFlowRules pins that a
// LoginFlow rule guarding a scope applies to an authorization served
// from an existing session, not only to a fresh login. The session is
// established with the primary factor alone and the grant is then
// widened to the guarded scope, so a later request for it is covered by
// the cached grant — a path that would otherwise mint silently. It must
// run the rule's factor, and under prompt=none fail with
// interaction_required. A request the rule does not match is still
// served silently.
//
// Tracks: CVE-2026-73278 (Gitea — OAuth2 / OIDC sign-in paths skipped
// the WebAuthn challenge when WebAuthn was the account's only second
// factor, so an alternative path issued a session with fewer factors).
func TestEndToEnd_SessionReuseStillEvaluatesLoginFlowRules(t *testing.T) {
	t.Parallel()

	clock := newMovableClock(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
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
	fix := buildFlowFixture(t, "LoginFlow+RuleScope", clock, flow)
	d := newReauthDriver(t, fix)

	login := d.authorize(url.Values{"scope": {"openid profile"}})
	if login.Query().Get("code") != "" {
		t.Fatalf("first request expected an interaction redirect, got a code: %s", login)
	}
	d.codeFrom(d.completeCredentialLogin(login.Path, 0))
	widenGrant(t, fix, reauthSubject, "email")

	silent := d.authorize(url.Values{"scope": {"openid email"}, "prompt": {"none"}})
	if got := silent.Query().Get("error"); got != "interaction_required" {
		t.Fatalf("prompt=none with a guarded scope: error=%q (redirect %s), want interaction_required", got, silent)
	}

	unguarded := d.authorize(url.Values{"scope": {"openid profile"}})
	d.codeFrom(unguarded)

	stepUp := d.authorize(url.Values{"scope": {"openid email"}})
	if stepUp.Query().Get("code") != "" {
		t.Fatalf("guarded scope minted a code from the session: %s", stepUp)
	}
	env, csrf := d.firstPrompt(stepUp.Path)
	if got, _ := env["type"].(string); got != secondFactorPromptType {
		t.Fatalf("first prompt=%q, want the rule's %q", got, secondFactorPromptType)
	}
	stateRef, _ := env["state_ref"].(string)
	resp := d.submit(stepUp.Path, csrf, stateRef, map[string]string{})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("after the rule's factor: status=%d body=%s, want the RP redirect without a second consent", resp.StatusCode, dump)
	}
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	d.codeFrom(loc)
}
