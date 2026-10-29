package authorizeendpoint_test

import (
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/op"
)

// TestEndToEnd_StepUpRefusedWhenEntrySessionEndedMidCeremony pins that a
// LoginFlow step run on top of an existing session cannot complete once
// that session is gone: Primary was inherited from it, so a sign-out
// between /authorize and the step's submission leaves the chain with a
// second factor alone. The completion must answer login_required rather
// than issue a code and a fresh session carrying the inherited pwd.
func TestEndToEnd_StepUpRefusedWhenEntrySessionEndedMidCeremony(t *testing.T) {
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
	_ = d.codeFrom(d.completeCredentialLogin(login.Path, 0))
	widenGrant(t, fix, reauthSubject, "email")

	clock.Advance(time.Minute)
	stepUp := d.authorize(url.Values{"scope": {"openid email"}})
	env, csrf := d.firstPrompt(stepUp.Path)
	if got, _ := env["type"].(string); got != secondFactorPromptType {
		t.Fatalf("first prompt=%q, want the rule's %q", got, secondFactorPromptType)
	}

	// The browser signs out in another tab: the session cookie is cleared.
	base, err := url.Parse(fix.server.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	d.cl.Jar.SetCookies(base, []*http.Cookie{{Name: cookie.SessionProfile.Name, Value: "", Path: "/", MaxAge: -1}})

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
	q := loc.Query()
	if q.Get("code") != "" {
		t.Fatalf("code issued after the entry session ended: %s", loc)
	}
	if got := q.Get("error"); got != "login_required" {
		t.Fatalf("error=%q, want login_required (location %s)", got, loc)
	}
}
