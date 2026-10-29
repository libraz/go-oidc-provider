package authorizeendpoint_test

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// walkLogin answers every credential prompt the interaction at path
// emits — the subject prompt with reauthSubject, the second factor with
// an empty form — then consent, and returns the prompt types in order.
func walkLogin(t *testing.T, d *reauthDriver, path string) []string {
	t.Helper()
	env, csrf := d.firstPrompt(path)
	cur := promptStep{env: env, csrf: csrf}
	cur.stateRef, _ = env["state_ref"].(string)
	var seen []string
	for {
		kind, _ := cur.env["type"].(string)
		seen = append(seen, kind)
		values := map[string]string{}
		if kind == testkit.SubjectPromptType {
			values[testkit.SubjectFieldName] = reauthSubject
		}
		resp := d.submit(path, cur.csrf, cur.stateRef, values)
		if resp.StatusCode == http.StatusOK {
			if rotated := findCookie(resp.Cookies(), "__Host-oidc_csrf"); rotated != nil {
				cur.csrf = rotated.Value
			}
		}
		consent, next, err := testkit.IsConsentPrompt(resp)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("read prompt: %v", err)
		}
		if consent {
			ref, _ := next["state_ref"].(string)
			resp = testkit.PostConsentApproval(t, d.cl, d.fix.server.URL+path, d.fix.issuer, cur.csrf, ref, approvedScopesFromPrompt(next))
			resp.Body.Close()
		}
		if resp.StatusCode == http.StatusFound {
			return seen
		}
		if next == nil {
			t.Fatalf("after prompts %v: status=%d, want another prompt or the RP redirect", seen, resp.StatusCode)
		}
		cur.env = next
		cur.stateRef, _ = next["state_ref"].(string)
		if len(seen) > 4 {
			t.Fatalf("login did not finish after prompts %v", seen)
		}
	}
}

// TestEndToEnd_PromptLoginRunsIdentifyingFactorFirst pins that, with a
// live session and prompt=login, the fresh authentication starts with the
// identifying factor. The possession rule step would otherwise run on
// the strength of the session subject alone and mint a code with no
// credential presented in this attempt.
func TestEndToEnd_PromptLoginRunsIdentifyingFactorFirst(t *testing.T) {
	t.Parallel()

	surfaces := map[string]func(*movableClock) op.Option{
		"LoginFlow": func(clock *movableClock) op.Option {
			return op.WithLoginFlow(op.LoginFlow{
				Primary: op.ExternalStep{
					Authenticator: passwordEchoAuthenticator{clock: clock},
					KindLabel:     op.StepKind("test.primary"),
				},
				Rules: []op.Rule{op.RuleAlways(op.ExternalStep{
					Authenticator: secondFactorEcho{clock: clock},
					KindLabel:     op.StepKind("test.second"),
				})},
			})
		},
	}
	for name, authnOpt := range surfaces {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			clock := newMovableClock(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
			d := newReauthDriver(t, buildFlowFixture(t, name, clock, authnOpt(clock)))

			first := d.authorize(url.Values{"scope": {"openid"}})
			if got := walkLogin(t, d, first.Path); got[0] != testkit.SubjectPromptType {
				t.Fatalf("initial login prompts %v, want the identifying factor first", got)
			}

			clock.Advance(time.Minute)
			again := d.authorize(url.Values{"scope": {"openid"}, "prompt": {"login"}})
			if again.Query().Get("code") != "" {
				t.Fatalf("prompt=login minted a code from the session: %s", again)
			}
			env, _ := d.firstPrompt(again.Path)
			if got, _ := env["type"].(string); got != testkit.SubjectPromptType {
				t.Fatalf("prompt=login first prompt = %q, want the identifying factor %q", got, testkit.SubjectPromptType)
			}
		})
	}
}
