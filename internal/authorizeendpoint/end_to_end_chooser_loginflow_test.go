package authorizeendpoint_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// A session the account chooser binds is planned by the LoginFlow exactly
// as the session a request arrives with: a rule or a Decider that demands
// more than the picked session carries is applied before any code.

const chooserRuleClientID = "rp-chooser-freshness"

// chooserLoginFlow is a flow whose Primary is the testkit subject factor,
// guarded for the fixture's client by a rule demanding a second factor.
func chooserLoginFlow(decider op.Decider) op.Option {
	clock := newMovableClock(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	return op.WithLoginFlow(op.LoginFlow{
		Primary: op.ExternalStep{
			Authenticator: testkit.SubjectAuthenticator{},
			KindLabel:     op.StepKind(testkit.SubjectAuthenticator{}.Type()),
		},
		Rules: []op.Rule{
			op.RuleClient(chooserRuleClientID, op.ExternalStep{
				Authenticator: secondFactorEcho{clock: clock},
				KindLabel:     op.StepKind("test.second"),
			}),
		},
		Decider: decider,
	})
}

// denySubject refuses the login of one subject and defers the rest.
type denySubject string

func (d denySubject) Decide(_ context.Context, lc op.LoginContext) op.Decision { //nolint:ireturn // Decision is a sealed sum type; returning it is the Decider contract.
	if string(lc.Identity.Subject) == string(d) {
		return op.Deny{Reason: "subject refused"}
	}
	return op.Pass{}
}

// authorizeWithSession sends /authorize carrying sessionCookie and returns
// the redirect it answers with.
func (f *chooserFreshnessFixture) authorizeWithSession(t *testing.T, sessionCookie string, extra url.Values) *url.URL {
	t.Helper()
	values := e2eAuthorizeValues(f.clientID, f.redirect)
	for k, v := range extra {
		values[k] = v
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		f.tk.Server.URL+"/oidc/auth?"+values.Encode(), http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest /authorize: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: sessionCookie})
	resp, err := f.cl.Do(req)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("authorize status=%d body=%s", resp.StatusCode, dump)
	}
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("authorize Location: %v", err)
	}
	return loc
}

// TestEndToEnd_ChooserPickRunsLoginFlowRule picks a fresh password-only
// sibling for a client a rule guards with a second factor: the rule's
// factor is demanded before any code, and completing it mints one and
// leaves the browser on a record carrying the second factor.
func TestEndToEnd_ChooserPickRunsLoginFlowRule(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	f := newChooserFreshnessFixture(t, sessions.Login{
		Subject:  "user-weak",
		AuthTime: start,
		ACR:      chooserStrongACR,
		AMR:      []string{"pwd"},
	}, chooserLoginFlow(nil))
	ctx := context.Background()
	resp, interactionURL, _, interactionCookie := f.pickSibling(t, url.Values{"prompt": {"select_account"}})
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusFound {
		loc, _ := resp.Location()
		t.Fatalf("the request ended straight after the chooser (%v); the client's rule demands a second factor", loc)
	}
	env := decodeMap(t, resp)
	if got, _ := env["type"].(string); got != secondFactorPromptType {
		t.Fatalf("after the chooser the next prompt was %q; want the rule's %q", got, secondFactorPromptType)
	}
	stateRef, _ := env["state_ref"].(string)
	csrfCookie := findCookie(resp.Cookies(), cookie.CSRFProfile.Name)
	if csrfCookie == nil {
		t.Fatal("csrf cookie missing on the second-factor prompt")
	}
	raw, err := json.Marshal(map[string]any{"state_ref": stateRef, "values": map[string]string{}})
	if err != nil {
		t.Fatalf("marshal second factor: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, interactionURL, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("NewRequest second factor: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", f.tk.Issuer)
	req.Header.Set("X-CSRF-Token", csrfCookie.Value)
	req.AddCookie(csrfCookie)
	req.AddCookie(interactionCookie)
	req.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: f.entry.Cookie})
	factorResp, err := f.cl.Do(req)
	if err != nil {
		t.Fatalf("POST second factor: %v", err)
	}
	defer factorResp.Body.Close()
	final := postConsentWithSessionCookie(t, f.cl, ctx, interactionURL, f.tk.Issuer,
		csrfCookie, interactionCookie, f.entry.Cookie, factorResp)
	defer final.Body.Close()
	if final.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(final.Body)
		t.Fatalf("after the second factor: status=%d body=%s", final.StatusCode, dump)
	}
	loc, err := final.Location()
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	if loc.Query().Get("code") == "" {
		t.Fatalf("the completed second factor minted no code: %s", loc)
	}
	sessCookie := findCookie(final.Cookies(), cookie.SessionProfile.Name)
	if sessCookie == nil {
		t.Fatal("the stepped-up pick set no session cookie")
	}
	active, err := f.mgr.Resolve(ctx, sessCookie.Value)
	if err != nil {
		t.Fatalf("Resolve the session cookie: %v", err)
	}
	if active.Session.Subject != "user-weak" || active.Session.ID == f.sibling.SessionID {
		t.Fatalf("session after the step-up: id=%q subject=%q; want a new user-weak record", active.Session.ID, active.Session.Subject)
	}
	if !containsString(active.Session.AMR, "otp") || !containsString(active.Session.AMR, "pwd") {
		t.Fatalf("session amr after the step-up = %v; want the picked pwd plus the rule's otp", active.Session.AMR)
	}
}

// TestEndToEnd_ChooserPickHonoursDeciderDeny picks a sibling the Decider
// refuses: the request ends with access_denied and no code, as it would
// had the sibling's session been the one the request arrived with.
func TestEndToEnd_ChooserPickHonoursDeciderDeny(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	f := newChooserFreshnessFixture(t, sessions.Login{
		Subject:  "user-refused",
		AuthTime: start,
		ACR:      chooserStrongACR,
		AMR:      []string{"pwd", "otp"},
	}, chooserLoginFlow(denySubject("user-refused")))
	resp, _, _, _ := f.pickSibling(t, url.Values{"prompt": {"select_account"}})
	defer resp.Body.Close()
	requireRedirectError(t, resp, "access_denied")
}

func containsString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
