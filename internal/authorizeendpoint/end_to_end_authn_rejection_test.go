package authorizeendpoint_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// promptStep is one rendered prompt: its envelope, the state_ref to
// answer it with, and the CSRF token bound to it.
type promptStep struct {
	env      map[string]any
	stateRef string
	csrf     string
}

// nextPrompt decodes a 200 prompt response, carrying the CSRF token
// forward unless the response rotated it.
func nextPrompt(t *testing.T, resp *http.Response, csrf string) promptStep {
	t.Helper()
	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s, want a prompt", resp.StatusCode, dump)
	}
	if rotated := findCookie(resp.Cookies(), "__Host-oidc_csrf"); rotated != nil {
		csrf = rotated.Value
	}
	env := decodeMap(t, resp)
	ref, _ := env["state_ref"].(string)
	if ref == "" {
		t.Fatalf("prompt without state_ref: %v", env)
	}
	return promptStep{env: env, stateRef: ref, csrf: csrf}
}

// TestEndToEnd_ConsentRejectionIsClientError pins that a consent
// submission the built-in consent screen refuses — an unrequested scope,
// a missing approved_scopes field, a declined required scope — is
// answered with a 400 on both login surfaces, never a 500.
func TestEndToEnd_ConsentRejectionIsClientError(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		values map[string]string
	}{
		{name: "unrequested scope", values: map[string]string{"approved_scopes": "openid profile email"}},
		{name: "approved_scopes absent", values: map[string]string{}},
		{name: "required scope declined", values: map[string]string{"approved_scopes": "openid"}},
	}
	for _, surface := range []authnSurface{surfaceLoginFlow, surfaceAuthenticators} {
		for _, tc := range cases {
			t.Run(surface.String()+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				clock := newMovableClock(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
				fix := newFlowFixture(t, surface, clock,
					op.WithScope(op.Scope{Name: "profile", Required: true, Public: true}))
				d := newReauthDriver(t, fix)

				login := d.authorize(url.Values{"scope": {"openid profile"}})
				env, csrf := d.firstPrompt(login.Path)
				ref, _ := env["state_ref"].(string)
				resp := d.submit(login.Path, csrf, ref, map[string]string{testkit.SubjectFieldName: reauthSubject})
				defer resp.Body.Close()
				consent := nextPrompt(t, resp, csrf)
				if got, _ := consent.env["type"].(string); got != "consent.scope" {
					t.Fatalf("prompt after the credential = %q, want consent.scope", got)
				}

				rejected := d.submit(login.Path, consent.csrf, consent.stateRef, tc.values)
				defer rejected.Body.Close()
				if rejected.StatusCode != http.StatusBadRequest {
					dump, _ := io.ReadAll(rejected.Body)
					t.Fatalf("consent rejection: status=%d body=%s, want 400", rejected.StatusCode, dump)
				}
			})
		}
	}
}

// rejectingCaptcha refuses the first reject tokens it sees and accepts
// the rest; a negative reject refuses every token.
type rejectingCaptcha struct {
	reject int32
	seen   atomic.Int32
}

func (c *rejectingCaptcha) Verify(context.Context, op.CaptchaInput) error {
	if n := c.seen.Add(1); c.reject < 0 || n <= c.reject {
		return errors.New("captcha provider rejected the token")
	}
	return nil
}

// TestEndToEnd_StepCaptchaRejectionReissuesChallenge pins the StepCaptcha
// failure path under op.WithLoginFlow: a rejected token re-issues the
// challenge rather than failing the request, a later good token moves on
// to the credential prompt, and a verifier that never accepts ends the
// attempt with a 400 once the failure budget is spent.
func TestEndToEnd_StepCaptchaRejectionReissuesChallenge(t *testing.T) {
	t.Parallel()

	build := func(t *testing.T, verifier op.CaptchaVerifier) (*reauthDriver, *url.URL, promptStep) {
		t.Helper()
		clock := newMovableClock(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
		flow := op.WithLoginFlow(op.LoginFlow{
			Primary: op.ExternalStep{
				Authenticator: passwordEchoAuthenticator{clock: clock},
				KindLabel:     op.StepKind("test.primary"),
			},
			Rules: []op.Rule{op.RuleAlways(op.StepCaptcha{Verifier: verifier})},
		})
		d := newReauthDriver(t, buildFlowFixture(t, "LoginFlow+StepCaptcha", clock, flow))
		login := d.authorize(url.Values{"scope": {"openid"}})
		env, csrf := d.firstPrompt(login.Path)
		if got, _ := env["type"].(string); got != "captcha" {
			t.Fatalf("first prompt = %q, want captcha", got)
		}
		ref, _ := env["state_ref"].(string)
		return d, login, promptStep{env: env, stateRef: ref, csrf: csrf}
	}
	token := map[string]string{op.CaptchaSubmissionFieldName: "token"}

	t.Run("rejected then accepted", func(t *testing.T) {
		t.Parallel()
		d, login, challenge := build(t, &rejectingCaptcha{reject: 1})

		resp := d.submit(login.Path, challenge.csrf, challenge.stateRef, token)
		defer resp.Body.Close()
		again := nextPrompt(t, resp, challenge.csrf)
		if got, _ := again.env["type"].(string); got != "captcha" {
			t.Fatalf("prompt after a rejected token = %q, want a fresh captcha", got)
		}
		if again.stateRef == challenge.stateRef {
			t.Fatal("the re-issued challenge reuses the rejected state_ref")
		}

		resp = d.submit(login.Path, again.csrf, again.stateRef, token)
		defer resp.Body.Close()
		next := nextPrompt(t, resp, again.csrf)
		if got, _ := next.env["type"].(string); got != testkit.SubjectPromptType {
			t.Fatalf("prompt after an accepted token = %q, want %q", got, testkit.SubjectPromptType)
		}
	})

	t.Run("budget exhausted", func(t *testing.T) {
		t.Parallel()
		d, login, challenge := build(t, &rejectingCaptcha{reject: -1})

		for i := 1; ; i++ {
			resp := d.submit(login.Path, challenge.csrf, challenge.stateRef, token)
			if resp.StatusCode == http.StatusOK {
				challenge = nextPrompt(t, resp, challenge.csrf)
				resp.Body.Close()
				if i > 10 {
					t.Fatal("the challenge is still re-issued after 10 rejected tokens")
				}
				continue
			}
			dump, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("rejection %d: status=%d body=%s, want 400", i, resp.StatusCode, dump)
			}
			return
		}
	})
}

// TestEndToEnd_ChooserForeignSessionIsClientError pins that a chooser
// submission naming a session outside the active chooser group — a stale
// or foreign session_id — is answered with a 400, not a 500.
func TestEndToEnd_ChooserForeignSessionIsClientError(t *testing.T) {
	t.Parallel()
	clock := &monotonicChooserClock{now: time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC), step: time.Microsecond}
	cookieKey := []byte(chooserCookieKey)
	tk := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(op.WithCookieKeys(cookieKey)),
	)
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash("rp-secret")
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "rp-chooser-foreign",
		SecretHash:              hash,
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	mgr, _ := newChooserSessionsManager(t, tk.Store.Sessions(), cookieKey, clock)
	own := establishFresh(t, mgr, sessions.Login{Subject: "user-A", AuthTime: clock.Current()}, clock.Current())
	foreign := establishFresh(t, mgr, sessions.Login{Subject: "user-C", AuthTime: clock.Current()}, clock.Current())
	sessionCookie := &http.Cookie{Name: cookie.SessionProfile.Name, Value: own.Cookie}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	client := tk.HTTPClient(jar)
	values := e2eAuthorizeValues(rp.ID, rp.RedirectURIs[0])
	values.Set("prompt", "select_account")
	get := func(target string, cookies ...*http.Cookie) *http.Response {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, http.NoBody)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		for _, c := range cookies {
			req.AddCookie(c)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", target, err)
		}
		return resp
	}

	authResp := get(tk.Server.URL+"/oidc/auth?"+values.Encode(), sessionCookie)
	authResp.Body.Close()
	loc, err := authResp.Location()
	if err != nil {
		t.Fatalf("authorize status=%d: %v", authResp.StatusCode, err)
	}
	interactionURL := tk.Server.URL + loc.Path
	interactionCookie := findCookie(authResp.Cookies(), cookie.InteractionProfile.Name)
	if interactionCookie == nil {
		t.Fatalf("authorize redirected to %s, want the interaction", loc)
	}

	stepResp := get(interactionURL, sessionCookie, interactionCookie)
	defer stepResp.Body.Close()
	chooser := nextPrompt(t, stepResp, "")
	if got, _ := chooser.env["type"].(string); got != "interaction.chooser" {
		t.Fatalf("prompt type = %q, want interaction.chooser", got)
	}

	raw, err := json.Marshal(map[string]any{
		"state_ref": chooser.stateRef,
		"values":    map[string]string{"session_id": foreign.SessionID},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	csrf := &http.Cookie{Name: cookie.CSRFProfile.Name, Value: chooser.csrf}
	post, err := http.NewRequestWithContext(context.Background(), http.MethodPost, interactionURL, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	post.Header.Set("Content-Type", "application/json")
	post.Header.Set("Origin", tk.Issuer)
	post.Header.Set("X-CSRF-Token", chooser.csrf)
	for _, c := range []*http.Cookie{csrf, interactionCookie, sessionCookie} {
		post.AddCookie(c)
	}
	resp, err := client.Do(post)
	if err != nil {
		t.Fatalf("POST chooser: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("foreign session_id: status=%d body=%s, want 400", resp.StatusCode, dump)
	}
}
