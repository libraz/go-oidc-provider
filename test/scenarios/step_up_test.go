package scenarios_test

// Catalog: test/scenarios/catalog/step_up.yaml (SUP-NNN)
// Spec:
//   - RFC 9470 §3 (insufficient_user_authentication challenge)
//   - RFC 9470 §4 (acr_values / max_age re-authentication)
//   - OIDC Core 1.0 §3.1.2.1 (acr_values, max_age, prompt)

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

const (
	supClientID = "rp-sup"
	supCallback = "https://rp.testkit.invalid/callback"
	supSecret   = "rp-sup-secret" //nolint:gosec // test fixture: not a real credential.
	supSubject  = "user-stepup"
	supScope    = "openid profile"
)

// TestScenario_SUP_001_MaxAgeZeroForcesReauthentication drives a first
// login to seat a session, then a second authorization with max_age=0.
// RFC 9470 §4: the OP must re-authenticate rather than reuse the session,
// and the issued ID Token carries an auth_time for the fresh login.
func TestScenario_SUP_001_MaxAgeZeroForcesReauthentication(t *testing.T) {
	t.Parallel()
	env := newSUPEnv(t)

	// First login seats the session + grant.
	code, interacted := env.authorize(t, nil)
	if !interacted {
		t.Fatal("first login should run an interaction")
	}
	env.exchange(t, code)

	// max_age=0 against the seated session must force a fresh login.
	code, interacted = env.authorize(t, url.Values{"max_age": {"0"}})
	if !interacted {
		t.Fatal("max_age=0 must force re-authentication, but the request was served silently")
	}
	claims := env.exchange(t, code)
	if _, ok := claims["auth_time"]; !ok {
		t.Errorf("auth_time missing from stepped-up id_token: %v", claims)
	}
}

// TestScenario_SUP_002_MaxAgeExpiryForcesReauthentication marks where
// the scenario-level test would go. Aging a session past a positive
// max_age requires a controllable clock the black-box flow harness does
// not seat, so the row names its own coverage in `covered_by` and the
// gate resolves that name; repeating it here would be a second copy
// nothing checks.
func TestScenario_SUP_002_MaxAgeExpiryForcesReauthentication(t *testing.T) {
	t.Parallel()
	t.Skip("covered outside the suite; see the step_up catalog row's covered_by")
}

// TestScenario_SUP_003_ACRUnsatisfiedForcesStepUp seats a session at acr
// "1", then requests acr_values=2. RFC 9470 §3/§4: the session no longer
// satisfies the requested context, so the OP re-authenticates and the
// issued ID Token's acr equals the stepped-up value.
func TestScenario_SUP_003_ACRUnsatisfiedForcesStepUp(t *testing.T) {
	t.Parallel()
	env := newSUPEnv(t)

	code, interacted := env.authorize(t, url.Values{"acr_values": {"1"}})
	if !interacted {
		t.Fatal("first login should run an interaction")
	}
	if got, _ := env.exchange(t, code)["acr"].(string); got != "1" {
		t.Fatalf("first id_token acr=%q want 1", got)
	}

	code, interacted = env.authorize(t, url.Values{"acr_values": {"2"}})
	if !interacted {
		t.Fatal("acr_values=2 unsatisfied by the acr-1 session must force a step-up interaction")
	}
	if got, _ := env.exchange(t, code)["acr"].(string); got != "2" {
		t.Errorf("stepped-up id_token acr=%q want 2", got)
	}
}

// TestScenario_SUP_004_ChallengeHelperShape pins the resource-server
// challenge string the public helper builds (RFC 9470 §3): mandatory
// error code, optional realm first, acr_values space-delimited, max_age
// rendered as a number, all quoted in canonical order.
func TestScenario_SUP_004_ChallengeHelperShape(t *testing.T) {
	t.Parallel()

	if got := op.StepUpChallenge("", nil, nil); got != `Bearer error="insufficient_user_authentication"` {
		t.Errorf("bare challenge = %q", got)
	}
	maxAge := int64(300)
	got := op.StepUpChallenge("api", []string{"urn:acr:high", "urn:acr:mfa"}, &maxAge)
	want := `Bearer realm="api", error="insufficient_user_authentication", ` +
		`acr_values="urn:acr:high urn:acr:mfa", max_age="300"`
	if got != want {
		t.Errorf("full challenge\n got: %s\nwant: %s", got, want)
	}
}

// TestScenario_SUP_005_SatisfiedSessionServedSilently seats a session at
// acr "1" then re-requests acr_values=1. RFC 9470 §4: the session already
// satisfies the request, so no new interaction runs and the ID Token
// echoes the satisfied acr.
func TestScenario_SUP_005_SatisfiedSessionServedSilently(t *testing.T) {
	t.Parallel()
	env := newSUPEnv(t)

	code, interacted := env.authorize(t, url.Values{"acr_values": {"1"}})
	if !interacted {
		t.Fatal("first login should run an interaction")
	}
	env.exchange(t, code)

	code, interacted = env.authorize(t, url.Values{"acr_values": {"1"}})
	if interacted {
		t.Fatal("a session already satisfying acr_values=1 must be served silently")
	}
	if got, _ := env.exchange(t, code)["acr"].(string); got != "1" {
		t.Errorf("silently-served id_token acr=%q want 1", got)
	}
}

// supEnv bundles a provider, a registered confidential client, and a
// cookie-jar-backed HTTP client so a scenario can drive two authorize
// round-trips against the same persisted session.
type supEnv struct {
	tk     *testkit.Provider
	client *http.Client
	pkce   scenariokit.PKCEPair
}

func newSUPEnv(t *testing.T) *supEnv {
	t.Helper()
	hash, err := op.HashClientSecret(supSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	tk := testkit.NewProvider(t)
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      supClientID,
		SecretHash:              hash,
		RedirectURIs:            []string{supCallback},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	return &supEnv{tk: tk, client: tk.HTTPClient(jar), pkce: scenariokit.NewPKCEPair("")}
}

// authorize drives one /authorize round-trip with the shared cookie jar.
// When the OP serves the request silently it returns the callback code
// with interacted=false; when it starts an interaction the helper
// completes the login as supSubject (approving consent when prompted) and
// returns the resulting code with interacted=true.
func (e *supEnv) authorize(t *testing.T, extra url.Values) (string, bool) {
	t.Helper()
	v := url.Values{
		"client_id":             {supClientID},
		"response_type":         {"code"},
		"redirect_uri":          {supCallback},
		"scope":                 {supScope},
		"state":                 {"state-sup"},
		"nonce":                 {"nonce-sup"},
		"code_challenge":        {e.pkce.Challenge},
		"code_challenge_method": {e.pkce.Method},
	}
	for k, vs := range extra {
		v[k] = append([]string(nil), vs...)
	}
	resp := e.mustGet(t, e.tk.Server.URL+"/oidc/auth?"+v.Encode())
	if resp.StatusCode != http.StatusFound {
		resp.Body.Close()
		t.Fatalf("/authorize status=%d want 302", resp.StatusCode)
	}
	loc, err := resp.Location()
	resp.Body.Close()
	if err != nil {
		t.Fatalf("/authorize Location: %v", err)
	}
	if code := callbackCode(t, loc); code != "" {
		return code, false
	}
	if !strings.HasPrefix(loc.Path, "/oidc/interaction/") {
		t.Fatalf("/authorize Location=%s want callback or interaction", loc.String())
	}
	return e.completeInteraction(t, e.tk.Server.URL+loc.Path), true
}

func (e *supEnv) completeInteraction(t *testing.T, interactionURL string) string {
	t.Helper()
	stepResp := e.mustGet(t, interactionURL)
	step := decodeStepUpJSON(t, stepResp)
	stateRef, _ := step["state_ref"].(string)
	csrf := findStepUpCookie(stepResp.Cookies(), "__Host-oidc_csrf")
	stepResp.Body.Close()
	if stateRef == "" || csrf == nil {
		t.Fatalf("interaction prompt missing state_ref/csrf: %v", step)
	}
	postResp := e.postInteraction(t, interactionURL, csrf.Value, stateRef,
		map[string]string{testkit.SubjectFieldName: supSubject})

	consent, env, err := testkit.IsConsentPrompt(postResp)
	if err != nil {
		t.Fatalf("inspect consent prompt: %v", err)
	}
	finalResp := postResp
	if consent {
		consentRef, _ := env["state_ref"].(string)
		// The CSRF cookie rotates on every step boundary; pull the
		// rotated value off the consent prompt response.
		if rotated := findStepUpCookie(postResp.Cookies(), "__Host-oidc_csrf"); rotated != nil {
			csrf = rotated
		}
		finalResp = testkit.PostConsentApproval(t, e.client, interactionURL, e.tk.Issuer,
			csrf.Value, consentRef, approvedStepUpScopes(env))
	}
	defer finalResp.Body.Close()
	if finalResp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(finalResp.Body)
		t.Fatalf("interaction final status=%d body=%s", finalResp.StatusCode, string(body))
	}
	loc, err := finalResp.Location()
	if err != nil {
		t.Fatalf("final Location: %v", err)
	}
	code := callbackCode(t, loc)
	if code == "" {
		t.Fatalf("no code in callback %s", loc.String())
	}
	return code
}

func (e *supEnv) exchange(t *testing.T, code string) map[string]any {
	t.Helper()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {supCallback},
		"code_verifier": {e.pkce.Verifier},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		e.tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(supClientID, supSecret)
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("/token status=%d body=%s", resp.StatusCode, string(body))
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	idt, _ := out["id_token"].(string)
	if idt == "" {
		t.Fatalf("id_token missing: %v", out)
	}
	return decodeScenarioJWTClaims(t, idt)
}

func (e *supEnv) mustGet(t *testing.T, rawURL string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		t.Fatalf("build GET %s: %v", rawURL, err)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	return resp
}

func (e *supEnv) postInteraction(t *testing.T, interactionURL, csrf, stateRef string, values map[string]string) *http.Response {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"state_ref": stateRef, "values": values})
	if err != nil {
		t.Fatalf("marshal interaction body: %v", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, interactionURL, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("build interaction POST: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", e.tk.Issuer)
	req.Header.Set("X-CSRF-Token", csrf)
	req.AddCookie(&http.Cookie{Name: "__Host-oidc_csrf", Value: csrf})
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("POST interaction: %v", err)
	}
	return resp
}

func callbackCode(t *testing.T, loc *url.URL) string {
	t.Helper()
	want, err := url.Parse(supCallback)
	if err != nil {
		t.Fatalf("parse callback: %v", err)
	}
	if loc.Scheme != want.Scheme || loc.Host != want.Host || loc.Path != want.Path {
		return ""
	}
	if errCode := loc.Query().Get("error"); errCode != "" {
		t.Fatalf("authorize error on callback: %s (%s)", errCode, loc.Query().Get("error_description"))
	}
	return loc.Query().Get("code")
}

func decodeStepUpJSON(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	out := map[string]any{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode interaction prompt: %v", err)
	}
	return out
}

func findStepUpCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func approvedStepUpScopes(env map[string]any) string {
	data, _ := env["data"].(map[string]any)
	scopesAny, _ := data["Scopes"].([]any)
	out := make([]string, 0, len(scopesAny))
	for _, s := range scopesAny {
		entry, _ := s.(map[string]any)
		if name, _ := entry["Name"].(string); name != "" {
			out = append(out, name)
		}
	}
	return strings.Join(out, " ")
}
