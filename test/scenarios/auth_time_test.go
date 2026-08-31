package scenarios_test

// Catalog: test/scenarios/catalog/auth_time.yaml (AT-NNN)
// Spec:
//   - OIDC Core 1.0 §2 (ID Token, `auth_time` claim)
//   - OIDC Core 1.0 §3.1.2.1 (`max_age`, `prompt`)
//   - OIDC Core 1.0 §5.5.1.1 (`auth_time` essential claim)
//   - OIDC Registration 1.0 §2 (`require_auth_time`, `default_max_age`)
//
// Every row here asserts a DIFFERENCE between two authorizations rather
// than the presence of the claim. The OP stamps auth_time on every
// interactive login, so "the claim exists" is true for any flow that
// reaches an interaction and would survive the removal of max_age /
// prompt=login / default_max_age handling entirely. What those triggers
// actually decide is whether a seated session is reused or a fresh
// login runs, and the observable consequence of that decision is
// auth_time advancing. The environment therefore pins the OP's clock so
// session staleness is evaluated against a known interval instead of
// real elapsed time.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

const (
	atClientID = "rp-at"
	atCallback = "https://rp.testkit.invalid/callback"
	atSecret   = "rp-at-secret"
	atSubject  = "user-at"
	atScope    = "openid profile"
)

func TestScenario_AT_001_RequestMaxAgeForcesAuthTime(t *testing.T) {
	t.Parallel()
	env := newATEnv(t, nil)

	first := env.login(t, nil)

	// Inside the requested max_age the seated session still counts as
	// fresh, so the OP must serve silently and echo the same auth_time.
	env.clock.advance(500 * time.Second)
	env.assertSilent(t, url.Values{"max_age": {"999"}}, first, "a session younger than max_age")

	// Past it the session is stale and the OP must re-authenticate,
	// which is the only thing that can move auth_time forward.
	env.clock.advance(600 * time.Second)
	env.assertReauthenticated(t, url.Values{"max_age": {"999"}}, first, 1100*time.Second)
}

func TestScenario_AT_002_PromptLoginForcesAuthTime(t *testing.T) {
	t.Parallel()
	env := newATEnv(t, nil)

	first := env.login(t, nil)
	env.clock.advance(60 * time.Second)

	// prompt=login forces a fresh login regardless of session age; the
	// same request without it is served from the session.
	env.assertReauthenticated(t, url.Values{"prompt": {"login"}}, first, 60*time.Second)
	env.assertSilent(t, nil, first.add(60*time.Second), "a request carrying no re-authentication trigger")
}

func TestScenario_AT_003_MaxAgeZeroForcesAuthTime(t *testing.T) {
	t.Parallel()
	env := newATEnv(t, nil)

	first := env.login(t, nil)
	env.clock.advance(60 * time.Second)

	// max_age=0 means "always re-authenticate", so even a session seated
	// one second ago is stale.
	env.assertReauthenticated(t, url.Values{"max_age": {"0"}}, first, 60*time.Second)
	env.assertSilent(t, nil, first.add(60*time.Second), "a request carrying no re-authentication trigger")
}

func TestScenario_AT_004_ClientDefaultMaxAgeZeroForcesAuthTime(t *testing.T) {
	t.Parallel()

	zero := int64(0)
	env := newATEnv(t, func(c *store.Client) { c.DefaultMaxAge = &zero })
	first := env.login(t, nil)
	env.clock.advance(60 * time.Second)

	// The request omits max_age; default_max_age=0 has to supply it.
	env.assertReauthenticated(t, nil, first, 60*time.Second)

	// The identical request against a client without the metadata is
	// served silently, so the re-authentication above is attributable to
	// default_max_age and not to anything else in the flow.
	plain := newATEnv(t, nil)
	plainFirst := plain.login(t, nil)
	plain.clock.advance(60 * time.Second)
	plain.assertSilent(t, nil, plainFirst, "a client without default_max_age")
}

func TestScenario_AT_005_ClientRequireAuthTimeForcesAuthTime(t *testing.T) {
	t.Parallel()

	env := newATEnv(t, func(c *store.Client) { c.RequireAuthTime = true })
	first := env.login(t, nil)
	env.clock.advance(2 * time.Hour)

	// require_auth_time is not a re-authentication trigger: it does not
	// make a seated session stale. What it must do is keep the claim on
	// the id_token issued from that reused session, carrying the instant
	// the user actually authenticated rather than the issuance instant.
	env.assertSilent(t, nil, first, "require_auth_time on its own")

	// And when the OP cannot supply an auth_time at all, a
	// require_auth_time client must be refused rather than served an
	// id_token with the claim quietly omitted. The device_code grant is
	// where an unstamped record is reachable: the substore keeps
	// whatever the verification ceremony wrote.
	t.Run("unstampable auth_time is refused", func(t *testing.T) {
		t.Parallel()
		p := newDevProvider(t, []string{"openid"})
		p.client.RequireAuthTime = true
		if err := p.tk.Store.UpdateClient(context.Background(), p.client); err != nil {
			t.Fatalf("UpdateClient: %v", err)
		}

		deviceCode := p.issueDeviceCode(t, "openid")
		p.approveDeviceCodeAt(t, deviceCode, devDefaultSubject, time.Time{})
		status, body := p.tokenForm(t, url.Values{
			"grant_type":  {devURNDeviceCode},
			"device_code": {deviceCode},
		})
		if status != http.StatusInternalServerError {
			t.Fatalf("/token status=%d want 500 for a require_auth_time client with no auth_time: %v", status, body)
		}
		if got, _ := body["error"].(string); got != "server_error" {
			t.Errorf("error=%q want server_error", got)
		}
	})
}

func TestScenario_AT_006_ClientDefaultMaxAgePositiveForcesAuthTime(t *testing.T) {
	t.Parallel()

	maxAge := int64(3600)
	env := newATEnv(t, func(c *store.Client) { c.DefaultMaxAge = &maxAge })
	first := env.login(t, nil)

	// Below the metadata ceiling the session is still fresh.
	env.clock.advance(1800 * time.Second)
	env.assertSilent(t, nil, first, "a session younger than default_max_age")

	// Above it the OP must re-authenticate even though the request
	// carries neither max_age nor prompt.
	env.clock.advance(3600 * time.Second)
	env.assertReauthenticated(t, nil, first, 5400*time.Second)
}

// TestScenario_AT_007_DeviceCodeIDTokenCarriesAuthTime pins the
// device-code id_token's auth_time claim. Approve stamps a wall-
// clock value onto the substore record; the token endpoint reads
// it back and emits the claim on the issued id_token.
func TestScenario_AT_007_DeviceCodeIDTokenCarriesAuthTime(t *testing.T) {
	t.Parallel()
	p := newDevProvider(t, []string{"openid"})

	deviceCode := p.issueDeviceCode(t, "openid")
	authTime := time.Date(2026, 5, 5, 12, 30, 0, 0, time.UTC)
	p.approveDeviceCodeAt(t, deviceCode, devDefaultSubject, authTime)

	_, body := p.tokenForm(t, url.Values{
		"grant_type":  {devURNDeviceCode},
		"device_code": {deviceCode},
	})
	idToken, _ := body["id_token"].(string)
	if idToken == "" {
		t.Fatalf("id_token missing: %v", body)
	}
	claims := decodeScenarioJWTClaims(t, idToken)
	got, ok := claims["auth_time"].(float64)
	if !ok {
		t.Fatalf("auth_time absent or wrong type: %v", claims["auth_time"])
	}
	if int64(got) != authTime.Unix() {
		t.Errorf("auth_time = %d, want %d", int64(got), authTime.Unix())
	}
}

// TestScenario_AT_008_CIBAIDTokenCarriesAuthTime is the CIBA
// counterpart of AT-007, and marks where the scenario-level test would
// go. CIBA's helper exposes no public approve hook the suite can call,
// so the row names its own coverage in `covered_by` and the gate
// resolves that name; a copy of the name here would only rot.
func TestScenario_AT_008_CIBAIDTokenCarriesAuthTime(t *testing.T) {
	t.Parallel()
	t.Skip("covered outside the suite; see the auth_time catalog row's covered_by")
}

// atClock is the mutable clock the AT environment hands to the OP.
// Rows advance it explicitly between authorizations so a session's age
// — the input every max_age decision reads — is exact, and so no row
// depends on how long the suite happens to take.
type atClock struct {
	mu  sync.Mutex
	now time.Time
}

func newATClock() *atClock {
	return &atClock{now: time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)}
}

func (c *atClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *atClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// atAuthTime is one observed auth_time claim, kept as its own type so a
// row cannot accidentally compare an epoch second against a duration.
type atAuthTime int64

func (a atAuthTime) add(d time.Duration) atAuthTime {
	return a + atAuthTime(d/time.Second)
}

// atEnv drives repeated authorizations for one browser identity against
// one client, on a clock the row controls.
type atEnv struct {
	tk     *testkit.Provider
	clock  *atClock
	client *http.Client
	pkce   scenariokit.PKCEPair
}

// newATEnv registers a confidential client and seats an empty cookie
// jar. mutate, when non-nil, applies the client metadata under test
// (default_max_age / require_auth_time) before any authorization runs.
func newATEnv(t *testing.T, mutate func(*store.Client)) *atEnv {
	t.Helper()

	hash, err := op.HashClientSecret(atSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	clock := newATClock()
	tk := testkit.NewProvider(t, testkit.WithClock(clock))
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      atClientID,
		SecretHash:              hash,
		RedirectURIs:            []string{atCallback},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	if mutate != nil {
		mutate(rp)
		if err := tk.Store.UpdateClient(context.Background(), rp); err != nil {
			t.Fatalf("UpdateClient: %v", err)
		}
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	return &atEnv{tk: tk, clock: clock, client: tk.HTTPClient(jar), pkce: scenariokit.NewPKCEPair("")}
}

// login runs the first authorization, which necessarily interacts
// because no session is seated yet, and returns its auth_time.
func (e *atEnv) login(t *testing.T, extra url.Values) atAuthTime {
	t.Helper()
	code, interacted := e.authorize(t, extra)
	if !interacted {
		t.Fatal("the first authorization must run an interaction: no session is seated yet")
	}
	return e.authTime(t, code)
}

// assertReauthenticated requires the authorization to run a fresh login
// and to report an auth_time that advanced by exactly the interval the
// row moved the clock. Both halves matter: the interaction proves the
// trigger was honoured, and the value proves the claim tracks the new
// authentication rather than being copied from the old session.
func (e *atEnv) assertReauthenticated(t *testing.T, extra url.Values, baseline atAuthTime, elapsed time.Duration) {
	t.Helper()
	code, interacted := e.authorize(t, extra)
	if !interacted {
		t.Fatalf("%v must force re-authentication, but the request was served from the session", extra)
	}
	got := e.authTime(t, code)
	if want := baseline.add(elapsed); got != want {
		t.Errorf("auth_time = %d, want %d (baseline %d advanced by %s)", got, want, baseline, elapsed)
	}
}

// assertSilent is the negative half: the OP must reuse the session and
// echo the baseline auth_time unchanged. Without it a row would pass
// against an OP that re-authenticates on every request, which honours
// no trigger in particular.
func (e *atEnv) assertSilent(t *testing.T, extra url.Values, baseline atAuthTime, because string) {
	t.Helper()
	code, interacted := e.authorize(t, extra)
	if interacted {
		t.Fatalf("%s must be served from the seated session, but the OP re-authenticated", because)
	}
	if got := e.authTime(t, code); got != baseline {
		t.Errorf("auth_time = %d, want the seated session's %d unchanged", got, baseline)
	}
}

// authorize drives one /authorize round-trip on the shared cookie jar.
// interacted reports whether the OP started a login interaction rather
// than serving the request from the seated session.
func (e *atEnv) authorize(t *testing.T, extra url.Values) (string, bool) {
	t.Helper()
	v := url.Values{
		"client_id":             {atClientID},
		"response_type":         {"code"},
		"redirect_uri":          {atCallback},
		"scope":                 {atScope},
		"state":                 {"state-at"},
		"nonce":                 {"nonce-at"},
		"code_challenge":        {e.pkce.Challenge},
		"code_challenge_method": {e.pkce.Method},
	}
	for k, vs := range extra {
		v[k] = append([]string(nil), vs...)
	}
	resp := e.mustGet(t, e.tk.Server.URL+"/oidc/auth?"+v.Encode())
	if resp.StatusCode != http.StatusFound {
		_ = resp.Body.Close()
		t.Fatalf("/authorize status=%d want 302", resp.StatusCode)
	}
	loc, err := resp.Location()
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("/authorize Location: %v", err)
	}
	if code := atCallbackCode(t, loc); code != "" {
		return code, false
	}
	if !strings.HasPrefix(loc.Path, "/oidc/interaction/") {
		t.Fatalf("/authorize Location=%s want callback or interaction", loc.String())
	}
	return e.completeInteraction(t, e.tk.Server.URL+loc.Path), true
}

func (e *atEnv) completeInteraction(t *testing.T, interactionURL string) string {
	t.Helper()
	stepResp := e.mustGet(t, interactionURL)
	step := decodeStepUpJSON(t, stepResp)
	stateRef, _ := step["state_ref"].(string)
	csrf := findStepUpCookie(stepResp.Cookies(), "__Host-oidc_csrf")
	_ = stepResp.Body.Close()
	if stateRef == "" || csrf == nil {
		t.Fatalf("interaction prompt missing state_ref/csrf: %v", step)
	}
	postResp := e.postInteraction(t, interactionURL, csrf.Value, stateRef,
		map[string]string{testkit.SubjectFieldName: atSubject})

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
	defer func() { _ = finalResp.Body.Close() }()
	if finalResp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(finalResp.Body)
		t.Fatalf("interaction final status=%d body=%s", finalResp.StatusCode, string(body))
	}
	loc, err := finalResp.Location()
	if err != nil {
		t.Fatalf("final Location: %v", err)
	}
	code := atCallbackCode(t, loc)
	if code == "" {
		t.Fatalf("no code in callback %s", loc.String())
	}
	return code
}

// authTime exchanges code and returns the id_token's auth_time claim.
// A missing or non-numeric claim fails the test: every row here runs
// with scope openid against a flow that authenticated a user, so the
// claim's absence is a regression rather than the encoder's
// omit-on-zero path.
func (e *atEnv) authTime(t *testing.T, code string) atAuthTime {
	t.Helper()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {atCallback},
		"code_verifier": {e.pkce.Verifier},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		e.tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(atClientID, atSecret)
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
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
	claims := decodeScenarioJWTClaims(t, idt)
	got, ok := claims["auth_time"].(float64)
	if !ok {
		t.Fatalf("auth_time absent or not numeric: %v (%T)", claims["auth_time"], claims["auth_time"])
	}
	return atAuthTime(got)
}

func (e *atEnv) mustGet(t *testing.T, rawURL string) *http.Response {
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

func (e *atEnv) postInteraction(t *testing.T, interactionURL, csrf, stateRef string, values map[string]string) *http.Response {
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

func atCallbackCode(t *testing.T, loc *url.URL) string {
	t.Helper()
	want, err := url.Parse(atCallback)
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

func decodeScenarioJWTClaims(tb testing.TB, jws string) map[string]any {
	tb.Helper()
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		tb.Fatalf("jwt has %d parts, want 3", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		tb.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		tb.Fatalf("unmarshal claims: %v", err)
	}
	return claims
}
