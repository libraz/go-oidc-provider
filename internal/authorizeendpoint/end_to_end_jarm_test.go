package authorizeendpoint_test

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
	"time"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// jarmCanonicalAudience is the client_id every JARM e2e row registers
// against. Pinning the value keeps the audience assertion readable.
const jarmCanonicalAudience = "rp-jarm"

// jarmAuthorizeValues returns the canonical happy-path query parameters
// for a JARM /authorize request, with the response_mode parameter set
// to mode.
func jarmAuthorizeValues(clientID, redirectURI, mode string) url.Values {
	v := e2eAuthorizeValues(clientID, redirectURI)
	v.Set("response_mode", mode)
	return v
}

// jarmHarness wires a testkit Provider that has the JARM feature flag
// enabled and registers a single client. Tests reuse the harness across
// the three response_mode rows.
type jarmHarness struct {
	tk           *testkit.Provider
	rpID         string
	rpSecret     string
	redirectURI  string
	httpClient   *http.Client
	clock        fakeClock
	publicJWKKey *josev4.JSONWebKey
}

func newJARMHarness(t *testing.T, opts ...testkit.Option) *jarmHarness {
	t.Helper()

	clock := fakeClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	options := append([]testkit.Option{
		testkit.WithClock(clock),
	}, opts...)
	options = append(options, testkit.WithOptions(op.WithFeature(feature.JARM)))
	tk := testkit.NewProvider(t, options...)

	const secret = "rp-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      jarmCanonicalAudience,
		SecretHash:              hash,
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	httpClient := &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	pub := josev4.JSONWebKey{
		Key:       tk.SigningKey.Signer.Public(),
		KeyID:     tk.SigningKey.KeyID,
		Algorithm: string(josev4.ES256),
		Use:       "sig",
	}
	return &jarmHarness{
		tk:           tk,
		rpID:         rp.ID,
		rpSecret:     secret,
		redirectURI:  rp.RedirectURIs[0],
		httpClient:   httpClient,
		clock:        clock,
		publicJWKKey: &pub,
	}
}

// runHappyPathInteraction drives /authorize → /interaction → terminal
// success POST. The terminal hop returns the response from the OP — a
// 302 redirect carrying the JARM JWT or, for form_post.jwt, a 200 with
// an HTML body.
func (h *jarmHarness) runHappyPathInteraction(t *testing.T, mode string) *http.Response {
	t.Helper()

	authorizeURL := h.tk.Server.URL + "/oidc/auth?" +
		jarmAuthorizeValues(h.rpID, h.redirectURI, mode).Encode()
	authResp, err := newGet(authorizeURL).Do(h.httpClient)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer authResp.Body.Close()
	if authResp.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(authResp.Body)
		t.Fatalf("authorize status=%d body=%s", authResp.StatusCode, string(dump))
	}
	location, err := authResp.Location()
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	if !strings.HasPrefix(location.Path, "/oidc/interaction/") {
		t.Fatalf("Location=%s", location.String())
	}
	stepResp, err := newGet(h.tk.Server.URL + location.Path).Do(h.httpClient)
	if err != nil {
		t.Fatalf("GET interaction: %v", err)
	}
	defer stepResp.Body.Close()
	step := decodeMap(t, stepResp)
	stateRef, _ := step["state_ref"].(string)
	if stateRef == "" {
		t.Fatal("state_ref missing from step body")
	}
	csrfCookie := findCookie(stepResp.Cookies(), "__Host-oidc_csrf")
	if csrfCookie == nil {
		t.Fatal("csrf cookie missing")
	}
	body := map[string]any{
		"state_ref": stateRef,
		"values":    map[string]string{"subject": "user-1"},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	postReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		h.tk.Server.URL+location.Path, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("NewRequest POST: %v", err)
	}
	postReq.Header.Set("Content-Type", "application/json")
	postReq.Header.Set("Origin", h.tk.Issuer)
	postReq.Header.Set("X-CSRF-Token", csrfCookie.Value)
	postReq.AddCookie(csrfCookie)
	postResp, err := h.httpClient.Do(postReq)
	if err != nil {
		t.Fatalf("POST interaction: %v", err)
	}
	return postResp
}

// verifyJARMClaims validates the signature against the OP's JWK and
// returns the verified claim map. It fails the test on any mismatch.
func (h *jarmHarness) verifyJARMClaims(t *testing.T, raw string) map[string]any {
	t.Helper()

	parsed, err := jwt.ParseSigned(raw, []josev4.SignatureAlgorithm{josev4.ES256})
	if err != nil {
		t.Fatalf("ParseSigned: %v", err)
	}
	out := map[string]any{}
	if err := parsed.Claims(h.publicJWKKey.Key, &out); err != nil {
		t.Fatalf("Claims (signature verify): %v", err)
	}
	if got := out["iss"]; got != h.tk.Issuer {
		t.Errorf("iss=%v want %s", got, h.tk.Issuer)
	}
	if got := out["aud"]; got != h.rpID {
		t.Errorf("aud=%v want %s", got, h.rpID)
	}
	return out
}

func TestEndToEnd_JARM_QueryJWT_Success(t *testing.T) {
	t.Parallel()

	h := newJARMHarness(t)
	resp := h.runHappyPathInteraction(t, "query.jwt")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, string(dump))
	}
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	rawJWT := loc.Query().Get("response")
	if rawJWT == "" {
		t.Fatalf("response missing in %s", loc.String())
	}
	if loc.Query().Get("code") != "" {
		t.Errorf("legacy 'code' parameter leaked: %s", loc.String())
	}
	claims := h.verifyJARMClaims(t, rawJWT)
	if got := claims["code"]; got == "" || got == nil {
		t.Errorf("code claim missing: %v", claims)
	}
	if got := claims["state"]; got != "state-abc" {
		t.Errorf("state=%v want state-abc", got)
	}
	if _, hasErr := claims["error"]; hasErr {
		t.Errorf("error claim present on success path: %v", claims)
	}
}

func TestEndToEnd_JARM_FragmentJWT_Success(t *testing.T) {
	t.Parallel()

	h := newJARMHarness(t)
	resp := h.runHappyPathInteraction(t, "fragment.jwt")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	// resp.Location() drops the fragment, so parse the raw header.
	loc := resp.Header.Get("Location")
	if loc == "" {
		t.Fatal("Location header missing")
	}
	hashIdx := strings.Index(loc, "#")
	if hashIdx < 0 {
		t.Fatalf("no fragment in Location=%s", loc)
	}
	frag := loc[hashIdx+1:]
	values, err := url.ParseQuery(frag)
	if err != nil {
		t.Fatalf("ParseQuery(%q): %v", frag, err)
	}
	rawJWT := values.Get("response")
	if rawJWT == "" {
		t.Fatalf("response missing in %s", loc)
	}
	claims := h.verifyJARMClaims(t, rawJWT)
	if got := claims["code"]; got == nil || got == "" {
		t.Errorf("code missing: %v", claims)
	}
}

func TestEndToEnd_JARM_FormPostJWT_Success(t *testing.T) {
	t.Parallel()

	h := newJARMHarness(t)
	resp := h.runHappyPathInteraction(t, "form_post.jwt")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, string(dump))
	}
	if got := resp.Header.Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Errorf("Content-Type=%q", got)
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("CSP missing strict default-src: %q", csp)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	bodyStr := string(body)
	if !strings.Contains(bodyStr, `action="`+h.redirectURI+`"`) {
		t.Errorf("body missing action=%q: %s", h.redirectURI, bodyStr)
	}
	jwtStr := extractFormResponseValue(t, bodyStr)
	claims := h.verifyJARMClaims(t, jwtStr)
	if got := claims["code"]; got == nil || got == "" {
		t.Errorf("code missing: %v", claims)
	}
}

// extractFormResponseValue pulls the value of the <input name="response"
// value="..."/> field from an HTML body. The helper is deliberately
// minimal: the body shape is fixed by [jarm.WriteFormPost], so we
// substring-search rather than HTML-parse to keep the test self-
// contained.
func extractFormResponseValue(t *testing.T, body string) string {
	t.Helper()

	const startTag = `name="response" value="`
	idx := strings.Index(body, startTag)
	if idx < 0 {
		t.Fatalf("response field not found in body: %s", body)
	}
	rest := body[idx+len(startTag):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		t.Fatalf("malformed response field: %s", body)
	}
	return rest[:end]
}

func TestEndToEnd_JARM_QueryJWT_ErrorEnvelope(t *testing.T) {
	t.Parallel()

	h := newJARMHarness(t)
	// Inject an invalid scope so Validate fails after redirect_uri has
	// been trusted. The "weird" scope is not registered to the client,
	// so the validator returns ErrScopeNotPermitted (invalid_scope) —
	// a redirect-safe error that JARM should sign.
	values := jarmAuthorizeValues(h.rpID, h.redirectURI, "query.jwt")
	values.Set("scope", "openid weird")
	authResp, err := newGet(h.tk.Server.URL + "/oidc/auth?" + values.Encode()).Do(h.httpClient)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer authResp.Body.Close()
	if authResp.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(authResp.Body)
		t.Fatalf("status=%d body=%s", authResp.StatusCode, string(dump))
	}
	loc, err := authResp.Location()
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	rawJWT := loc.Query().Get("response")
	if rawJWT == "" {
		t.Fatalf("response missing in %s", loc.String())
	}
	if loc.Query().Get("error") != "" {
		t.Errorf("legacy 'error' parameter leaked: %s", loc.String())
	}
	claims := h.verifyJARMClaims(t, rawJWT)
	if got := claims["error"]; got != "invalid_scope" {
		t.Errorf("error=%v want invalid_scope", got)
	}
	if got := claims["state"]; got != "state-abc" {
		t.Errorf("state=%v", got)
	}
	if _, hasCode := claims["code"]; hasCode {
		t.Errorf("code claim present on error path: %v", claims)
	}
}

func TestEndToEnd_JARM_FeatureDisabled_ReturnsLegacyError(t *testing.T) {
	t.Parallel()

	// No WithFeature(feature.JARM): the testkit provider lacks the
	// JARM signer. A request that asks for a JARM mode must surface
	// "unsupported_response_mode" via the legacy redirect — JARM
	// cannot be used to convey "JARM is not supported".
	clock := fakeClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	tk := testkit.NewProvider(t, testkit.WithClock(clock))
	const secret = "rp-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "rp-no-jarm",
		SecretHash:              hash,
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	values := jarmAuthorizeValues(rp.ID, rp.RedirectURIs[0], "query.jwt")
	resp, err := newGet(tk.Server.URL + "/oidc/auth?" + values.Encode()).Do(client)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, string(dump))
	}
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	if loc.Query().Get("response") != "" {
		t.Errorf("JARM JWT leaked despite feature off: %s", loc.String())
	}
	if got := loc.Query().Get("error"); got != "unsupported_response_mode" {
		t.Errorf("error=%q want unsupported_response_mode", got)
	}
	if got := loc.Query().Get("state"); got != "state-abc" {
		t.Errorf("state=%q", got)
	}
}
