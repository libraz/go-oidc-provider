package scenarios_test

// Catalog: test/scenarios/catalog/pairwise.yaml (PW-NN)
// Spec:
//   - OIDC Core 1.0 §8, §8.1, §8.2, §3.1.2.1, §5.3, §5.5.1, §16
//   - OIDC Dynamic Client Registration 1.0 §2
//   - OIDC CIBA Core 1.0 §11
//   - OIDC Device Authorization 1.0 §6
//   - RFC 7662 — OAuth 2.0 Token Introspection

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/subject"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

// pwPairwiseSalt is the deterministic 32-byte salt the PW issuance
// rows wire through op.WithPairwiseSubject. The catalogue requires
// fixed fixtures so a failing trace replays identically across runs.
var pwPairwiseSalt = []byte("pw-pairwise-fixed-salt-32b!_v0.9")

// pwClientSecret is the deterministic confidential-client secret the
// PW issuance rows reuse. It mirrors the cgClientSecret pattern in
// custom_grants_test.go so the constant is local to the suite.
const pwClientSecret = "pw-client-secret"

// newPairwiseProvider constructs a testkit Provider that derives the
// "sub" claim through op.WithPairwiseSubject. Tests assemble their
// own clients via tk.RegisterClient because per-row sector setups
// vary (different redirect-host pairs, shared sector_identifier_uri,
// etc.).
func newPairwiseProvider(t *testing.T) *testkit.Provider {
	t.Helper()
	return testkit.NewProvider(t, testkit.WithOptions(
		op.WithPairwiseSubject(pwPairwiseSalt),
	))
}

// newPairwiseDCRProvider mirrors [newPairwiseProvider] but also enables
// Dynamic Client Registration so the registration-time validation rows
// (PW-10..PW-12, PW-20) can drive POST /oidc/register through the
// public wire. Static-client tests stay on [newPairwiseProvider].
func newPairwiseDCRProvider(t *testing.T) *testkit.Provider {
	t.Helper()
	return testkit.NewProvider(t, testkit.WithOptions(
		op.WithPairwiseSubject(pwPairwiseSalt),
		op.WithDynamicRegistration(op.RegistrationOption{}),
	))
}

// pairwiseClient seeds a confidential client whose redirect_uri host
// will be picked up as the sector by the pairwise generator (sector
// resolution falls back to the single redirect host when
// SectorIdentifierURI is empty). Returns the registered store.Client
// and the plaintext secret so the test can drive HTTP Basic auth.
func pairwiseClient(t *testing.T, tk *testkit.Provider, id, redirectURI string) *store.Client {
	t.Helper()
	hash, err := op.HashClientSecret(pwClientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	return tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      id,
		SecretHash:              hash,
		RedirectURIs:            []string{redirectURI},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
		SubjectType:             "pairwise",
	})
}

// mustPWSecretHash returns the Argon2id hash of [pwClientSecret] so a
// fixture can register a confidential client without repeating the
// error handling.
func mustPWSecretHash(t *testing.T) string {
	t.Helper()
	hash, err := op.HashClientSecret(pwClientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	return hash
}

// pairwisePublicClient is the subject_type=public counterpart to
// [pairwiseClient]. The two exist as a pair because every "follows the
// client's subject_type" row needs both arms on ONE provider: a
// projector stuck in a single mode passes either arm alone.
func pairwisePublicClient(t *testing.T, tk *testkit.Provider, id, redirectURI string) *store.Client {
	t.Helper()
	return tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      id,
		SecretHash:              mustPWSecretHash(t),
		RedirectURIs:            []string{redirectURI},
		Scopes:                  []string{"openid", "profile", "email", "offline_access"},
		TokenEndpointAuthMethod: "client_secret_basic",
		SubjectType:             "public",
	})
}

// pairwiseSubjectTypePair registers one pairwise and one public client
// on tk, drives both through the code flow for the same end user, and
// returns the two id_token "sub" values in that order.
func pairwiseSubjectTypePair(t *testing.T, tk *testkit.Provider, idPrefix string) (pairwiseSub, publicSub string) {
	t.Helper()
	pairwiseCallback := "https://" + idPrefix + "-pairwise.example.com/cb"
	publicCallback := "https://" + idPrefix + "-public.example.net/cb"

	pairwiseRP := pairwiseClient(t, tk, idPrefix+"-pairwise", pairwiseCallback)
	publicRP := pairwisePublicClient(t, tk, idPrefix+"-public", publicCallback)

	return runPairwiseFlow(t, tk, pairwiseRP, pairwiseCallback),
		runPairwiseFlow(t, tk, publicRP, publicCallback)
}

// pairwiseIntrospect POSTs token to /introspect authenticated as
// clientID and returns the decoded envelope, failing the test on a
// non-200 or an inactive result. Callers use it only for tokens the
// authenticated client owns, so inactive is always a fixture bug.
func pairwiseIntrospect(t *testing.T, tk *testkit.Provider, clientID, token string) map[string]any {
	t.Helper()
	form := url.Values{"token": {token}, "token_type_hint": {"refresh_token"}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/introspect", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build /introspect request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, pwClientSecret)
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /introspect as %s: %v", clientID, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/introspect as %s status=%d body=%s", clientID, resp.StatusCode, body)
	}
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("/introspect body is not JSON: %v (raw=%s)", err, body)
	}
	if active, _ := env["active"].(bool); !active {
		t.Fatalf("/introspect as %s returned inactive for its own token: %v", clientID, env)
	}
	return env
}

// pairwiseEndSession issues GET /oidc/end_session with the supplied
// hint through browser (whose jar carries the session cookie the hint
// is compared against). Redirects are not followed so the caller can
// inspect the status and Location. The caller closes the body.
func pairwiseEndSession(
	t *testing.T,
	tk *testkit.Provider,
	browser *http.Client,
	idTokenHint, postLogoutRedirectURI string,
) *http.Response {
	t.Helper()
	values := url.Values{
		"id_token_hint":            {idTokenHint},
		"post_logout_redirect_uri": {postLogoutRedirectURI},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		tk.Server.URL+"/oidc/end_session?"+values.Encode(), http.NoBody)
	if err != nil {
		t.Fatalf("build GET /end_session: %v", err)
	}
	resp, err := browser.Do(req)
	if err != nil {
		t.Fatalf("GET /end_session: %v", err)
	}
	return resp
}

// mintPairwiseIDTokenHint signs an id_token-shaped JWS naming sub for
// audience clientID. PW-53 uses it to present a hint carrying the
// OP-internal account id, which the OP never issues to a pairwise
// client and therefore must not accept as a session match.
func mintPairwiseIDTokenHint(t *testing.T, tk *testkit.Provider, clientID, sub string) string {
	t.Helper()
	now := time.Now().Unix()
	tok, err := tk.SignedJWT(map[string]any{
		"iss": tk.Issuer,
		"sub": sub,
		"aud": clientID,
		"iat": now - 60,
		"exp": now + 3600,
	})
	if err != nil {
		t.Fatalf("SignedJWT: %v", err)
	}
	return tok
}

// runPairwiseFlow drives a complete /authorize → /interaction →
// /token round-trip for the given client and returns the id_token
// "sub" claim. The subject submitted to the testkit
// SubjectAuthenticator is fixed (DefaultSubject) so tests can compare
// "sub" output across clients without per-call subject jitter.
func runPairwiseFlow(t *testing.T, tk *testkit.Provider, c *store.Client, redirectURI string) string {
	t.Helper()
	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    c.ID,
		RedirectURI: redirectURI,
		Scope:       "openid",
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  redirectURI,
		Verifier:     pkce.Verifier,
		ClientID:     c.ID,
		ClientSecret: pwClientSecret,
	})
	if tok.StatusCode != http.StatusOK {
		t.Fatalf("/token status=%d body=%v", tok.StatusCode, tok.Raw)
	}
	if tok.IDToken == "" {
		t.Fatalf("/token did not return id_token (raw=%v)", tok.Raw)
	}
	claims := decodePWJWTClaims(t, tok.IDToken)
	sub, _ := claims["sub"].(string)
	if sub == "" {
		t.Fatalf("id_token claims missing sub: %v", claims)
	}
	return sub
}

func runPairwiseTokenFlow(t *testing.T, tk *testkit.Provider, c *store.Client, redirectURI, scope string) scenariokit.TokenResponse {
	t.Helper()
	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    c.ID,
		RedirectURI: redirectURI,
		Scope:       scope,
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  redirectURI,
		Verifier:     pkce.Verifier,
		ClientID:     c.ID,
		ClientSecret: pwClientSecret,
	})
	if tok.StatusCode != http.StatusOK {
		t.Fatalf("/token status=%d body=%v", tok.StatusCode, tok.Raw)
	}
	return tok
}

func pairwiseBrowserClient(t *testing.T, tk *testkit.Provider) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	return tk.HTTPClient(jar)
}

func runPairwiseAuthorizeWithBrowser(
	t *testing.T,
	tk *testkit.Provider,
	client *http.Client,
	subject string,
	params scenariokit.AuthorizeParams,
) scenariokit.CodeFlowResult {
	t.Helper()
	authResp := getPairwiseAuthorizeResponse(t, tk, client, params)
	defer func() { _ = authResp.Body.Close() }()
	loc, err := authResp.Location()
	if err != nil {
		t.Fatalf("/authorize Location: %v", err)
	}
	if result, ok := pairwiseCaptureCallback(t, params.RedirectURI, loc); ok {
		return result
	}
	interactionURL := tk.Server.URL + loc.Path
	stepResp := mustPairwiseGET(t, client, interactionURL)
	step := decodePWJSON(t, stepResp)
	_ = stepResp.Body.Close()
	stateRef, _ := step["state_ref"].(string)
	csrf := findPWCookie(stepResp.Cookies(), "__Host-oidc_csrf")
	if stateRef == "" || csrf == nil {
		t.Fatalf("interaction prompt missing state_ref or csrf: %v", step)
	}
	postResp := postPairwiseInteraction(t, client, interactionURL, tk.Issuer, csrf.Value, stateRef,
		map[string]string{testkit.SubjectFieldName: subject})
	finalResp := completePairwiseConsentIfPrompted(t, client, interactionURL, tk.Issuer, csrf.Value, postResp)
	defer func() { _ = finalResp.Body.Close() }()
	if finalResp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(finalResp.Body)
		t.Fatalf("final interaction status=%d body=%s", finalResp.StatusCode, string(body))
	}
	loc, err = finalResp.Location()
	if err != nil {
		t.Fatalf("final Location: %v", err)
	}
	result, ok := pairwiseCaptureCallback(t, params.RedirectURI, loc)
	if !ok {
		t.Fatalf("callback %s does not match redirect_uri %s", loc.String(), params.RedirectURI)
	}
	return result
}

func getPairwiseAuthorizeCallback(
	t *testing.T,
	tk *testkit.Provider,
	client *http.Client,
	params scenariokit.AuthorizeParams,
) scenariokit.CodeFlowResult {
	t.Helper()
	resp := getPairwiseAuthorizeResponse(t, tk, client, params)
	defer func() { _ = resp.Body.Close() }()
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("/authorize Location: %v", err)
	}
	result, ok := pairwiseCaptureCallback(t, params.RedirectURI, loc)
	if !ok {
		t.Fatalf("/authorize Location=%s did not target redirect_uri=%s", loc.String(), params.RedirectURI)
	}
	return result
}

func getPairwiseAuthorizeResponse(
	t *testing.T,
	tk *testkit.Provider,
	client *http.Client,
	params scenariokit.AuthorizeParams,
) *http.Response {
	t.Helper()
	resp := mustPairwiseGET(t, client, tk.Server.URL+"/oidc/auth?"+params.Values().Encode())
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("/authorize status=%d body=%s", resp.StatusCode, string(body))
	}
	return resp
}

func mustPairwiseGET(t *testing.T, client *http.Client, rawURL string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		t.Fatalf("build GET %s: %v", rawURL, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	return resp
}

func decodePWJSON(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read JSON body: %v", err)
	}
	out := map[string]any{}
	if len(raw) == 0 {
		return out
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode JSON body %s: %v", string(raw), err)
	}
	return out
}

func postPairwiseInteraction(
	t *testing.T,
	client *http.Client,
	interactionURL, origin, csrf, stateRef string,
	values map[string]string,
) *http.Response {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"state_ref": stateRef, "values": values})
	if err != nil {
		t.Fatalf("marshal interaction submission: %v", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, interactionURL, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("build POST %s: %v", interactionURL, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", origin)
	req.Header.Set("X-CSRF-Token", csrf)
	req.AddCookie(&http.Cookie{Name: "__Host-oidc_csrf", Value: csrf})
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", interactionURL, err)
	}
	return resp
}

func completePairwiseConsentIfPrompted(
	t *testing.T,
	client *http.Client,
	interactionURL, origin, csrf string,
	prior *http.Response,
) *http.Response {
	t.Helper()
	consent, env, err := testkit.IsConsentPrompt(prior)
	if err != nil {
		t.Fatalf("inspect consent prompt: %v", err)
	}
	if !consent {
		return prior
	}
	stateRef, _ := env["state_ref"].(string)
	if stateRef == "" {
		t.Fatal("consent prompt missing state_ref")
	}
	if rotated := findPWCookie(prior.Cookies(), "__Host-oidc_csrf"); rotated != nil {
		csrf = rotated.Value
	}
	return testkit.PostConsentApproval(t, client, interactionURL, origin, csrf, stateRef, pairwiseApprovedScopes(env))
}

func pairwiseApprovedScopes(env map[string]any) string {
	data, _ := env["data"].(map[string]any)
	scopesAny, _ := data["Scopes"].([]any)
	out := make([]string, 0, len(scopesAny))
	for _, s := range scopesAny {
		entry, _ := s.(map[string]any)
		name, _ := entry["Name"].(string)
		if name != "" {
			out = append(out, name)
		}
	}
	return strings.Join(out, " ")
}

func pairwiseCaptureCallback(t *testing.T, redirectURI string, location *url.URL) (scenariokit.CodeFlowResult, bool) {
	t.Helper()
	want, err := url.Parse(redirectURI)
	if err != nil {
		t.Fatalf("parse redirect_uri %q: %v", redirectURI, err)
	}
	if location.Scheme != want.Scheme || location.Host != want.Host || location.Path != want.Path {
		return scenariokit.CodeFlowResult{}, false
	}
	q := location.Query()
	return scenariokit.CodeFlowResult{
		Code:      q.Get("code"),
		State:     q.Get("state"),
		Iss:       q.Get("iss"),
		Error:     q.Get("error"),
		ErrorDesc: q.Get("error_description"),
		Location:  location,
	}, true
}

func findPWCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func pairwiseGetUserInfo(t *testing.T, tk *testkit.Provider, accessToken string) map[string]any {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		tk.Server.URL+"/oidc/userinfo", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("GET /userinfo: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/userinfo status=%d want 200 body=%s", resp.StatusCode, body)
	}
	out := map[string]any{}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode /userinfo body %s: %v", string(body), err)
	}
	return out
}

// decodePWJWTClaims pulls the payload claims out of a JWS Compact
// Serialisation without verifying the signature. The PW issuance
// rows compare "sub" values across flows; verifying the signature
// would re-test JWS framing, which the IDT-suite already covers.
func decodePWJWTClaims(tb testing.TB, jws string) map[string]any {
	tb.Helper()
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		tb.Fatalf("jwt parts=%d want 3 (value=%q)", len(parts), jws)
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

// postPairwiseRegistration drives the public /oidc/register endpoint for
// the PW-02..PW-04 rows. The helper centralises the IAT issuance, JSON
// body marshalling, bearer header, and response decoding so the
// per-row tests can focus on the assertion that distinguishes them.
// Returns the HTTP status code and decoded response body (which may be
// either a successful client-information response or an error envelope
// per RFC 7591 §3.2).
func postPairwiseRegistration(tb testing.TB, tk *testkit.Provider, body map[string]any) (int, map[string]any) {
	tb.Helper()

	issued, err := tk.OP.IssueInitialAccessToken(context.Background(), op.InitialAccessTokenSpec{})
	if err != nil {
		tb.Fatalf("IssueInitialAccessToken: %v", err)
	}

	raw, err := json.Marshal(body)
	if err != nil {
		tb.Fatalf("marshal body: %v", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/register", bytes.NewReader(raw))
	if err != nil {
		tb.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+issued.Value)

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		tb.Fatalf("POST /oidc/register: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		tb.Fatalf("read body: %v", err)
	}
	var decoded map[string]any
	if len(bytes.TrimSpace(respBytes)) > 0 {
		if err := json.Unmarshal(respBytes, &decoded); err != nil {
			tb.Fatalf("body is not JSON: %v (raw=%q)", err, string(respBytes))
		}
	}
	return resp.StatusCode, decoded
}

// TestScenario_PW_01_DiscoveryEnumeratesSupportedTypes asserts that the
// OP's discovery document advertises the exact set of subject identifier
// types it implements. With pairwise pinned OFF in v1.0
// (PairwiseEnabled=false; no public WithPairwiseSubject option ships)
// the published list MUST be exactly ["public"]. Advertising "pairwise"
// here without serving it would mislead RPs into requesting a
// subject_type the OP cannot honour.
//
// Spec: OIDC Core 1.0 §8 (subject_types_supported is REQUIRED metadata).
func TestScenario_PW_01_DiscoveryEnumeratesSupportedTypes(t *testing.T) {
	t.Parallel()

	p := testkit.NewProvider(t)

	_, _, doc := fetchDiscovery(t, p.Server.URL)

	raw, ok := doc["subject_types_supported"].([]any)
	if !ok {
		t.Fatalf("subject_types_supported missing or wrong type: %T", doc["subject_types_supported"])
	}
	got := make([]string, 0, len(raw))
	for i, v := range raw {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("subject_types_supported[%d]=%v not a string", i, v)
		}
		got = append(got, s)
	}
	slices.Sort(got)
	want := []string{"public"}
	if !slices.Equal(got, want) {
		t.Errorf("subject_types_supported=%v want %v (pairwise is OFF in v1.0)", got, want)
	}
}

// TestScenario_PW_02_MissingSubjectTypeFallsBackToPublic drives the
// public /oidc/register endpoint with a metadata payload that omits
// subject_type and asserts the success response echoes
// "subject_type": "public" — the OP's documented default. Verified on
// the wire (registration response body) so the assertion covers the
// public surface rather than internal fields.
//
// Spec: OIDC Core 1.0 §8 / OIDC Dynamic Client Registration 1.0 §2
// (subject_type is OPTIONAL; omitted means the OP's default).
func TestScenario_PW_02_MissingSubjectTypeFallsBackToPublic(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t,
		testkit.WithOptions(op.WithDynamicRegistration(op.RegistrationOption{})),
	)

	body := map[string]any{
		"redirect_uris": []string{"https://rp.example.com/cb"},
		// subject_type intentionally omitted.
	}
	status, resp := postPairwiseRegistration(t, tk, body)
	if status != http.StatusCreated {
		t.Fatalf("status=%d want 201 body=%v", status, resp)
	}
	got, _ := resp["subject_type"].(string)
	if got != "public" {
		t.Errorf("subject_type=%q want %q (default when omitted)", got, "public")
	}
}

// TestScenario_PW_03_PairwiseRequestRejectedWhenFeatureOff drives the
// public /oidc/register endpoint with subject_type=pairwise against an
// OP whose pairwise feature is disabled (the v1.0 default; no public
// WithPairwiseSubject option ships). The OP MUST refuse the
// registration with 400 invalid_client_metadata so the RP cannot
// silently receive a public sub when it asked for a pairwise one. The
// internal validator (validateSubjectType) phrases this as
// "subject_type pairwise requires WithPairwiseSubject"; this test asserts
// only the wire-stable error code and that the description names the
// offending field.
//
// Spec: OIDC Core 1.0 §8 / RFC 7591 §3.2.2 (invalid_client_metadata).
func TestScenario_PW_03_PairwiseRequestRejectedWhenFeatureOff(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t,
		testkit.WithOptions(op.WithDynamicRegistration(op.RegistrationOption{})),
	)

	body := map[string]any{
		"redirect_uris": []string{"https://rp.example.com/cb"},
		"subject_type":  "pairwise",
	}
	status, resp := postPairwiseRegistration(t, tk, body)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", status, resp)
	}
	if got, _ := resp["error"].(string); got != "invalid_client_metadata" {
		t.Errorf("error=%q want invalid_client_metadata (body=%v)", got, resp)
	}
	desc, _ := resp["error_description"].(string)
	if !strings.Contains(desc, "subject_type") {
		t.Errorf("error_description=%q must name the subject_type field", desc)
	}
}

// TestScenario_PW_04_PairwiseUnimplementedRejectsRegistration captures
// the framing of OIDC Dynamic Client Registration 1.0 §2 from the
// perspective of an OP that does not implement pairwise at all (as
// opposed to PW-03's "feature is wired but disabled at this OP"
// framing). On v1.0 of this Go OP the two collapse to the same wire
// behaviour because no implementation path for pairwise ships, but
// keeping the row separate preserves the catalog's spec-level
// distinction so a future minor that implements pairwise still has a
// dedicated test for the "implementation absent" case.
//
// Spec: OIDC Dynamic Client Registration 1.0 §2 (subject_type values
// the OP does not support yield invalid_client_metadata).
func TestScenario_PW_04_PairwiseUnimplementedRejectsRegistration(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t,
		testkit.WithOptions(op.WithDynamicRegistration(op.RegistrationOption{})),
	)

	body := map[string]any{
		"redirect_uris": []string{"https://rp.example.com/cb"},
		"subject_type":  "pairwise",
	}
	status, resp := postPairwiseRegistration(t, tk, body)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", status, resp)
	}
	if got, _ := resp["error"].(string); got != "invalid_client_metadata" {
		t.Errorf("error=%q want invalid_client_metadata (body=%v)", got, resp)
	}
}

// TestScenario_PW_10_SingleHostRedirectURIsAdoptHostAsSector confirms
// a pairwise client may register without sector_identifier_uri when
// every redirect_uri shares one host. The OP accepts the registration
// (the host then serves as the sector at issuance time, see PW-43 /
// PW-44 for the issuance-side determinism); a 400 here would force
// every single-host pairwise RP to host a sector document needlessly.
//
// Spec: OIDC Core 1.0 §8.1 (single-host pairwise needs no sector
// document; the redirect host is sufficient).
func TestScenario_PW_10_SingleHostRedirectURIsAdoptHostAsSector(t *testing.T) {
	t.Parallel()

	tk := newPairwiseDCRProvider(t)
	body := map[string]any{
		"redirect_uris": []string{
			"https://rp.example.com/cb1",
			"https://rp.example.com/cb2",
		},
		"subject_type": "pairwise",
	}
	status, resp := postPairwiseRegistration(t, tk, body)
	if status != http.StatusCreated {
		t.Fatalf("status=%d want 201 body=%v", status, resp)
	}
	got, _ := resp["subject_type"].(string)
	if got != "pairwise" {
		t.Errorf("subject_type=%q want pairwise (body=%v)", got, resp)
	}
}

// TestScenario_PW_10B_SingleHostRedirectURIsCompareHostCaseInsensitively
// confirms the single-host shortcut follows DNS hostname semantics.
// Hosts are case-insensitive, so redirect_uris that differ only by host
// casing must not force an otherwise unnecessary sector_identifier_uri.
func TestScenario_PW_10B_SingleHostRedirectURIsCompareHostCaseInsensitively(t *testing.T) {
	t.Parallel()

	tk := newPairwiseDCRProvider(t)
	body := map[string]any{
		"redirect_uris": []string{
			"https://RP.example.com/cb1",
			"https://rp.example.com/cb2",
		},
		"subject_type": "pairwise",
	}
	status, resp := postPairwiseRegistration(t, tk, body)
	if status != http.StatusCreated {
		t.Fatalf("status=%d want 201 body=%v", status, resp)
	}
	if got, _ := resp["subject_type"].(string); got != "pairwise" {
		t.Errorf("subject_type=%q want pairwise (body=%v)", got, resp)
	}
}

// TestScenario_PW_11_MultiHostRequiresSectorURI asserts a pairwise
// client whose redirect_uris span more than one host and omits
// sector_identifier_uri is rejected with invalid_client_metadata.
// Without an explicit sector document the OP cannot decide which
// host scopes the pairwise hash — admitting the registration would
// silently bind subs to whichever redirect arrived first.
//
// Spec: OIDC Core 1.0 §8.1 / RFC 7591 §3.2.2.
func TestScenario_PW_11_MultiHostRequiresSectorURI(t *testing.T) {
	t.Parallel()

	tk := newPairwiseDCRProvider(t)
	body := map[string]any{
		"redirect_uris": []string{
			"https://alpha.example/cb",
			"https://beta.example/cb",
		},
		"subject_type": "pairwise",
	}
	status, resp := postPairwiseRegistration(t, tk, body)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", status, resp)
	}
	if got, _ := resp["error"].(string); got != "invalid_client_metadata" {
		t.Errorf("error=%q want invalid_client_metadata (body=%v)", got, resp)
	}
	desc, _ := resp["error_description"].(string)
	if !strings.Contains(desc, "sector_identifier_uri") {
		t.Errorf("error_description=%q must name the sector_identifier_uri requirement", desc)
	}
}

// TestScenario_PW_12_PathDifferenceOnSameHostAllowed pins that the
// single-host check looks only at the URL host: two redirect_uris
// that share a host but differ in path register without a sector
// document. The OAuth redirect_uri matching is byte-exact at runtime,
// but the §8.1 sector grouping is host-only by design.
//
// Spec: OIDC Core 1.0 §8.1.
func TestScenario_PW_12_PathDifferenceOnSameHostAllowed(t *testing.T) {
	t.Parallel()

	tk := newPairwiseDCRProvider(t)
	body := map[string]any{
		"redirect_uris": []string{
			"https://rp.example.com/app/cb",
			"https://rp.example.com/admin/cb",
		},
		"subject_type": "pairwise",
	}
	status, resp := postPairwiseRegistration(t, tk, body)
	if status != http.StatusCreated {
		t.Fatalf("status=%d want 201 body=%v", status, resp)
	}
	if got, _ := resp["subject_type"].(string); got != "pairwise" {
		t.Errorf("subject_type=%q want pairwise (body=%v)", got, resp)
	}
}

// TestScenario_PW_13_NoRedirectURIsRelyOnJwksHost is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_13_NoRedirectURIsRelyOnJwksHost(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-13 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_20_SectorURIMustBeHTTPS confirms the OP refuses a
// sector_identifier_uri whose scheme is not https. The check fires at
// URL parse time before any outbound I/O so an attacker cannot use
// the OP to probe an http upstream from a known network position.
// DCR-VAL-06 covers the same wire shape from the DCR catalog; this
// row pins the binding from the pairwise catalog.
//
// Spec: OIDC Core 1.0 §8.1 (sector_identifier_uri MUST be https).
func TestScenario_PW_20_SectorURIMustBeHTTPS(t *testing.T) {
	t.Parallel()

	tk := newPairwiseDCRProvider(t)
	body := map[string]any{
		"redirect_uris":         []string{"https://rp.example.com/cb"},
		"subject_type":          "pairwise",
		"sector_identifier_uri": "http://rp.example.com/sector.json",
	}
	status, resp := postPairwiseRegistration(t, tk, body)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", status, resp)
	}
	if got, _ := resp["error"].(string); got != "invalid_client_metadata" {
		t.Errorf("error=%q want invalid_client_metadata (body=%v)", got, resp)
	}
}

// TestScenario_PW_21_SectorURIFetchedAtRegistration is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_21_SectorURIFetchedAtRegistration(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-21 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_22_SectorURINon200StatusFails is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_22_SectorURINon200StatusFails(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-22 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_23_SectorURIUnparseableJSONFails is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_23_SectorURIUnparseableJSONFails(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-23 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_24_SectorURINonArrayBodyFails is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_24_SectorURINonArrayBodyFails(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-24 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_25_SectorURIMustIncludeAllRedirectURIs is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_25_SectorURIMustIncludeAllRedirectURIs(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-25 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_26_PublicClientSectorURIHostRecorded is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_26_PublicClientSectorURIHostRecorded(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-26 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_27_SectorIdentifierIsLowercaseHost is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_27_SectorIdentifierIsLowercaseHost(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-27 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_30_CIBARequiresJwksURIInSectorList is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_30_CIBARequiresJwksURIInSectorList(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-30 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_31_DeviceFlowRequiresJwksURIInSectorList is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_31_DeviceFlowRequiresJwksURIInSectorList(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-31 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_32_NoRedirectClientsUseJwksAsSectorAnchor is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_32_NoRedirectClientsUseJwksAsSectorAnchor(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-32 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_40_PairwiseSubIsDeterministic confirms the
// pairwise transform is deterministic at issuance: two independent
// authorize → /token round-trips through the same client for the
// same internal subject MUST produce the same id_token "sub". The
// determinism contract is the basis of the (sector, subject)
// grouping every other PW-40 series row depends on.
//
// Spec: OIDC Core 1.0 §8.1.
func TestScenario_PW_40_PairwiseSubIsDeterministic(t *testing.T) {
	t.Parallel()
	tk := newPairwiseProvider(t)
	c := pairwiseClient(t, tk, "rp-pw-40", "https://rp.example.com/cb")

	sub1 := runPairwiseFlow(t, tk, c, "https://rp.example.com/cb")
	sub2 := runPairwiseFlow(t, tk, c, "https://rp.example.com/cb")
	if sub1 != sub2 {
		t.Errorf("pairwise sub drifted across two flows: %q vs %q", sub1, sub2)
	}
}

func TestScenario_PW_40_PairwisePromptNoneReusesProjectedGrant(t *testing.T) {
	t.Parallel()
	tk := newPairwiseProvider(t)
	c := pairwiseClient(t, tk, "rp-pw-40-prompt-none", "https://rp.example.com/cb")
	client := pairwiseBrowserClient(t, tk)
	pkce := scenariokit.NewPKCEPair("")
	params := scenariokit.AuthorizeParams{
		ClientID:    c.ID,
		RedirectURI: "https://rp.example.com/cb",
		Scope:       "openid",
		PKCE:        pkce,
	}
	first := runPairwiseAuthorizeWithBrowser(t, tk, client, scenariokit.DefaultSubject, params)
	if first.Code == "" || first.Error != "" {
		t.Fatalf("first authorize result = %+v, want code", first)
	}

	params.Extra = url.Values{"prompt": {"none"}}
	second := getPairwiseAuthorizeCallback(t, tk, client, params)
	if second.Error != "" {
		t.Fatalf("prompt=none returned error=%q desc=%q; want cached grant to mint code", second.Error, second.ErrorDesc)
	}
	if second.Code == "" {
		t.Fatalf("prompt=none callback missing code: %+v", second)
	}
}

// A pairwise OP projects the subject per client at every egress point,
// so the value it persists has to stay raw: the grant is looked up by
// (Subject, ClientID), one grant serves whichever clients the subject
// authorizes, and a salt rotation is meant to change what is emitted
// without rewriting stored rows. A projected subject on the grant would
// be projected a second time on the way out. Comparing the id_token
// "sub" against the stored row is what separates the two — every
// egress-side assertion in this file passes either way.
func TestScenario_PW_40_GrantStoresTheRawSubjectNotTheProjection(t *testing.T) {
	t.Parallel()
	tk := newPairwiseProvider(t)
	c := pairwiseClient(t, tk, "rp-pw-40-grant-raw", "https://rp.example.com/cb")

	idSub := runPairwiseFlow(t, tk, c, "https://rp.example.com/cb")
	if idSub == "" || idSub == scenariokit.DefaultSubject {
		t.Fatalf("id_token sub=%q, want a pairwise value distinct from the raw subject", idSub)
	}

	grants, err := tk.Store.Grants().ListBySubject(context.Background(), scenariokit.DefaultSubject)
	if err != nil {
		t.Fatalf("ListBySubject(raw): %v", err)
	}
	if len(grants) == 0 {
		t.Fatalf("no grant is keyed on the raw subject %q; the flow stored a projected value", scenariokit.DefaultSubject)
	}
	for _, g := range grants {
		if g.Subject != scenariokit.DefaultSubject {
			t.Errorf("Grant.Subject=%q want the raw %q", g.Subject, scenariokit.DefaultSubject)
		}
		if g.Subject == idSub {
			t.Errorf("Grant.Subject=%q equals the id_token sub; the projection was applied at persistence", g.Subject)
		}
	}

	projected, err := tk.Store.Grants().ListBySubject(context.Background(), idSub)
	if err != nil {
		t.Fatalf("ListBySubject(projected): %v", err)
	}
	if len(projected) != 0 {
		t.Errorf("%d grant(s) keyed on the projected sub %q; nothing may be stored under a per-client value", len(projected), idSub)
	}
}

func TestScenario_PW_40_UserInfoLooksUpRawSubjectAndReturnsPairwiseSub(t *testing.T) {
	t.Parallel()
	tk := newPairwiseProvider(t)
	c := pairwiseClient(t, tk, "rp-pw-40-userinfo", "https://rp.example.com/cb")
	tk.Store.PutUser(context.Background(), &store.User{
		Subject: scenariokit.DefaultSubject,
		Claims: map[string]any{
			"email":          "user-1@example.test",
			"email_verified": true,
		},
	})

	tok := runPairwiseTokenFlow(t, tk, c, "https://rp.example.com/cb", "openid email")
	if tok.AccessToken == "" || tok.IDToken == "" {
		t.Fatalf("/token response missing access_token or id_token: %v", tok.Raw)
	}
	idClaims := decodePWJWTClaims(t, tok.IDToken)
	idSub, _ := idClaims["sub"].(string)
	if idSub == "" || idSub == scenariokit.DefaultSubject {
		t.Fatalf("id_token sub=%q, want non-empty pairwise value distinct from raw subject", idSub)
	}

	ui := pairwiseGetUserInfo(t, tk, tok.AccessToken)
	if got, _ := ui["sub"].(string); got != idSub {
		t.Errorf("userinfo sub=%q want id_token sub=%q", got, idSub)
	}
	if got, _ := ui["email"].(string); got != "user-1@example.test" {
		t.Errorf("userinfo email=%v want raw-subject user claim", ui["email"])
	}
}

// TestScenario_PW_40_AccessTokenSubMatchesIDTokenSub pins RFC 9068 §3:
// the "sub" claim of the JWT-formatted access token MUST match the
// corresponding id_token "sub". Pairwise OPs project the per-client
// value at every egress point (id_token, JWT access_token, userinfo,
// introspection) so a resource server validating the access token
// observes the same opaque identifier the client received in the id_token.
func TestScenario_PW_40_AccessTokenSubMatchesIDTokenSub(t *testing.T) {
	t.Parallel()
	tk := newPairwiseProvider(t)
	c := pairwiseClient(t, tk, "rp-pw-40-at-sub", "https://rp.example.com/cb")

	tok := runPairwiseTokenFlow(t, tk, c, "https://rp.example.com/cb", "openid")
	if tok.AccessToken == "" || tok.IDToken == "" {
		t.Fatalf("/token response missing access_token or id_token: %v", tok.Raw)
	}
	idClaims := decodePWJWTClaims(t, tok.IDToken)
	atClaims := decodePWJWTClaims(t, tok.AccessToken)
	idSub, _ := idClaims["sub"].(string)
	atSub, _ := atClaims["sub"].(string)
	if idSub == "" {
		t.Fatalf("id_token sub is empty: %v", idClaims)
	}
	if idSub == scenariokit.DefaultSubject {
		t.Fatalf("id_token sub=%q must be the pairwise value, not the raw subject", idSub)
	}
	if atSub != idSub {
		t.Errorf("access_token sub=%q must equal id_token sub=%q (RFC 9068 §3)", atSub, idSub)
	}
}

// TestScenario_PW_40_IntrospectionReturnsProjectedSub pins the pairwise
// projection across the introspection egress: a refresh-token record
// persists the raw OP-internal subject, but the wire response carries
// the per-client value resolved through SubjectProjector. Without the
// projection the RS would observe a third subject identifier
// (raw on introspection, pairwise on userinfo / id_token), breaking the
// OIDC Core §8.1 single-pairwise-per-client guarantee.
func TestScenario_PW_40_IntrospectionReturnsProjectedSub(t *testing.T) {
	t.Parallel()
	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithPairwiseSubject(pwPairwiseSalt),
		op.WithFeature(feature.Introspect),
	))
	hash, err := op.HashClientSecret(pwClientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	c := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "rp-pw-40-introspect",
		SecretHash:              hash,
		RedirectURIs:            []string{"https://rp.example.com/cb"},
		Scopes:                  []string{"openid", "profile", "email", "offline_access"},
		TokenEndpointAuthMethod: "client_secret_basic",
		SubjectType:             "pairwise",
	})

	tok := runPairwiseTokenFlow(t, tk, c, "https://rp.example.com/cb", "openid offline_access")
	if tok.RefreshToken == "" {
		t.Fatalf("/token response missing refresh_token (raw=%v)", tok.Raw)
	}
	idClaims := decodePWJWTClaims(t, tok.IDToken)
	idSub, _ := idClaims["sub"].(string)
	if idSub == "" || idSub == scenariokit.DefaultSubject {
		t.Fatalf("id_token sub=%q, want non-empty pairwise value", idSub)
	}

	form := url.Values{"token": {tok.RefreshToken}, "token_type_hint": {"refresh_token"}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/introspect", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.ID, pwClientSecret)
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /introspect: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/introspect status=%d body=%s", resp.StatusCode, body)
	}
	var intro map[string]any
	if err := json.Unmarshal(body, &intro); err != nil {
		t.Fatalf("decode /introspect body %s: %v", body, err)
	}
	if active, _ := intro["active"].(bool); !active {
		t.Fatalf("introspection inactive for live refresh token: %v", intro)
	}
	if got, _ := intro["sub"].(string); got != idSub {
		t.Errorf("introspection sub=%q must equal id_token sub=%q", got, idSub)
	}
}

// TestScenario_PW_41_SaltIsSensitiveOPSecret is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_41_SaltIsSensitiveOPSecret(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-41 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_42_DefaultAlgorithmShape is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_42_DefaultAlgorithmShape(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-42 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_43_DifferentSectorsProduceDifferentSubs confirms
// that two clients whose sector_identifier hosts differ receive
// different "sub" values for the same internal subject. The two
// clients here register single redirect URIs on disjoint hosts
// (alpha.example vs beta.example); the OIDC Core §8.1 sector
// resolution falls back to the redirect host when
// sector_identifier_uri is absent, so the two flows derive the
// pairwise sub against different sectors.
//
// Spec: OIDC Core 1.0 §8.1 (sector grouping enforces disjoint
// pseudonyms across sector boundaries).
func TestScenario_PW_43_DifferentSectorsProduceDifferentSubs(t *testing.T) {
	t.Parallel()
	tk := newPairwiseProvider(t)
	alpha := pairwiseClient(t, tk, "rp-pw-43-alpha", "https://alpha.example/cb")
	beta := pairwiseClient(t, tk, "rp-pw-43-beta", "https://beta.example/cb")

	subAlpha := runPairwiseFlow(t, tk, alpha, "https://alpha.example/cb")
	subBeta := runPairwiseFlow(t, tk, beta, "https://beta.example/cb")
	if subAlpha == subBeta {
		t.Errorf("pairwise subs collided across sectors (%q == %q)", subAlpha, subBeta)
	}
}

// TestScenario_PW_44_SameSectorProducesSameSub confirms the
// converse of PW-43: two clients that resolve to the same sector
// (here, the same redirect host) receive the same pairwise "sub"
// for the same internal subject. The grouping is the whole point
// of the sector concept — applications a user owns under one
// brand share an identity even when the OAuth client_id differs.
//
// Spec: OIDC Core 1.0 §8.1.
func TestScenario_PW_44_SameSectorProducesSameSub(t *testing.T) {
	t.Parallel()
	tk := newPairwiseProvider(t)
	first := pairwiseClient(t, tk, "rp-pw-44-first", "https://shared.example/cb")
	second := pairwiseClient(t, tk, "rp-pw-44-second", "https://shared.example/cb")

	subFirst := runPairwiseFlow(t, tk, first, "https://shared.example/cb")
	subSecond := runPairwiseFlow(t, tk, second, "https://shared.example/cb")
	if subFirst != subSecond {
		t.Errorf("pairwise subs diverged within shared sector (%q != %q)", subFirst, subSecond)
	}
}

// TestScenario_PW_45_PublicClientUsesLocalAccountID confirms the
// pairwise transform is scoped per client rather than per provider: on
// an OP enrolled with op.WithPairwiseSubject, a client registered
// subject_type=public still receives the OP-internal account id
// verbatim. OIDC Core 1.0 §8 makes subject_type per-client metadata, so
// enabling pairwise globally must not silently pseudonymise clients
// that never asked for it — an RP correlating against its own user
// table would break at the moment another tenant enrolled.
//
// Spec: OIDC Core 1.0 §8 / RFC 7591 §2.
func TestScenario_PW_45_PublicClientUsesLocalAccountID(t *testing.T) {
	t.Parallel()

	tk := newPairwiseProvider(t)
	c := pairwisePublicClient(t, tk, "rp-pw-45-public", "https://rp-pw-45.example.com/cb")

	sub := runPairwiseFlow(t, tk, c, "https://rp-pw-45.example.com/cb")
	if sub != scenariokit.DefaultSubject {
		t.Errorf("subject_type=public sub=%q want the raw account id %q; "+
			"the pairwise transform must not run for a public client", sub, scenariokit.DefaultSubject)
	}
}

// TestScenario_PW_46_PairwiseSubLengthBounded pins the OIDC Core 1.0
// §8 recommendation that a sub stays within 255 characters. The value
// is persisted by every RP that stores it and echoed on every token, so
// an unbounded identifier would push past column widths RPs sized
// against the spec's guidance.
//
// Spec: OIDC Core 1.0 §8 (sub SHOULD NOT exceed 255 ASCII characters).
func TestScenario_PW_46_PairwiseSubLengthBounded(t *testing.T) {
	t.Parallel()

	tk := newPairwiseProvider(t)
	c := pairwiseClient(t, tk, "rp-pw-46", "https://rp-pw-46.example.com/cb")

	sub := runPairwiseFlow(t, tk, c, "https://rp-pw-46.example.com/cb")
	if sub == scenariokit.DefaultSubject {
		t.Fatalf("sub=%q is the raw account id; pairwise projection did not run", sub)
	}
	if len(sub) > 255 {
		t.Errorf("pairwise sub is %d chars, want <= 255", len(sub))
	}
	// ASCII-only: the spec's 255 bound is stated in characters, and a
	// multi-byte value would silently consume more storage than an RP
	// sizing a varchar(255) against the spec would expect.
	for i, r := range sub {
		if r > 127 {
			t.Fatalf("pairwise sub contains non-ASCII rune %q at %d", r, i)
		}
	}
}

// TestScenario_PW_50_IDTokenSubFollowsSubjectType asserts both
// directions of the id_token projection on ONE provider: the pairwise
// client receives a pseudonym, the public client receives the raw
// account id, for the same authenticated end user. Asserting the pair
// together is what makes the row meaningful — either arm alone passes
// against a projector stuck in a single mode.
//
// Spec: OIDC Core 1.0 §8 / §2 (id_token sub).
func TestScenario_PW_50_IDTokenSubFollowsSubjectType(t *testing.T) {
	t.Parallel()

	tk := newPairwiseProvider(t)
	pairwiseSub, publicSub := pairwiseSubjectTypePair(t, tk, "pw-50")

	if pairwiseSub == scenariokit.DefaultSubject {
		t.Errorf("pairwise client id_token sub=%q must not be the raw account id", pairwiseSub)
	}
	if publicSub != scenariokit.DefaultSubject {
		t.Errorf("public client id_token sub=%q want the raw account id %q", publicSub, scenariokit.DefaultSubject)
	}
	if pairwiseSub == publicSub {
		t.Errorf("both clients resolved to %q; subject_type must decide the projection", pairwiseSub)
	}
}

// TestScenario_PW_51_UserinfoSubFollowsSubjectType asserts /userinfo
// applies the same per-client rule as the id_token, in both directions.
// A divergence here would hand one RP two identifiers for one user
// across two endpoints of the same OP, which OIDC Core 1.0 §5.3.2
// forbids by requiring the userinfo sub to match the id_token sub.
//
// Spec: OIDC Core 1.0 §5.3.2 / §8.
func TestScenario_PW_51_UserinfoSubFollowsSubjectType(t *testing.T) {
	t.Parallel()

	tk := newPairwiseProvider(t)
	tk.Store.PutUser(context.Background(), &store.User{Subject: scenariokit.DefaultSubject})

	pairwiseRP := pairwiseClient(t, tk, "rp-pw-51-pairwise", "https://rp-pw-51-pairwise.example.com/cb")
	publicRP := pairwisePublicClient(t, tk, "rp-pw-51-public", "https://rp-pw-51-public.example.net/cb")

	pairwiseTok := runPairwiseTokenFlow(t, tk, pairwiseRP, "https://rp-pw-51-pairwise.example.com/cb", "openid")
	publicTok := runPairwiseTokenFlow(t, tk, publicRP, "https://rp-pw-51-public.example.net/cb", "openid")

	pairwiseID, _ := decodePWJWTClaims(t, pairwiseTok.IDToken)["sub"].(string)
	publicID, _ := decodePWJWTClaims(t, publicTok.IDToken)["sub"].(string)

	pairwiseUI, _ := pairwiseGetUserInfo(t, tk, pairwiseTok.AccessToken)["sub"].(string)
	publicUI, _ := pairwiseGetUserInfo(t, tk, publicTok.AccessToken)["sub"].(string)

	if pairwiseUI != pairwiseID {
		t.Errorf("pairwise userinfo sub=%q must equal its id_token sub=%q", pairwiseUI, pairwiseID)
	}
	if pairwiseUI == scenariokit.DefaultSubject {
		t.Errorf("pairwise userinfo sub=%q leaked the raw account id", pairwiseUI)
	}
	if publicUI != publicID {
		t.Errorf("public userinfo sub=%q must equal its id_token sub=%q", publicUI, publicID)
	}
	if publicUI != scenariokit.DefaultSubject {
		t.Errorf("public userinfo sub=%q want the raw account id %q", publicUI, scenariokit.DefaultSubject)
	}
}

// TestScenario_PW_52_IntrospectionSubFollowsSubjectType pins that the
// introspection egress projects against the subject_type of the client
// the TOKEN was issued to. Both directions run on one provider so a
// projector that ignored client metadata fails on one arm.
//
// The cross-client half of this rule — a delegated resource server
// reading another client's token still gets that token's pseudonym —
// is bound by introspection#INT-015, which drives the
// op.ProtectedResource.IntrospectionClients path this row does not.
//
// Spec: RFC 7662 §2.2 / OIDC Core 1.0 §8.
func TestScenario_PW_52_IntrospectionSubFollowsSubjectType(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithPairwiseSubject(pwPairwiseSalt),
		op.WithFeature(feature.Introspect),
	))
	tk.Store.PutUser(context.Background(), &store.User{Subject: scenariokit.DefaultSubject})

	// Registered inline rather than through pairwiseClient: this row
	// introspects a refresh token, so both arms need offline_access.
	pairwiseRP := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "rp-pw-52-pairwise",
		SecretHash:              mustPWSecretHash(t),
		RedirectURIs:            []string{"https://rp-pw-52-pairwise.example.com/cb"},
		Scopes:                  []string{"openid", "profile", "email", "offline_access"},
		TokenEndpointAuthMethod: "client_secret_basic",
		SubjectType:             "pairwise",
	})
	publicRP := pairwisePublicClient(t, tk, "rp-pw-52-public", "https://rp-pw-52-public.example.net/cb")

	pairwiseTok := runPairwiseTokenFlow(t, tk, pairwiseRP,
		"https://rp-pw-52-pairwise.example.com/cb", "openid offline_access")
	publicTok := runPairwiseTokenFlow(t, tk, publicRP,
		"https://rp-pw-52-public.example.net/cb", "openid offline_access")

	pairwiseID, _ := decodePWJWTClaims(t, pairwiseTok.IDToken)["sub"].(string)

	pairwiseIntro := pairwiseIntrospect(t, tk, pairwiseRP.ID, pairwiseTok.RefreshToken)
	if got, _ := pairwiseIntro["sub"].(string); got != pairwiseID {
		t.Errorf("pairwise introspection sub=%q must equal its id_token sub=%q", got, pairwiseID)
	}
	publicIntro := pairwiseIntrospect(t, tk, publicRP.ID, publicTok.RefreshToken)
	if got, _ := publicIntro["sub"].(string); got != scenariokit.DefaultSubject {
		t.Errorf("public introspection sub=%q want the raw account id %q", got, scenariokit.DefaultSubject)
	}
}

// TestScenario_PW_53_HintSubComparedAgainstSubjectType pins that
// /end_session compares an id_token_hint's "sub" in the requesting
// client's subject space. For a pairwise client the session's
// OP-internal subject is projected before the comparison, so a hint
// carrying the pseudonym the client actually holds matches and
// short-circuits the confirmation gate, while a hint carrying the raw
// account id does not.
//
// The negative arm is the security-relevant one: if the comparison ran
// against the unprojected subject, anyone who learned an account's
// internal id could skip the logout confirmation for that user.
//
// Spec: OIDC RP-Initiated Logout 1.0 §2 / OIDC Core 1.0 §8.
func TestScenario_PW_53_HintSubComparedAgainstSubjectType(t *testing.T) {
	t.Parallel()

	const (
		clientID    = "rp-pw-53"
		callback    = "https://rp-pw-53.example.com/cb"
		postLogout  = "https://rp-pw-53.example.com/after-logout"
		hintSubject = scenariokit.DefaultSubject
	)

	tk := newPairwiseProvider(t)
	hash, err := op.HashClientSecret(pwClientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	c := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		PostLogoutRedirectURIs:  []string{postLogout},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
		SubjectType:             "pairwise",
	})

	// Establish a session in a browser jar, then reuse that jar so
	// /end_session resolves the session cookie the hint is compared
	// against. Without a resolvable session the handler admits any
	// hint, and the comparison this row is about never runs.
	browser := pairwiseBrowserClient(t, tk)
	pkce := scenariokit.NewPKCEPair("")
	flow := runPairwiseAuthorizeWithBrowser(t, tk, browser, hintSubject, scenariokit.AuthorizeParams{
		ClientID:    c.ID,
		RedirectURI: callback,
		Scope:       "openid",
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     c.ID,
		ClientSecret: pwClientSecret,
	})
	if tok.StatusCode != http.StatusOK || tok.IDToken == "" {
		t.Fatalf("/token status=%d body=%v", tok.StatusCode, tok.Raw)
	}
	pairwiseSub, _ := decodePWJWTClaims(t, tok.IDToken)["sub"].(string)
	if pairwiseSub == "" || pairwiseSub == hintSubject {
		t.Fatalf("id_token sub=%q must be a pairwise value distinct from the raw subject", pairwiseSub)
	}

	// Negative arm FIRST, while the session is still live: with no
	// resolvable session the handler admits any hint (there is nothing
	// to destroy), so running this after the logout below would pass
	// for the wrong reason. A hint naming the OP-internal account id
	// must not be read as naming this client's session.
	rawHint := mintPairwiseIDTokenHint(t, tk, c.ID, hintSubject)
	unmatched := pairwiseEndSession(t, tk, browser, rawHint, postLogout)
	defer func() { _ = unmatched.Body.Close() }()
	if unmatched.StatusCode == http.StatusFound && unmatched.Header.Get("Location") == postLogout {
		t.Errorf("raw-subject hint short-circuited the logout gate; the comparison must run " +
			"in the client's projected subject space")
	}
	// Pin WHY it did not short-circuit: the request must land on the
	// confirmation interstitial, not on some unrelated rejection that
	// would satisfy the check above for the wrong reason.
	if unmatched.StatusCode != http.StatusOK {
		t.Errorf("raw-subject hint: status=%d want 200 (the logout confirmation page)", unmatched.StatusCode)
	}

	// Positive arm: the hint the client legitimately holds names the
	// pseudonym, matches the projected session subject, and skips the
	// confirmation interstitial.
	matched := pairwiseEndSession(t, tk, browser, tok.IDToken, postLogout)
	defer func() { _ = matched.Body.Close() }()
	if matched.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(matched.Body)
		t.Fatalf("matching pairwise hint: status=%d want 302; body=%s", matched.StatusCode, body)
	}
	if loc := matched.Header.Get("Location"); loc != postLogout {
		t.Errorf("matching pairwise hint: Location=%q want %q", loc, postLogout)
	}
}

// TestScenario_PW_54_PairwiseClaimsSubValueMustMatch is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_54_PairwiseClaimsSubValueMustMatch(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-54 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_60_SaltRotationInvalidatesAllSubs pins the
// operational consequence embedder documentation has to carry: the salt
// is an input to the hash, so rotating it changes every pairwise sub
// the OP will ever emit, for every client at once. An RP keyed on the
// old value sees its users as strangers. The test drives two providers
// that differ ONLY by salt and asserts the same client and the same end
// user resolve to different subjects.
//
// Spec: OIDC Core 1.0 §8.1 (the pairwise input set is OP-chosen; the
// salt is part of it).
func TestScenario_PW_60_SaltRotationInvalidatesAllSubs(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-pw-60"
		callback = "https://rp-pw-60.example.com/cb"
	)
	subFor := func(salt []byte) string {
		tk := testkit.NewProvider(t, testkit.WithOptions(op.WithPairwiseSubject(salt)))
		c := pairwiseClient(t, tk, clientID, callback)
		return runPairwiseFlow(t, tk, c, callback)
	}

	before := subFor(pwPairwiseSalt)
	after := subFor([]byte("pw-pairwise-ROTATED-salt-32byte!"))

	if before == "" || after == "" {
		t.Fatalf("empty pairwise sub (before=%q after=%q)", before, after)
	}
	if before == scenariokit.DefaultSubject || after == scenariokit.DefaultSubject {
		t.Fatalf("pairwise projection did not run (before=%q after=%q)", before, after)
	}
	if before == after {
		t.Errorf("same sub %q under two different salts; the salt must be an input to the hash", before)
	}
}

// TestScenario_PW_61_LocalIDNotLeakedInAuditPayload is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_61_LocalIDNotLeakedInAuditPayload(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-61 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_62_DiscoveryAdvertisesPairwiseWhenEnabled is the
// complement of PW-01, which pins the default document to ["public"]:
// once the OP is enrolled with op.WithPairwiseSubject, the REQUIRED
// subject_types_supported metadata MUST also list "pairwise" so an RP
// discovers that it may register for it. Withholding the value would
// make every pairwise registration a trial-and-error 400.
//
// Spec: OIDC Core 1.0 §8 / OIDC Discovery 1.0 §3
// (subject_types_supported is REQUIRED).
func TestScenario_PW_62_DiscoveryAdvertisesPairwiseWhenEnabled(t *testing.T) {
	t.Parallel()

	tk := newPairwiseProvider(t)
	_, _, doc := fetchDiscovery(t, tk.Server.URL)

	raw, ok := doc["subject_types_supported"].([]any)
	if !ok {
		t.Fatalf("subject_types_supported missing or wrong type: %T", doc["subject_types_supported"])
	}
	got := make([]string, 0, len(raw))
	for i, v := range raw {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("subject_types_supported[%d]=%v not a string", i, v)
		}
		got = append(got, s)
	}
	slices.Sort(got)
	want := []string{"pairwise", "public"}
	if !slices.Equal(got, want) {
		t.Errorf("subject_types_supported=%v want %v when pairwise is enrolled", got, want)
	}
}

// TestScenario_PW_63_EmbedderHookForSaltAndHashFunction pins the two
// public seams an embedder uses to own the pairwise derivation. The OP
// splits the row's single hypothetical hook in two, deliberately:
// op.WithPairwiseSubject takes the per-environment salt and keeps the
// library's vetted hash, while op.WithSubjectGenerator replaces the
// derivation wholesale for embedders whose strategy the built-in shape
// cannot express. The test drives both and asserts each reaches the
// id_token "sub".
//
// Spec: OIDC Core 1.0 §8.1 (the derivation is OP-defined).
func TestScenario_PW_63_EmbedderHookForSaltAndHashFunction(t *testing.T) {
	t.Parallel()

	const callback = "https://rp-pw-63.example.com/cb"

	// Seam 1: embedder-supplied salt, library-owned hash. Reaching a
	// non-raw sub is the evidence the option is wired through to
	// issuance; PW-60 separately proves the salt itself is an input.
	tkSalt := newPairwiseProvider(t)
	subFromSalt := runPairwiseFlow(t, tkSalt, pairwiseClient(t, tkSalt, "rp-pw-63-salt", callback), callback)
	if subFromSalt == "" || subFromSalt == scenariokit.DefaultSubject {
		t.Errorf("WithPairwiseSubject did not reach the sub claim (got %q)", subFromSalt)
	}

	// Seam 2: a fully embedder-owned generator. The sentinel shape is
	// one the library would never emit, so observing it on the wire
	// proves the generator — not a library default — produced the sub.
	tkGen := testkit.NewProvider(t, testkit.WithOptions(
		op.WithSubjectGenerator(pwFixedGenerator{prefix: "embedder-owned:"}),
	))
	c := tkGen.RegisterClient(t, testkit.ClientFixture{
		ID:                      "rp-pw-63-generator",
		SecretHash:              mustPWSecretHash(t),
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	subFromGen := runPairwiseFlow(t, tkGen, c, callback)
	want := "embedder-owned:" + scenariokit.DefaultSubject
	if subFromGen != want {
		t.Errorf("WithSubjectGenerator sub=%q want %q", subFromGen, want)
	}
}

// pwFixedGenerator is a deterministic embedder-owned
// [op.SubjectGenerator] used by PW-63. It prefixes the OP-internal user
// id so the wire value is unmistakably the embedder's own product.
type pwFixedGenerator struct{ prefix string }

func (g pwFixedGenerator) Generate(_ context.Context, in op.SubjectGeneratorInput) (subject.Subject, error) {
	return subject.Subject(g.prefix + in.InternalUserID), nil
}

// TestScenario_PW_64_SectorURIFetchHasBoundedTimeout is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_64_SectorURIFetchHasBoundedTimeout(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-64 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_65_SectorURIResponseCacheablePolicyOPDefined is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_65_SectorURIResponseCacheablePolicyOPDefined(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-65 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_70_RejectsSwitchOnUsedStoreWithWipedMarker pins the
// empty-store edge case for the subject-mode immutability gate. A
// re-used metadata store whose [store.SubjectModeKey] row was wiped
// (truncation, deliberate manipulation, or a tooling bug) but whose
// [store.OpInitKey] sentinel survives MUST refuse a non-public
// op.New construction. Without the sentinel probe the gate would
// fall through to the "fresh install" branch and silently re-key
// every future "sub" against the new strategy. The test seeds the
// op-init sentinel directly to simulate the post-wipe shape because
// no public API exposes a metadata-only truncation.
//
// Spec: OIDC Core 1.0 §8 (sub stability) / project v0.9.1 contract.
func TestScenario_PW_70_RejectsSwitchOnUsedStoreWithWipedMarker(t *testing.T) {
	t.Parallel()
	st := inmem.New()
	if err := st.Metadata().Set(context.Background(), store.OpInitKey, store.OpInitMarker); err != nil {
		t.Fatalf("seed op-init sentinel: %v", err)
	}
	// MinimalOptions seeds its own inmem store; we override with WithStore
	// so the gate observes the sentinel we just stamped. The pairwise
	// option drives the gate into the "non-public on a previously-used
	// store" branch the row pins.
	opts := testkit.MinimalOptions(t,
		op.WithStore(st),
		op.WithPairwiseSubject(pwPairwiseSalt),
	)
	_, err := op.New(opts...)
	if !errors.Is(err, op.ErrSubjectModeMismatch) {
		t.Fatalf("op.New err=%v, want ErrSubjectModeMismatch (wiped marker on used store)", err)
	}
}
