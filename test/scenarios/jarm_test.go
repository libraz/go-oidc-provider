package scenarios_test

// Catalog: test/scenarios/catalog/jarm.yaml (JARM-NNN)
// Spec:
//   - OAuth 2.0 JWT Secured Authorization Response Mode (JARM)
//   - RFC 7515 — JSON Web Signature
//   - RFC 7516 — JSON Web Encryption
//   - RFC 8414 — OAuth 2.0 Authorization Server Metadata
//   - RFC 9101 — JWT-Secured Authorization Request (JAR)
//   - OpenID Connect Core 1.0 §3.1.2, §3.3
//   - RFC 9207 — Authorization Server Issuer Identification

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

// jarmTestClientID is the canonical client_id every JARM scenario
// registers when the test does not need a private fixture. Pinning the
// value keeps "aud" / "iss" assertions readable.
const jarmTestClientID = "rp-jarm-scenarios"

// jarmTestRedirectURI is the registered redirect_uri the JARM scenarios
// share. The host is the testkit's invalid-TLD convention so the tests
// never hit a real network endpoint.
const jarmTestRedirectURI = "https://rp.testkit.invalid/callback"

// jarmTestSecret is the cleartext client_secret hashed into every JARM
// scenario fixture. The value is never used as a real credential — it
// only satisfies the [testkit.ClientFixture] hash field.
//
//nolint:gosec // test fixture: not a real credential.
const jarmTestSecret = "rp-jarm-scenarios-secret"

// newJARMProvider boots a [testkit.Provider] with [feature.JARM] on and
// registers the canonical JARM client. Tests share the helper so the
// fixture stays uniform across the catalog rows.
func newJARMProvider(t *testing.T) (*testkit.Provider, *store.Client) {
	t.Helper()
	hash, err := op.HashClientSecret(jarmTestSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithFeature(feature.JARM)))
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      jarmTestClientID,
		SecretHash:              hash,
		RedirectURIs:            []string{jarmTestRedirectURI},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
		ResponseTypes:           []string{"code"},
		GrantTypes:              []string{"authorization_code"},
	})
	return tk, rp
}

// runJARMCodeFlow is the canonical happy-path driver the JARM envelope
// rows share. It runs response_type=code with the supplied
// response_mode and returns the decoded JWT claims captured from the
// callback URL ("query.jwt" / "jwt") delivers the JWT in the query
// string).
func runJARMCodeFlow(t *testing.T, tk *testkit.Provider, rp *store.Client, responseMode, state string) map[string]any {
	t.Helper()
	pkce := scenariokit.NewPKCEPair("")
	params := scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: jarmTestRedirectURI,
		PKCE:        pkce,
		Extra:       url.Values{"response_mode": {responseMode}},
	}
	if state != "" {
		params.State = state
	}
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, params)
	if flow.Error != "" {
		t.Fatalf("authorize error=%s desc=%s", flow.Error, flow.ErrorDesc)
	}
	rawJWT := flow.Location.Query().Get("response")
	if rawJWT == "" {
		t.Fatalf("'response' parameter missing from callback: %s", flow.Location.String())
	}
	return decodeScenarioJWTClaims(t, rawJWT)
}

// jarmAuthorizeQuery returns the canonical /authorize query parameters
// for a JARM error scenario (prompt=none, no session). The caller sets
// response_mode and any overrides on the returned url.Values.
func jarmAuthorizeQuery(clientID, redirectURI, responseMode string) url.Values {
	pkce := scenariokit.NewPKCEPair("")
	return url.Values{
		"client_id":             {clientID},
		"response_type":         {"code"},
		"redirect_uri":          {redirectURI},
		"scope":                 {"openid"},
		"state":                 {scenariokit.DefaultState},
		"nonce":                 {scenariokit.DefaultNonce},
		"code_challenge":        {pkce.Challenge},
		"code_challenge_method": {pkce.Method},
		"prompt":                {"none"},
		"response_mode":         {responseMode},
	}
}

// doJARMAuthorize runs a single GET /authorize hop without following
// redirects, returning the response so the caller can inspect the
// transport-specific shape (302 redirect, 200 HTML body, ...).
func doJARMAuthorize(t *testing.T, tk *testkit.Provider, query url.Values) *http.Response {
	t.Helper()
	authorizeURL := tk.Server.URL + "/oidc/auth?" + query.Encode()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, authorizeURL, http.NoBody)
	if err != nil {
		t.Fatalf("build /authorize request: %v", err)
	}
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	return resp
}

// TestScenario_JARM_001_DiscoverySurfaceAdvertised confirms that
// /.well-known/openid-configuration on a JARM-enabled OP advertises the
// signing-alg list with at least "ES256" and a response_modes_supported
// matching the v1.0 set ["query", "form_post", "query.jwt",
// "fragment.jwt", "form_post.jwt", "jwt"]. The encryption-alg / -enc
// fields are absent because JWE for JARM responses is out-of-scope, and
// "web_message" / "web_message.jwt" are absent because the transport
// is not implemented.
//
// Spec: JARM §6 / RFC 8414 §2.
func TestScenario_JARM_001_DiscoverySurfaceAdvertised(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithFeature(feature.JARM)))
	_, _, doc := fetchDiscovery(t, tk.Server.URL)

	signing, _ := doc["authorization_signing_alg_values_supported"].([]any)
	if len(signing) == 0 {
		t.Fatalf("authorization_signing_alg_values_supported missing or empty: %v", doc["authorization_signing_alg_values_supported"])
	}
	hasES256 := false
	for _, v := range signing {
		if s, _ := v.(string); s == "ES256" {
			hasES256 = true
			break
		}
	}
	if !hasES256 {
		t.Errorf("authorization_signing_alg_values_supported must include ES256: %v", signing)
	}

	if _, ok := doc["authorization_encryption_alg_values_supported"]; ok {
		t.Errorf("authorization_encryption_alg_values_supported MUST NOT be published in v1.0 (JWE OOS): %v", doc["authorization_encryption_alg_values_supported"])
	}
	if _, ok := doc["authorization_encryption_enc_values_supported"]; ok {
		t.Errorf("authorization_encryption_enc_values_supported MUST NOT be published in v1.0 (JWE OOS): %v", doc["authorization_encryption_enc_values_supported"])
	}

	modesAny, _ := doc["response_modes_supported"].([]any)
	got := make([]string, 0, len(modesAny))
	for _, v := range modesAny {
		s, _ := v.(string)
		got = append(got, s)
	}
	want := []string{"query", "form_post", "query.jwt", "fragment.jwt", "form_post.jwt", "jwt"}
	if len(got) != len(want) {
		t.Fatalf("response_modes_supported=%v want %v", got, want)
	}
	for i, mode := range want {
		if got[i] != mode {
			t.Errorf("response_modes_supported[%d]=%q want %q (full=%v)", i, got[i], mode, got)
		}
	}
	for _, mode := range got {
		if mode == "web_message" || mode == "web_message.jwt" {
			t.Errorf("response_modes_supported must NOT include %q in v1.0: %v", mode, got)
		}
	}
}

func TestScenario_JARM_010_JwtModeFragmentForImplicitHybrid(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JARM-010")
}

// TestScenario_JARM_011_JwtModeQueryForCode confirms that an
// /authorize request with response_type=code and the bare alias
// response_mode=jwt resolves to query-delivery (per JARM §4.3) and
// that the resulting JARM JWT carries code, aud, exp, state, and iss
// while omitting the scope claim.
//
// Spec: JARM §4.3 (response_mode=jwt resolution) / §4.1 (claim set).
func TestScenario_JARM_011_JwtModeQueryForCode(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-jarm-011"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-jarm-011-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithFeature(feature.JARM)))
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
		ResponseTypes:           []string{"code"},
		GrantTypes:              []string{"authorization_code"},
	})
	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		PKCE:        pkce,
		Extra:       url.Values{"response_mode": {"jwt"}},
	})

	if flow.Code != "" {
		t.Errorf("legacy 'code' parameter leaked alongside JARM response: %s", flow.Location.String())
	}
	if flow.Error != "" {
		t.Fatalf("authorize error=%s desc=%s", flow.Error, flow.ErrorDesc)
	}
	if flow.Location.RawFragment != "" || flow.Location.Fragment != "" {
		t.Errorf("response_type=code with response_mode=jwt must resolve to query delivery; got fragment=%q in %s",
			flow.Location.Fragment, flow.Location.String())
	}

	rawJWT := flow.Location.Query().Get("response")
	if rawJWT == "" {
		t.Fatalf("'response' parameter missing from callback: %s", flow.Location.String())
	}

	claims := decodeScenarioJWTClaims(t, rawJWT)

	if got, _ := claims["code"].(string); got == "" {
		t.Errorf("code claim missing or empty: %v", claims)
	}
	if got := claims["aud"]; got != rp.ID {
		t.Errorf("aud=%v want %q", got, rp.ID)
	}
	if got := claims["iss"]; got != tk.Issuer {
		t.Errorf("iss=%v want %q", got, tk.Issuer)
	}
	if got := claims["state"]; got != scenariokit.DefaultState {
		t.Errorf("state=%v want %q", got, scenariokit.DefaultState)
	}
	if _, ok := claims["exp"].(float64); !ok {
		t.Errorf("exp must be a JSON number: %T (claims=%v)", claims["exp"], claims)
	}
	if _, present := claims["scope"]; present {
		t.Errorf("response_type=code JARM payload must NOT include scope: %v", claims)
	}
	if _, present := claims["error"]; present {
		t.Errorf("error claim leaked on success path: %v", claims)
	}
}

func TestScenario_JARM_012_JwtModeQueryForNone(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JARM-012")
}

// TestScenario_JARM_020_AudEqualsClientID asserts that the JARM
// response JWT's "aud" claim equals the requesting client_id. The check
// runs on the response_mode=query.jwt success path so the JWT envelope
// is unambiguously the JARM one.
//
// Spec: JARM §4.1 (aud claim).
func TestScenario_JARM_020_AudEqualsClientID(t *testing.T) {
	t.Parallel()

	tk, rp := newJARMProvider(t)
	claims := runJARMCodeFlow(t, tk, rp, "query.jwt", "")
	if got := claims["aud"]; got != rp.ID {
		t.Errorf("aud=%v (%T) want %q", got, got, rp.ID)
	}
}

// TestScenario_JARM_021_ExpClaimIsNumber asserts that the JARM response
// JWT carries an "exp" claim and that it is a JSON number (decoded as
// float64), representing UTC seconds since the Unix epoch.
//
// Spec: JARM §4.1 (exp claim) / RFC 7519 §4.1.4.
func TestScenario_JARM_021_ExpClaimIsNumber(t *testing.T) {
	t.Parallel()

	tk, rp := newJARMProvider(t)
	claims := runJARMCodeFlow(t, tk, rp, "query.jwt", "")
	exp, ok := claims["exp"].(float64)
	if !ok {
		t.Fatalf("exp must be a JSON number: %T (claims=%v)", claims["exp"], claims)
	}
	if exp <= 0 {
		t.Errorf("exp=%v must be a positive UTC seconds value", exp)
	}
}

// TestScenario_JARM_022_IssEqualsIssuer asserts that the JARM response
// JWT's "iss" claim equals the OP issuer URL the OP advertises in
// /.well-known/openid-configuration.
//
// Spec: JARM §4.1 (iss claim) / RFC 9207 §2.
func TestScenario_JARM_022_IssEqualsIssuer(t *testing.T) {
	t.Parallel()

	tk, rp := newJARMProvider(t)
	claims := runJARMCodeFlow(t, tk, rp, "query.jwt", "")
	if got := claims["iss"]; got != tk.Issuer {
		t.Errorf("iss=%v want %q", got, tk.Issuer)
	}
}

// TestScenario_JARM_023_StateRoundTripped asserts that a caller-supplied
// "state" parameter is round-tripped verbatim into the JARM response
// JWT's "state" claim. The test uses a non-default state value so the
// assertion fails if the OP accidentally defaulted.
//
// Spec: JARM §4.1 (state claim) / RFC 6749 §4.1.1.
func TestScenario_JARM_023_StateRoundTripped(t *testing.T) {
	t.Parallel()

	const customState = "jarm-023-state-roundtrip"
	tk, rp := newJARMProvider(t)
	claims := runJARMCodeFlow(t, tk, rp, "query.jwt", customState)
	if got := claims["state"]; got != customState {
		t.Errorf("state=%v want %q", got, customState)
	}
}

func TestScenario_JARM_030_ExpiredSecretSurfacesInvalidClient(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JARM-030")
}

func TestScenario_JARM_040_QueryJwtUnencryptedForbiddenForHybrid(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JARM-040")
}

func TestScenario_JARM_041_QueryJwtAllowedWithEncryption(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JARM-041")
}

func TestScenario_JARM_042_QueryJwtSuccessForCode(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JARM-042")
}

func TestScenario_JARM_043_QueryJwtSuccessForNone(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JARM-043")
}

func TestScenario_JARM_044_QueryJwtExpiredSecretBareError(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JARM-044")
}

// TestScenario_JARM_050_QueryJwtErrorRedirect drives /authorize with
// response_type=code, response_mode=query.jwt, and prompt=none against
// an unauthenticated session. The OP MUST surface "login_required" via
// a 302 redirect whose query string carries response=<signed JARM
// JWT>; the JWT's claims include error=login_required and the JARM
// envelope (state, aud, iss, exp).
//
// Spec: JARM §4.3 (query.jwt error transport) / OIDC Core §3.1.2.6.
func TestScenario_JARM_050_QueryJwtErrorRedirect(t *testing.T) {
	t.Parallel()

	tk, rp := newJARMProvider(t)
	resp := doJARMAuthorize(t, tk, jarmAuthorizeQuery(rp.ID, jarmTestRedirectURI, "query.jwt"))
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 302 body=%s", resp.StatusCode, string(body))
	}
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	if loc.Query().Get("error") != "" {
		t.Errorf("legacy 'error' parameter leaked alongside JARM JWT: %s", loc.String())
	}
	rawJWT := loc.Query().Get("response")
	if rawJWT == "" {
		t.Fatalf("'response' missing from query: %s", loc.String())
	}
	if loc.Fragment != "" || loc.RawFragment != "" {
		t.Errorf("query.jwt error must NOT use fragment delivery: %s", loc.String())
	}
	claims := decodeScenarioJWTClaims(t, rawJWT)
	if got := claims["error"]; got != "login_required" {
		t.Errorf("error=%v want login_required", got)
	}
	if got := claims["aud"]; got != rp.ID {
		t.Errorf("aud=%v want %q", got, rp.ID)
	}
	if got := claims["iss"]; got != tk.Issuer {
		t.Errorf("iss=%v want %q", got, tk.Issuer)
	}
	if got := claims["state"]; got != scenariokit.DefaultState {
		t.Errorf("state=%v want %q", got, scenariokit.DefaultState)
	}
	if _, ok := claims["exp"].(float64); !ok {
		t.Errorf("exp must be a JSON number: %T (claims=%v)", claims["exp"], claims)
	}
	if _, has := claims["code"]; has {
		t.Errorf("code claim leaked on error path: %v", claims)
	}
}

// TestScenario_JARM_051_FragmentJwtErrorRedirect drives the same
// prompt=none / login_required scenario as JARM-050 but with
// response_mode=fragment.jwt. The OP MUST emit a 302 whose URL
// fragment carries response=<signed JARM JWT>.
//
// Spec: JARM §4.3 (fragment.jwt error transport).
func TestScenario_JARM_051_FragmentJwtErrorRedirect(t *testing.T) {
	t.Parallel()

	tk, rp := newJARMProvider(t)
	resp := doJARMAuthorize(t, tk, jarmAuthorizeQuery(rp.ID, jarmTestRedirectURI, "fragment.jwt"))
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 302 body=%s", resp.StatusCode, string(body))
	}
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	if got := loc.Query().Get("response"); got != "" {
		t.Errorf("fragment.jwt must NOT place response in the query: %s", loc.String())
	}
	if got := loc.Query().Get("error"); got != "" {
		t.Errorf("legacy 'error' parameter leaked: %s", loc.String())
	}
	frag := loc.Fragment
	if frag == "" {
		// Some Go versions surface the raw fragment when it contains
		// percent-encoded bytes; fall back to RawFragment.
		frag = loc.RawFragment
	}
	if frag == "" {
		t.Fatalf("fragment is empty in %s", loc.String())
	}
	parsed, err := url.ParseQuery(frag)
	if err != nil {
		t.Fatalf("parse fragment %q: %v", frag, err)
	}
	rawJWT := parsed.Get("response")
	if rawJWT == "" {
		t.Fatalf("response missing in fragment %q", frag)
	}
	claims := decodeScenarioJWTClaims(t, rawJWT)
	if got := claims["error"]; got != "login_required" {
		t.Errorf("error=%v want login_required", got)
	}
	if got := claims["aud"]; got != rp.ID {
		t.Errorf("aud=%v want %q", got, rp.ID)
	}
	if got := claims["iss"]; got != tk.Issuer {
		t.Errorf("iss=%v want %q", got, tk.Issuer)
	}
	if got := claims["state"]; got != scenariokit.DefaultState {
		t.Errorf("state=%v want %q", got, scenariokit.DefaultState)
	}
	if _, ok := claims["exp"].(float64); !ok {
		t.Errorf("exp must be a JSON number: %T", claims["exp"])
	}
}

// TestScenario_JARM_052_FormPostJwtErrorRendered drives the same
// prompt=none scenario as JARM-050 but with response_mode=form_post.jwt.
// The OP MUST return 200 (text/html) with an auto-POST HTML form whose
// hidden "response" input carries the signed error JWT and whose action
// attribute is the registered redirect_uri.
//
// Spec: JARM §4.3 (form_post.jwt transport).
func TestScenario_JARM_052_FormPostJwtErrorRendered(t *testing.T) {
	t.Parallel()

	tk, rp := newJARMProvider(t)
	resp := doJARMAuthorize(t, tk, jarmAuthorizeQuery(rp.ID, jarmTestRedirectURI, "form_post.jwt"))
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, string(body))
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Errorf("Content-Type=%q want text/html prefix", got)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	bodyStr := string(body)
	if !strings.Contains(bodyStr, `action="`+jarmTestRedirectURI+`"`) {
		t.Errorf("body missing form action=%q: %s", jarmTestRedirectURI, bodyStr)
	}
	rawJWT := extractFormResponseInput(t, bodyStr)
	claims := decodeScenarioJWTClaims(t, rawJWT)
	if got := claims["error"]; got != "login_required" {
		t.Errorf("error=%v want login_required", got)
	}
	if got := claims["aud"]; got != rp.ID {
		t.Errorf("aud=%v want %q", got, rp.ID)
	}
	if got := claims["iss"]; got != tk.Issuer {
		t.Errorf("iss=%v want %q", got, tk.Issuer)
	}
	if got := claims["state"]; got != scenariokit.DefaultState {
		t.Errorf("state=%v want %q", got, scenariokit.DefaultState)
	}
	if _, ok := claims["exp"].(float64); !ok {
		t.Errorf("exp must be a JSON number: %T", claims["exp"])
	}
}

// extractFormResponseInput pulls the value of the
// <input name="response" value="..."/> field from a JARM form_post.jwt
// HTML body. The shape is fixed by the OP's emitter, so we
// substring-search rather than HTML-parse.
func extractFormResponseInput(tb testing.TB, body string) string {
	tb.Helper()
	const startTag = `name="response" value="`
	idx := strings.Index(body, startTag)
	if idx < 0 {
		tb.Fatalf("response field not found in body: %s", body)
	}
	rest := body[idx+len(startTag):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		tb.Fatalf("malformed response field: %s", body)
	}
	return rest[:end]
}

func TestScenario_JARM_053_WebMessageJwtErrorRendered(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JARM-053")
}

func TestScenario_JARM_054_ExpiredSecretAllTransports(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JARM-054")
}
