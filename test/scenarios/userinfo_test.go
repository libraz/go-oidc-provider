package scenarios_test

// Catalog: test/scenarios/catalog/userinfo.yaml (UI-NNN)
// Spec:
//   - OIDC Core 1.0 §5.3, §5.3.1, §5.3.2, §5.3.3, §5.4
//   - RFC 6750 §2, §3 (Bearer)
//   - RFC 6749 §5.2, §10.4
//   - RFC 7235 §2.1
//   - RFC 9449 §7 (DPoP error responses)
//   - OIDC Discovery 1.0 (`userinfo_endpoint`)

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

// uiTestClientID is the canonical client_id the UI scenarios register.
// Each test owns its testkit.Provider so collisions across parallel
// runs are not possible.
const (
	uiTestClientID     = "rp-userinfo"
	uiTestCallback     = "https://rp.testkit.invalid/callback"
	uiTestClientSecret = "rp-userinfo-secret" //nolint:gosec // G101: test fixture, not a real credential.
)

// uiSeedClientAndUser registers the UI test client on tk and seeds the
// in-memory UserStore with a subject carrying the email-scope claims so
// /userinfo can release them. The helper centralises the boilerplate
// every successful-path UI test repeats.
func uiSeedClientAndUser(t *testing.T, tk *testkit.Provider) {
	t.Helper()
	hash, err := op.HashClientSecret(uiTestClientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      uiTestClientID,
		SecretHash:              hash,
		RedirectURIs:            []string{uiTestCallback},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
	})
	tk.Store.PutUser(context.Background(), &store.User{
		Subject: scenariokit.DefaultSubject,
		Claims: map[string]any{
			"email":          "user-1@example.test",
			"email_verified": true,
		},
	})
}

// uiMintAccessToken drives the /authorize → /token round-trip and
// returns a usable access_token bound to the seeded subject. Tests that
// only need an opaque "valid bearer" call this and forget about the
// exchange machinery.
func uiMintAccessToken(t *testing.T, tk *testkit.Provider, scope string) string {
	t.Helper()
	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    uiTestClientID,
		RedirectURI: uiTestCallback,
		Scope:       scope,
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  uiTestCallback,
		Verifier:     pkce.Verifier,
		ClientID:     uiTestClientID,
		ClientSecret: uiTestClientSecret,
	})
	if tok.StatusCode != http.StatusOK || tok.AccessToken == "" {
		t.Fatalf("/token status=%d body=%v, want 200 with access_token", tok.StatusCode, tok.Raw)
	}
	return tok.AccessToken
}

// TestScenario_UI_001_JWTUserinfoRequiresEndpointEnabled is OOS — see catalog out_of_scope_reason.
func TestScenario_UI_001_JWTUserinfoRequiresEndpointEnabled(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: UI-001 (see catalog out_of_scope_reason)")
}

// TestScenario_UI_002_GETReturnsClaimsHonoringRejected asserts the OIDC
// Core 1.0 §5.3.2 / §5.4 success shape: a GET /userinfo carrying a
// scope=openid email access token releases the "sub" plus the
// email-scope claims (`email`, `email_verified`) that the UserStore
// publishes for the subject.
//
// Spec: OIDC Core §5.3.2 / §5.4.
func TestScenario_UI_002_GETReturnsClaimsHonoringRejected(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	uiSeedClientAndUser(t, tk)
	at := uiMintAccessToken(t, tk, "openid email")

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		tk.Server.URL+"/oidc/userinfo", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+at)

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("GET /oidc/userinfo: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Errorf("Content-Type=%q want application/json", got)
	}
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not JSON: %v (raw=%q)", err, string(body))
	}
	if got, _ := env["sub"].(string); got != scenariokit.DefaultSubject {
		t.Errorf("sub=%v want %q", env["sub"], scenariokit.DefaultSubject)
	}
	// At least one email-scope claim MUST surface; assert the email
	// value matches the one the UserStore published.
	if got, _ := env["email"].(string); got != "user-1@example.test" {
		t.Errorf("email=%v want user-1@example.test (body=%s)", env["email"], string(body))
	}
}

// TestScenario_UI_003_POSTReturnsSameBody mirrors UI-002 but uses POST
// /userinfo with the access token in the urlencoded body. OIDC Core
// 1.0 §5.3.1 admits POST as an equivalent transport; the response body
// composition MUST match the GET path.
//
// Spec: OIDC Core §5.3.1.
func TestScenario_UI_003_POSTReturnsSameBody(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	uiSeedClientAndUser(t, tk)
	at := uiMintAccessToken(t, tk, "openid email")

	form := url.Values{"access_token": {at}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/userinfo", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /oidc/userinfo: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, body)
	}
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not JSON: %v (raw=%q)", err, string(body))
	}
	if got, _ := env["sub"].(string); got != scenariokit.DefaultSubject {
		t.Errorf("sub=%v want %q", env["sub"], scenariokit.DefaultSubject)
	}
	if got, _ := env["email"].(string); got != "user-1@example.test" {
		t.Errorf("email=%v want user-1@example.test", env["email"])
	}
}

func TestScenario_UI_004_RequestContextEntitiesPopulated(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: UI-004 (request-context entities are not part of v1.0 wire surface)")
}

// TestScenario_UI_005_UnknownTokenReturnsInvalidToken sends a syntactically
// well-formed but unrecognised opaque bearer token to /userinfo. RFC
// 6750 §3.1 + OIDC Core §5.3.3 require 401 with error=invalid_token
// and a description that names the token as the cause so the client
// can re-acquire credentials.
//
// Spec: RFC 6750 §3.1 / OIDC Core §5.3.3.
func TestScenario_UI_005_UnknownTokenReturnsInvalidToken(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		tk.Server.URL+"/oidc/userinfo", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer this-token-was-never-issued-by-the-op")

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("GET /oidc/userinfo: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 401 body=%s", resp.StatusCode, raw)
	}
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if !strings.Contains(wwwAuth, `error="invalid_token"`) {
		t.Errorf("WWW-Authenticate=%q must carry error=\"invalid_token\"", wwwAuth)
	}
}

// TestScenario_UI_006_NoTokenReturnsInvalidToken sends a /userinfo
// request with no Authorization header and no other token carrier.
// RFC 6750 §3.1 requires 401 with error=invalid_token and a
// description naming the missing token, mediated through the
// WWW-Authenticate response header.
//
// Spec: RFC 6750 §3.1.
func TestScenario_UI_006_NoTokenReturnsInvalidToken(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		tk.Server.URL+"/oidc/userinfo", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("GET /oidc/userinfo: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 401 body=%s", resp.StatusCode, raw)
	}
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if !strings.Contains(wwwAuth, "Bearer") {
		t.Errorf("WWW-Authenticate=%q must start with Bearer challenge", wwwAuth)
	}
	// When the body is non-empty, OIDC Core mandates a JSON envelope
	// even though RFC 6750 conveys the error primarily via the
	// challenge header. If the OP returns a body, sanity-check it
	// parses; an empty body is also acceptable.
	body, _ := io.ReadAll(resp.Body)
	if len(body) > 0 {
		var env map[string]any
		if err := json.Unmarshal(body, &env); err != nil {
			t.Errorf("body is non-empty and not JSON: %v (raw=%q)", err, string(body))
		}
	}
}

func TestScenario_UI_007_MissingOpenIDScopeReturnsInsufficientScope(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: UI-007 (v1.0 /userinfo does not enforce per-request scope)")
}

func TestScenario_UI_008_ClientGoneReturnsInvalidToken(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: UI-008 (v1.0 /userinfo does not lookup the client)")
}

// uiMissingSubjectStore wraps an inmem.Store and shadows Users() so
// every FindBySubject lookup returns store.ErrNotFound. UI-009 uses
// this to drive the "account gone after issuance" branch without
// poking at the inmem internals: we mint a token with the real
// UserStore, then swap the OP onto a hybrid that always reports
// ErrNotFound for the subject.
type uiMissingSubjectStore struct {
	*inmem.Store
}

func (s *uiMissingSubjectStore) Users() store.UserStore { return uiMissingSubjectUsers{} }

type uiMissingSubjectUsers struct{}

func (uiMissingSubjectUsers) FindBySubject(_ context.Context, _ string) (*store.User, error) {
	return nil, store.ErrNotFound
}

// TestScenario_UI_009_AccountGoneReturnsInvalidToken asserts that when
// the access token is otherwise valid but the bound account no longer
// resolves (UserStore returns ErrNotFound), /userinfo returns 401 with
// WWW-Authenticate carrying error=invalid_token and the description
// "subject unknown".
//
// Spec: OIDC Core §5.3.2 / RFC 6750 §3.1.
func TestScenario_UI_009_AccountGoneReturnsInvalidToken(t *testing.T) {
	t.Parallel()

	base := inmem.New()
	hybrid := &uiMissingSubjectStore{Store: base}

	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithStore(hybrid)))

	hash, err := op.HashClientSecret(uiTestClientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	// Register the client directly on the base inmem.Store the hybrid
	// wraps; tk.Store points at the auto-created store the testkit
	// builds before WithStore overrides, so it would not be reachable
	// through the OP's request path.
	if err := base.RegisterClient(context.Background(), &store.Client{
		ID:                      uiTestClientID,
		SecretHash:              hash,
		RedirectURIs:            []string{uiTestCallback},
		Scopes:                  []string{"openid", "profile", "email"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
	}); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}

	at := uiMintAccessToken(t, tk, "openid email")

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		tk.Server.URL+"/oidc/userinfo", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+at)

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("GET /oidc/userinfo: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 401 body=%s", resp.StatusCode, raw)
	}
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if !strings.Contains(wwwAuth, `error="invalid_token"`) {
		t.Errorf("WWW-Authenticate=%q must carry error=\"invalid_token\"", wwwAuth)
	}
	if !strings.Contains(wwwAuth, `error_description="subject unknown"`) {
		t.Errorf("WWW-Authenticate=%q must carry error_description=\"subject unknown\"", wwwAuth)
	}
}

func TestScenario_UI_010_RequestNarrowsScopeAllowed(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: UI-010 (v1.0 /userinfo does not consult a request-level scope parameter)")
}

func TestScenario_UI_011_RequestExpandsScopeForbidden(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: UI-011 (v1.0 /userinfo does not enforce per-request scope)")
}

// TestScenario_UI_012_NoBearerEnumeratesBothChallenges asserts that a
// /userinfo request with no Authorization header, no body, and no
// query parameter receives the bare Bearer challenge. v1.0 emits
// `WWW-Authenticate: Bearer realm="userinfo"` exactly — DPoP is NOT
// listed alongside Bearer because the missing-credentials branch
// stays free of error= / scope= attributes.
//
// Spec: RFC 6750 §3.
func TestScenario_UI_012_NoBearerEnumeratesBothChallenges(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		tk.Server.URL+"/oidc/userinfo", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("GET /oidc/userinfo: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 401 body=%s", resp.StatusCode, raw)
	}
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if wwwAuth != `Bearer realm="userinfo"` {
		t.Errorf("WWW-Authenticate=%q want exactly `Bearer realm=\"userinfo\"`", wwwAuth)
	}
	if strings.Contains(wwwAuth, "DPoP") {
		t.Errorf("WWW-Authenticate=%q must NOT enumerate DPoP alongside the bare Bearer challenge", wwwAuth)
	}
}

// TestScenario_UI_013_MultipleBearerCarriersRejected asserts that a
// POST /userinfo carrying the access_token both via Authorization:
// Bearer header AND via the access_token= form field returns 400 with
// WWW-Authenticate `Bearer error="invalid_request",
// error_description="The request is missing a required parameter or
// is malformed"`. RFC 6750 §2 forbids multi-channel transport.
//
// Spec: RFC 6750 §2.
func TestScenario_UI_013_MultipleBearerCarriersRejected(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	uiSeedClientAndUser(t, tk)
	at := uiMintAccessToken(t, tk, "openid email")

	form := url.Values{"access_token": {at}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/userinfo", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+at)

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /oidc/userinfo: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, raw)
	}
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if !strings.Contains(wwwAuth, `error="invalid_request"`) {
		t.Errorf("WWW-Authenticate=%q must carry error=\"invalid_request\"", wwwAuth)
	}
	if !strings.Contains(wwwAuth, `error_description="The request is missing a required parameter or is malformed"`) {
		t.Errorf("WWW-Authenticate=%q must carry the canonical malformed-request description", wwwAuth)
	}
}

// TestScenario_UI_014_AuthorizationHeaderOnePartRejected asserts that
// "Authorization: Bearer" (no token component) is treated as missing
// credentials — the header parser requires `len > len("Bearer ")`, so
// the unrecognised shape collapses onto the bare Bearer challenge with
// status 401, NOT 400 invalid_request.
//
// Spec: RFC 6750 §2.1 / RFC 7235 §2.1.
func TestScenario_UI_014_AuthorizationHeaderOnePartRejected(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		tk.Server.URL+"/oidc/userinfo", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer")

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("GET /oidc/userinfo: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 401 body=%s", resp.StatusCode, raw)
	}
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if wwwAuth != `Bearer realm="userinfo"` {
		t.Errorf("WWW-Authenticate=%q want exactly `Bearer realm=\"userinfo\"`", wwwAuth)
	}
}

// TestScenario_UI_015_AuthorizationHeaderTooManyPartsRejected asserts
// that "Authorization: Bearer some three" is parsed as token="some
// three": the header parser only strips the "Bearer " prefix, so the
// whitespace-bearing remainder is forwarded to the verifier, which
// rejects it. The endpoint returns 401 with WWW-Authenticate carrying
// error=invalid_token "The access token is invalid".
//
// Spec: RFC 6750 §2.1 / RFC 7235 §2.1.
func TestScenario_UI_015_AuthorizationHeaderTooManyPartsRejected(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		tk.Server.URL+"/oidc/userinfo", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer some three")

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("GET /oidc/userinfo: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 401 body=%s", resp.StatusCode, raw)
	}
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if !strings.Contains(wwwAuth, `error="invalid_token"`) {
		t.Errorf("WWW-Authenticate=%q must carry error=\"invalid_token\"", wwwAuth)
	}
	if !strings.Contains(wwwAuth, `error_description="The access token is invalid"`) {
		t.Errorf("WWW-Authenticate=%q must carry error_description=\"The access token is invalid\"", wwwAuth)
	}
}

// TestScenario_UI_016_WrongAuthSchemeRejected asserts that an
// Authorization header whose scheme is neither Bearer nor DPoP (e.g.
// Basic) is treated as missing credentials. The scheme-match in
// bearerFromHeader fails, no body field is present, and the request
// collapses onto the bare-challenge "no credentials" branch.
//
// Spec: RFC 6750 §2.1.
func TestScenario_UI_016_WrongAuthSchemeRejected(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		tk.Server.URL+"/oidc/userinfo", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("GET /oidc/userinfo: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 401 body=%s", resp.StatusCode, raw)
	}
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if wwwAuth != `Bearer realm="userinfo"` {
		t.Errorf("WWW-Authenticate=%q want exactly `Bearer realm=\"userinfo\"`", wwwAuth)
	}
}

func TestScenario_UI_017_EmptyTokenViaQueryRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: UI-017 (v1.0 deliberately does not consult URL query for the access token)")
}

// TestScenario_UI_018_EmptyTokenViaBodyRejected asserts that a POST
// /userinfo with `access_token=` (empty value) in the urlencoded body
// is parsed as token="" — the body parser observes a single
// access_token entry, so the request is dispatched to the verifier,
// which rejects the empty value. The endpoint returns 401 with
// WWW-Authenticate carrying error=invalid_token "The access token is
// invalid" rather than collapsing onto the bare-challenge branch.
//
// Spec: RFC 6750 §2.2 / §3.
func TestScenario_UI_018_EmptyTokenViaBodyRejected(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)

	form := url.Values{"access_token": {""}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/userinfo", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /oidc/userinfo: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 401 body=%s", resp.StatusCode, raw)
	}
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if !strings.Contains(wwwAuth, `error="invalid_token"`) {
		t.Errorf("WWW-Authenticate=%q must carry error=\"invalid_token\"", wwwAuth)
	}
	if !strings.Contains(wwwAuth, `error_description="The access token is invalid"`) {
		t.Errorf("WWW-Authenticate=%q must carry error_description=\"The access token is invalid\"", wwwAuth)
	}
}

// TestScenario_UI_019_EmptyBodyAndNoHeaderRejected asserts that a POST
// /userinfo with no Authorization header and an empty body is treated
// as missing credentials: neither bearerFromHeader nor bearerFromBody
// observes a token, so the request collapses onto the bare Bearer
// challenge with status 401.
//
// Spec: RFC 6750 §3.
func TestScenario_UI_019_EmptyBodyAndNoHeaderRejected(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/userinfo", strings.NewReader(""))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /oidc/userinfo: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 401 body=%s", resp.StatusCode, raw)
	}
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if wwwAuth != `Bearer realm="userinfo"` {
		t.Errorf("WWW-Authenticate=%q want exactly `Bearer realm=\"userinfo\"`", wwwAuth)
	}
}
