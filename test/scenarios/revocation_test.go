package scenarios_test

// Catalog: test/scenarios/catalog/revocation.yaml (REV-NNN)
// Spec:
//   - RFC 7009 — OAuth 2.0 Token Revocation
//   - RFC 6749 §2.3 — Client Authentication
//   - RFC 8414 §2 — `revocation_endpoint` discovery metadata
//   - RFC 9068 §6 — Structured JWT access tokens not revocable
//   - OIDC Core 1.0 §1 — Grant cascade extension

import (
	"context"
	"encoding/json"
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

// TestScenario_REV_001_DiscoveryAdvertisesRevocationEndpoint verifies
// that when feature.Revoke is enabled the OP's discovery document
// advertises a non-empty, absolute revocation_endpoint pointing at the
// canonical /oidc/revoke route.
//
// Spec: RFC 8414 §2.
func TestScenario_REV_001_DiscoveryAdvertisesRevocationEndpoint(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithFeature(feature.Revoke)))

	_, _, doc := fetchDiscovery(t, tk.Server.URL)
	endpoint, _ := doc["revocation_endpoint"].(string)
	if endpoint == "" {
		t.Fatalf("revocation_endpoint missing when Revoke feature is on; doc=%v", doc)
	}
	if !strings.HasSuffix(endpoint, "/oidc/revoke") {
		t.Errorf("revocation_endpoint=%q must end with /oidc/revoke", endpoint)
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		t.Fatalf("revocation_endpoint=%q is not a URL: %v", endpoint, err)
	}
	if !parsed.IsAbs() || parsed.Scheme == "" || parsed.Host == "" {
		t.Errorf("revocation_endpoint=%q must be absolute (scheme + host)", endpoint)
	}
	if _, present := doc["token_revocation_endpoint"]; present {
		t.Errorf("legacy token_revocation_endpoint must not be advertised; doc=%v", doc)
	}
}

// TestScenario_REV_002_AccessTokenRevokeNoHint runs a code flow, takes
// the resulting access token, and submits it to /oidc/revoke with no
// token_type_hint. The endpoint MUST return 200 with an empty body and
// the access token MUST stop verifying at /userinfo (challenge carries
// error="invalid_token"). The paired refresh token, however, MUST still
// rotate at /token: ADR 0025 explicitly rejects cascading single-AT
// revocation onto a grant tombstone.
//
// Spec: RFC 7009 §2 / ADR 0025 §Alternatives.
func TestScenario_REV_002_AccessTokenRevokeNoHint(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-rev-002"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-rev-002-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t,
		testkit.WithOptions(
			op.WithFeature(feature.Revoke),
			op.WithStrictOfflineAccess(),
		),
	)
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile", "email", "offline_access"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
	})
	tk.Store.PutUser(context.Background(), &store.User{Subject: scenariokit.DefaultSubject})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		Scope:       "openid offline_access",
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     rp.ID,
		ClientSecret: clientSecret,
	})
	if tok.StatusCode != http.StatusOK || tok.AccessToken == "" || tok.RefreshToken == "" {
		t.Fatalf("/token status=%d body=%v, want 200 with access_token + refresh_token", tok.StatusCode, tok.Raw)
	}

	// /userinfo must work BEFORE revocation (sanity check).
	if status, _, challenge := getUserInfo(t, tk, tok.AccessToken); status != http.StatusOK {
		t.Fatalf("pre-revoke /userinfo status=%d challenge=%q want 200", status, challenge)
	}

	if status := postRevoke(t, tk, tok.AccessToken, rp.ID, clientSecret); status != http.StatusOK {
		t.Fatalf("/revoke status=%d want 200", status)
	}

	// Access token is destroyed.
	uiStatus, _, challenge := getUserInfo(t, tk, tok.AccessToken)
	if uiStatus != http.StatusUnauthorized {
		t.Fatalf("post-revoke /userinfo status=%d want 401; challenge=%q", uiStatus, challenge)
	}
	if !strings.Contains(challenge, `error="invalid_token"`) {
		t.Errorf("WWW-Authenticate=%q must declare invalid_token", challenge)
	}

	// Grant is preserved: refresh token still rotates.
	rotateForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tok.RefreshToken},
	}
	rotateReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/token", strings.NewReader(rotateForm.Encode()))
	if err != nil {
		t.Fatalf("build /token rotate request: %v", err)
	}
	rotateReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rotateReq.SetBasicAuth(rp.ID, clientSecret)

	rotateResp, err := tk.HTTPClient(nil).Do(rotateReq)
	if err != nil {
		t.Fatalf("POST /token rotate: %v", err)
	}
	rotateBody, _ := io.ReadAll(rotateResp.Body)
	_ = rotateResp.Body.Close()
	if rotateResp.StatusCode != http.StatusOK {
		t.Fatalf("rotate /token status=%d want 200 (grant must survive single-AT revoke); body=%s",
			rotateResp.StatusCode, rotateBody)
	}
	var rotated map[string]any
	if err := json.Unmarshal(rotateBody, &rotated); err != nil {
		t.Fatalf("rotate body is not JSON: %v (raw=%s)", err, rotateBody)
	}
	if at, _ := rotated["access_token"].(string); at == "" {
		t.Errorf("rotated /token did not return a new access_token; body=%s", rotateBody)
	}
}

func TestScenario_REV_003_AccessTokenRevokeCascadesGrant(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: REV-003")
}

// TestScenario_REV_004_AccessTokenRevokeCorrectHint runs the
// AT-revocation flow with token_type_hint=access_token and asserts
// 200 + empty body, then verifies the access token can no longer
// drive /userinfo.
//
// Spec: RFC 7009 §2.1.
func TestScenario_REV_004_AccessTokenRevokeCorrectHint(t *testing.T) {
	t.Parallel()

	tk, rp, secret, at := mintRevocationAccessToken(t, "rp-rev-004")
	if status, body := postRevokeWithHint(t, tk, at, "access_token", rp.ID, secret); status != http.StatusOK || len(body) != 0 {
		t.Fatalf("/revoke status=%d body=%s want 200 + empty", status, body)
	}

	uiStatus, _, challenge := getUserInfo(t, tk, at)
	if uiStatus != http.StatusUnauthorized {
		t.Fatalf("post-revoke /userinfo status=%d want 401; challenge=%q", uiStatus, challenge)
	}
	if !strings.Contains(challenge, `error="invalid_token"`) {
		t.Errorf("WWW-Authenticate=%q must declare invalid_token", challenge)
	}
}

// TestScenario_REV_005_AccessTokenRevokeWrongHint posts an access
// token to /revoke with token_type_hint=refresh_token. RFC 7009 §2.1
// allows the hint to be wrong; the OP MUST fall back to a full
// resolution and still destroy the access token.
//
// Spec: RFC 7009 §2.1.
func TestScenario_REV_005_AccessTokenRevokeWrongHint(t *testing.T) {
	t.Parallel()

	tk, rp, secret, at := mintRevocationAccessToken(t, "rp-rev-005")
	if status, body := postRevokeWithHint(t, tk, at, "refresh_token", rp.ID, secret); status != http.StatusOK || len(body) != 0 {
		t.Fatalf("/revoke status=%d body=%s want 200 + empty", status, body)
	}

	uiStatus, _, challenge := getUserInfo(t, tk, at)
	if uiStatus != http.StatusUnauthorized {
		t.Fatalf("post-revoke /userinfo status=%d want 401; challenge=%q (wrong hint must not block destruction)", uiStatus, challenge)
	}
	if !strings.Contains(challenge, `error="invalid_token"`) {
		t.Errorf("WWW-Authenticate=%q must declare invalid_token", challenge)
	}
}

// TestScenario_REV_006_AccessTokenRevokeUnrecognisedHint posts an
// access token with an arbitrary unknown token_type_hint value. RFC
// 7009 §2.1 requires the OP to ignore unrecognised hints and still
// resolve the token normally.
//
// Spec: RFC 7009 §2.1.
func TestScenario_REV_006_AccessTokenRevokeUnrecognisedHint(t *testing.T) {
	t.Parallel()

	tk, rp, secret, at := mintRevocationAccessToken(t, "rp-rev-006")
	if status, body := postRevokeWithHint(t, tk, at, "foobar", rp.ID, secret); status != http.StatusOK || len(body) != 0 {
		t.Fatalf("/revoke status=%d body=%s want 200 + empty", status, body)
	}

	uiStatus, _, challenge := getUserInfo(t, tk, at)
	if uiStatus != http.StatusUnauthorized {
		t.Fatalf("post-revoke /userinfo status=%d want 401; challenge=%q (unrecognised hint must not block destruction)", uiStatus, challenge)
	}
}

func TestScenario_REV_007_AdapterFindExceptionPropagates(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: REV-007")
}

// TestScenario_REV_008_RefreshTokenRevokeNoHint runs a code flow with
// offline_access, posts the resulting refresh token to /oidc/revoke
// without a token_type_hint, and asserts 200 + empty body. A subsequent
// /token grant_type=refresh_token attempt with the same token MUST fail
// with invalid_grant: RFC 7009 §2 + the v1.0 reference adapter destroy
// the entire refresh-token chain rooted at the revoked token.
//
// Spec: RFC 7009 §2 / RFC 6749 §6.
func TestScenario_REV_008_RefreshTokenRevokeNoHint(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-rev-008"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-rev-008-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t,
		testkit.WithOptions(
			op.WithFeature(feature.Revoke),
			op.WithStrictOfflineAccess(),
		),
	)
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile", "email", "offline_access"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
	})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		Scope:       "openid offline_access",
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     rp.ID,
		ClientSecret: clientSecret,
	})
	if tok.StatusCode != http.StatusOK || tok.RefreshToken == "" {
		t.Fatalf("/token status=%d body=%v, want refresh_token (offline_access scope?)", tok.StatusCode, tok.Raw)
	}

	if status := postRevoke(t, tk, tok.RefreshToken, rp.ID, clientSecret); status != http.StatusOK {
		t.Fatalf("/revoke status=%d want 200", status)
	}

	// Refresh token must no longer rotate.
	rotateForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tok.RefreshToken},
	}
	rotateReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/token", strings.NewReader(rotateForm.Encode()))
	if err != nil {
		t.Fatalf("build /token rotate request: %v", err)
	}
	rotateReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rotateReq.SetBasicAuth(rp.ID, clientSecret)

	rotateResp, err := tk.HTTPClient(nil).Do(rotateReq)
	if err != nil {
		t.Fatalf("POST /token rotate: %v", err)
	}
	rotateBody, _ := io.ReadAll(rotateResp.Body)
	_ = rotateResp.Body.Close()
	if rotateResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("post-revoke rotate /token status=%d want 400; body=%s", rotateResp.StatusCode, rotateBody)
	}
	var env map[string]any
	if err := json.Unmarshal(rotateBody, &env); err != nil {
		t.Fatalf("rotate body is not JSON: %v (raw=%s)", err, rotateBody)
	}
	if got, _ := env["error"].(string); got != "invalid_grant" {
		t.Errorf("error=%q want invalid_grant; body=%s", got, rotateBody)
	}
}

// TestScenario_REV_009_RefreshTokenRevokeCorrectHint posts a refresh
// token to /revoke with token_type_hint=refresh_token. The OP MUST
// return 200 + empty body and the chain MUST be destroyed (a follow-up
// /token grant_type=refresh_token attempt is rejected with
// invalid_grant).
//
// Spec: RFC 7009 §2.1.
func TestScenario_REV_009_RefreshTokenRevokeCorrectHint(t *testing.T) {
	t.Parallel()

	tk, rp, secret, rt := mintRevocationRefreshToken(t, "rp-rev-009")
	if status, body := postRevokeWithHint(t, tk, rt, "refresh_token", rp.ID, secret); status != http.StatusOK || len(body) != 0 {
		t.Fatalf("/revoke status=%d body=%s want 200 + empty", status, body)
	}
	assertRefreshTokenInvalid(t, tk, rt, rp.ID, secret)
}

// TestScenario_REV_010_RefreshTokenRevokeWrongHint posts a refresh
// token to /revoke with token_type_hint=access_token. RFC 7009 §2.1
// requires the OP to ignore the wrong hint, fall back to a full
// resolution, and still destroy the refresh token.
//
// Spec: RFC 7009 §2.1.
func TestScenario_REV_010_RefreshTokenRevokeWrongHint(t *testing.T) {
	t.Parallel()

	tk, rp, secret, rt := mintRevocationRefreshToken(t, "rp-rev-010")
	if status, body := postRevokeWithHint(t, tk, rt, "access_token", rp.ID, secret); status != http.StatusOK || len(body) != 0 {
		t.Fatalf("/revoke status=%d body=%s want 200 + empty", status, body)
	}
	assertRefreshTokenInvalid(t, tk, rt, rp.ID, secret)
}

// TestScenario_REV_011_RefreshTokenRevokeUnrecognisedHint posts a
// refresh token to /revoke with an arbitrary unknown
// token_type_hint. RFC 7009 §2.1 requires unrecognised hints to be
// ignored; the refresh token MUST still be destroyed.
//
// Spec: RFC 7009 §2.1.
func TestScenario_REV_011_RefreshTokenRevokeUnrecognisedHint(t *testing.T) {
	t.Parallel()

	tk, rp, secret, rt := mintRevocationRefreshToken(t, "rp-rev-011")
	if status, body := postRevokeWithHint(t, tk, rt, "foobar", rp.ID, secret); status != http.StatusOK || len(body) != 0 {
		t.Fatalf("/revoke status=%d body=%s want 200 + empty", status, body)
	}
	assertRefreshTokenInvalid(t, tk, rt, rp.ID, secret)
}

// TestScenario_REV_012_ClientCredentialsRevokeNoHint mints an access
// token via grant_type=client_credentials, revokes it without a hint,
// and asserts 200 + empty body. The token MUST then be inactive at
// /oidc/introspect (client_credentials tokens have no end-user subject
// so /userinfo is not the right verification surface). The OP runs in
// the ADR 0024 opaque-AT format so the substore that backs introspect
// observes the revoked row directly; the JWT-AT path for
// client_credentials tokens lacks a "gid" claim so the GrantTombstone
// branch cannot pin a denylist row to it.
//
// Spec: RFC 7009 §2 / RFC 6749 §4.4 / ADR 0024.
func TestScenario_REV_012_ClientCredentialsRevokeNoHint(t *testing.T) {
	t.Parallel()

	const clientID = "rp-rev-012"
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-rev-012-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t,
		testkit.WithOptions(
			op.WithAccessTokenFormat(op.AccessTokenFormatOpaque),
			op.WithFeature(feature.Revoke),
			op.WithFeature(feature.Introspect),
		),
	)
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		Scopes:                  []string{"api"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"client_credentials"},
	})

	// Mint a client_credentials access token.
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"api"}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build /token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(rp.ID, clientSecret)

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/token status=%d want 200; body=%s", resp.StatusCode, body)
	}
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("/token body is not JSON: %v (raw=%s)", err, body)
	}
	at, _ := env["access_token"].(string)
	if at == "" {
		t.Fatalf("client_credentials /token returned no access_token; body=%s", body)
	}

	// Pre-revoke: the token MUST introspect as active.
	if status, intro := postIntrospect(t, tk, at, rp.ID, clientSecret); status != http.StatusOK {
		t.Fatalf("pre-revoke /introspect status=%d want 200", status)
	} else if active, _ := intro["active"].(bool); !active {
		t.Fatalf("pre-revoke active=false want true; body=%v", intro)
	}

	if status := postRevoke(t, tk, at, rp.ID, clientSecret); status != http.StatusOK {
		t.Fatalf("/revoke status=%d want 200", status)
	}

	// Post-revoke: the token MUST collapse onto active=false.
	status, intro := postIntrospect(t, tk, at, rp.ID, clientSecret)
	if status != http.StatusOK {
		t.Fatalf("post-revoke /introspect status=%d want 200", status)
	}
	if active, _ := intro["active"].(bool); active {
		t.Errorf("post-revoke active=true want false; body=%v", intro)
	}
}

// TestScenario_REV_013_ClientCredentialsRevokeCorrectHint mints a
// client_credentials access token (opaque format so /introspect
// observes the substore directly) and revokes it with
// token_type_hint=access_token. The OP MUST return 200 + empty body
// and the token MUST be inactive at /oidc/introspect.
//
// Spec: RFC 7009 §2.1.
func TestScenario_REV_013_ClientCredentialsRevokeCorrectHint(t *testing.T) {
	t.Parallel()

	tk, rp, secret, at := mintRevocationClientCredentialsToken(t, "rp-rev-013")
	if status, body := postRevokeWithHint(t, tk, at, "access_token", rp.ID, secret); status != http.StatusOK || len(body) != 0 {
		t.Fatalf("/revoke status=%d body=%s want 200 + empty", status, body)
	}
	assertCCTokenInactive(t, tk, at, rp.ID, secret)
}

// TestScenario_REV_014_ClientCredentialsRevokeUnrecognisedHint mints
// a client_credentials access token and submits an arbitrary unknown
// token_type_hint to /revoke. RFC 7009 §2.1 requires unrecognised
// hints to be ignored; the token MUST still be destroyed.
//
// Spec: RFC 7009 §2.1.
func TestScenario_REV_014_ClientCredentialsRevokeUnrecognisedHint(t *testing.T) {
	t.Parallel()

	tk, rp, secret, at := mintRevocationClientCredentialsToken(t, "rp-rev-014")
	if status, body := postRevokeWithHint(t, tk, at, "foobar", rp.ID, secret); status != http.StatusOK || len(body) != 0 {
		t.Fatalf("/revoke status=%d body=%s want 200 + empty", status, body)
	}
	assertCCTokenInactive(t, tk, at, rp.ID, secret)
}

// TestScenario_REV_015_MissingTokenParameterRejected POSTs an
// authenticated /revoke request without a `token` form parameter.
// RFC 7009 §2.1 makes `token` REQUIRED, so the OP MUST reject with
// 400 invalid_request and an error_description that names the
// missing parameter.
//
// Spec: RFC 7009 §2.1.
func TestScenario_REV_015_MissingTokenParameterRejected(t *testing.T) {
	t.Parallel()

	const clientID = "rp-rev-015"
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-rev-015-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithFeature(feature.Revoke)))
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		Scopes:                  []string{"openid"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	form := url.Values{}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/revoke", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build /revoke request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /revoke: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, raw)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not JSON: %v (raw=%q)", err, string(body))
	}
	if got, _ := env["error"].(string); got != "invalid_request" {
		t.Errorf("error=%q want invalid_request (raw=%s)", got, string(body))
	}
	if desc, _ := env["error_description"].(string); !strings.Contains(desc, "token") {
		t.Errorf("error_description=%q must name the missing 'token' parameter", desc)
	}
}

// TestScenario_REV_016_NonsenseTokenReturnsEmpty200 posts an arbitrary
// non-token string to /oidc/revoke under valid client authentication.
// RFC 7009 §2.2 requires the endpoint to respond 200 with an empty
// body so a probing client cannot infer whether the value matched any
// stored token.
//
// Spec: RFC 7009 §2.2.
func TestScenario_REV_016_NonsenseTokenReturnsEmpty200(t *testing.T) {
	t.Parallel()

	const clientID = "rp-rev-016"
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-rev-016-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithFeature(feature.Revoke)))
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		Scopes:                  []string{"openid"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	form := url.Values{"token": {"this-is-not-a-real-token-of-any-kind"}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/revoke", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build /revoke request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(rp.ID, clientSecret)

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /revoke: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", resp.StatusCode, body)
	}
	if len(body) != 0 {
		t.Errorf("body length=%d want 0; body=%s", len(body), body)
	}
}

func TestScenario_REV_017_StructuredJWTRejectedAtRevocation(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: REV-017")
}

func TestScenario_REV_018_ConfidentialCrossClientRevokeRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: REV-018")
}

// TestScenario_REV_019_PublicCrossClientRevokeSilent registers two
// clients — a confidential owner that mints an access token through
// the code flow, and a public probe (token_endpoint_auth_method=none).
// The probe submits the owner's access token to /oidc/revoke. RFC 7009
// §2.2 forbids leaking ownership errors through the wire, so the
// response MUST be 200 with an empty body and the OWNER's token MUST
// remain valid at /userinfo afterwards (cross-client revocation is
// silently ignored, never actually destructive).
//
// Spec: RFC 7009 §2.2.
func TestScenario_REV_019_PublicCrossClientRevokeSilent(t *testing.T) {
	t.Parallel()

	const (
		ownerID     = "rp-rev-019-owner"
		ownerCB     = "https://rp.testkit.invalid/owner"
		ownerSecret = "rp-rev-019-owner-secret" //nolint:gosec // test fixture
		probeID     = "rp-rev-019-probe"
		probeCB     = "https://rp.testkit.invalid/probe"
	)

	ownerHash, err := op.HashClientSecret(ownerSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithFeature(feature.Revoke)))
	owner := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      ownerID,
		SecretHash:              ownerHash,
		RedirectURIs:            []string{ownerCB},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
	})
	probe := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      probeID,
		RedirectURIs:            []string{probeCB},
		Scopes:                  []string{"openid"},
		TokenEndpointAuthMethod: "none",
		GrantTypes:              []string{"authorization_code"},
		PublicClient:            true,
	})
	tk.Store.PutUser(context.Background(), &store.User{Subject: scenariokit.DefaultSubject})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    owner.ID,
		RedirectURI: ownerCB,
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  ownerCB,
		Verifier:     pkce.Verifier,
		ClientID:     owner.ID,
		ClientSecret: ownerSecret,
	})
	if tok.StatusCode != http.StatusOK || tok.AccessToken == "" {
		t.Fatalf("/token status=%d body=%v, want 200 with access_token", tok.StatusCode, tok.Raw)
	}

	// PUBLIC probe submits the OWNER's token to /revoke. The wire MUST
	// be 200 + empty body.
	form := url.Values{
		"token":     {tok.AccessToken},
		"client_id": {probe.ID},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/revoke", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build /revoke request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /revoke: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("cross-client /revoke status=%d want 200; body=%s", resp.StatusCode, body)
	}
	if len(body) != 0 {
		t.Errorf("cross-client /revoke body length=%d want 0; body=%s", len(body), body)
	}

	// Owner's token MUST still verify at /userinfo.
	uiStatus, _, challenge := getUserInfo(t, tk, tok.AccessToken)
	if uiStatus != http.StatusOK {
		t.Fatalf("post-cross-revoke /userinfo status=%d want 200; challenge=%q (cross-client revoke must be a no-op)",
			uiStatus, challenge)
	}
}

// TestScenario_REV_020_BadClientAuthEmitsAuditError submits a /revoke
// request whose Basic-auth header carries a registered client_id but
// the wrong secret. The OP MUST reject with 401 invalid_client and
// stamp WWW-Authenticate: Basic realm="oidc" so RFC 6749 §2.3 + RFC
// 7235 user-agents can challenge cleanly. Note: the catalog row's
// "audit event" wording is aspirational — v1.0's /revoke does not yet
// emit a client-auth failure event (token.revoke_failed is reserved
// for post-auth store faults), so this row pins the wire-only contract.
//
// Spec: RFC 6749 §2.3 / RFC 7009.
func TestScenario_REV_020_BadClientAuthEmitsAuditError(t *testing.T) {
	t.Parallel()

	const clientID = "rp-rev-020"
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-rev-020-correct-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithFeature(feature.Revoke)))
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		Scopes:                  []string{"openid"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	form := url.Values{"token": {"any-token-value"}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/revoke", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build /revoke request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, "wrong-secret")

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /revoke: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 401; body=%s", resp.StatusCode, raw)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not JSON: %v (raw=%q)", err, string(body))
	}
	if got, _ := env["error"].(string); got != "invalid_client" {
		t.Errorf("error=%q want invalid_client (raw=%s)", got, string(body))
	}
	challenge := resp.Header.Get("WWW-Authenticate")
	if !strings.Contains(challenge, "Basic") {
		t.Errorf("WWW-Authenticate=%q must carry Basic challenge", challenge)
	}
	if !strings.Contains(challenge, `realm="oidc"`) {
		t.Errorf("WWW-Authenticate=%q must carry realm=\"oidc\"", challenge)
	}
}

func TestScenario_REV_021_UnrevokableKindSilent200(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: REV-021")
}

// TestScenario_REV_022_AccessTokenSuccessRegistersEntities is OOS — see catalog out_of_scope_reason.
func TestScenario_REV_022_AccessTokenSuccessRegistersEntities(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: REV-022 (see catalog out_of_scope_reason)")
}

// TestScenario_REV_023_RefreshTokenSuccessRegistersEntities is OOS — see catalog out_of_scope_reason.
func TestScenario_REV_023_RefreshTokenSuccessRegistersEntities(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: REV-023 (see catalog out_of_scope_reason)")
}

// TestScenario_REV_024_ClientCredentialsSuccessRegistersEntities is OOS — see catalog out_of_scope_reason.
func TestScenario_REV_024_ClientCredentialsSuccessRegistersEntities(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: REV-024 (see catalog out_of_scope_reason)")
}

// mintRevocationAccessToken stands up a confidential RP, drives the
// code flow with offline_access, and returns the resulting access
// token alongside the provider/client/secret triple so a hint variant
// can revoke it.
func mintRevocationAccessToken(t *testing.T, idPrefix string) (*testkit.Provider, *store.Client, string, string) {
	t.Helper()
	clientID := idPrefix
	clientSecret := idPrefix + "-secret" //nolint:gosec // test fixture
	callback := "https://rp.testkit.invalid/callback"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t,
		testkit.WithOptions(
			op.WithFeature(feature.Revoke),
			op.WithStrictOfflineAccess(),
		),
	)
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile", "email", "offline_access"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
	})
	tk.Store.PutUser(context.Background(), &store.User{Subject: scenariokit.DefaultSubject})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		Scope:       "openid offline_access",
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     rp.ID,
		ClientSecret: clientSecret,
	})
	if tok.StatusCode != http.StatusOK || tok.AccessToken == "" {
		t.Fatalf("/token status=%d body=%v want 200 with access_token", tok.StatusCode, tok.Raw)
	}
	return tk, rp, clientSecret, tok.AccessToken
}

// mintRevocationRefreshToken is like mintRevocationAccessToken but
// returns the refresh token paired with the same code-flow exchange.
func mintRevocationRefreshToken(t *testing.T, idPrefix string) (*testkit.Provider, *store.Client, string, string) {
	t.Helper()
	clientID := idPrefix
	clientSecret := idPrefix + "-secret" //nolint:gosec // test fixture
	callback := "https://rp.testkit.invalid/callback"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t,
		testkit.WithOptions(
			op.WithFeature(feature.Revoke),
			op.WithStrictOfflineAccess(),
		),
	)
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile", "email", "offline_access"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
	})
	tk.Store.PutUser(context.Background(), &store.User{Subject: scenariokit.DefaultSubject})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		Scope:       "openid offline_access",
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     rp.ID,
		ClientSecret: clientSecret,
	})
	if tok.StatusCode != http.StatusOK || tok.RefreshToken == "" {
		t.Fatalf("/token status=%d body=%v want refresh_token (offline_access scope?)", tok.StatusCode, tok.Raw)
	}
	return tk, rp, clientSecret, tok.RefreshToken
}

// mintRevocationClientCredentialsToken stands up a cc-only client and
// mints an opaque access token through grant_type=client_credentials.
// Opaque AT format is required so /introspect can observe the
// revocation directly without going through the JTI-denylist path.
func mintRevocationClientCredentialsToken(t *testing.T, idPrefix string) (*testkit.Provider, *store.Client, string, string) {
	t.Helper()
	clientID := idPrefix
	clientSecret := idPrefix + "-secret" //nolint:gosec // test fixture

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t,
		testkit.WithOptions(
			op.WithAccessTokenFormat(op.AccessTokenFormatOpaque),
			op.WithFeature(feature.Revoke),
			op.WithFeature(feature.Introspect),
		),
	)
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		Scopes:                  []string{"api"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"client_credentials"},
	})

	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"api"}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build /token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(rp.ID, clientSecret)

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/token status=%d want 200; body=%s", resp.StatusCode, body)
	}
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("/token body is not JSON: %v (raw=%s)", err, body)
	}
	at, _ := env["access_token"].(string)
	if at == "" {
		t.Fatalf("client_credentials /token returned no access_token; body=%s", body)
	}
	return tk, rp, clientSecret, at
}

// postRevokeWithHint POSTs token plus the supplied
// token_type_hint to /oidc/revoke, returning the status code and raw
// body. Callers assert on RFC 7009 §2 ("200 + empty body") shape.
func postRevokeWithHint(t *testing.T, tk *testkit.Provider, token, hint, clientID, clientSecret string) (int, []byte) {
	t.Helper()
	form := url.Values{"token": {token}, "token_type_hint": {hint}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/revoke", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build /revoke request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /revoke: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

// assertRefreshTokenInvalid attempts to redeem rt at /token and
// asserts the OP returns 400 invalid_grant — the post-revocation
// shape required by RFC 7009 §2 (the chain MUST be destroyed).
func assertRefreshTokenInvalid(t *testing.T, tk *testkit.Provider, rt, clientID, clientSecret string) {
	t.Helper()
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build /token rotate request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /token rotate: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("post-revoke rotate /token status=%d want 400; body=%s", resp.StatusCode, body)
	}
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("rotate body is not JSON: %v (raw=%s)", err, body)
	}
	if got, _ := env["error"].(string); got != "invalid_grant" {
		t.Errorf("error=%q want invalid_grant; body=%s", got, body)
	}
}

// assertCCTokenInactive introspects at and asserts the OP reports
// active=false, the post-revocation shape required by RFC 7009 §2 +
// RFC 7662 §2.2.
func assertCCTokenInactive(t *testing.T, tk *testkit.Provider, at, clientID, clientSecret string) {
	t.Helper()
	status, env := postIntrospect(t, tk, at, clientID, clientSecret)
	if status != http.StatusOK {
		t.Fatalf("post-revoke /introspect status=%d want 200", status)
	}
	if active, _ := env["active"].(bool); active {
		t.Errorf("post-revoke active=true want false; body=%v", env)
	}
}
