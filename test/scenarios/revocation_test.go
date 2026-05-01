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

func TestScenario_REV_004_AccessTokenRevokeCorrectHint(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REV-004")
}

func TestScenario_REV_005_AccessTokenRevokeWrongHint(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REV-005")
}

func TestScenario_REV_006_AccessTokenRevokeUnrecognisedHint(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REV-006")
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

func TestScenario_REV_009_RefreshTokenRevokeCorrectHint(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REV-009")
}

func TestScenario_REV_010_RefreshTokenRevokeWrongHint(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REV-010")
}

func TestScenario_REV_011_RefreshTokenRevokeUnrecognisedHint(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REV-011")
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

func TestScenario_REV_013_ClientCredentialsRevokeCorrectHint(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REV-013")
}

func TestScenario_REV_014_ClientCredentialsRevokeUnrecognisedHint(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REV-014")
}

func TestScenario_REV_015_MissingTokenParameterRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REV-015")
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

func TestScenario_REV_022_AccessTokenSuccessRegistersEntities(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REV-022")
}

func TestScenario_REV_023_RefreshTokenSuccessRegistersEntities(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REV-023")
}

func TestScenario_REV_024_ClientCredentialsSuccessRegistersEntities(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REV-024")
}
