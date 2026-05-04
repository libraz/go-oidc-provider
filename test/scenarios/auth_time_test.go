package scenarios_test

// Catalog: test/scenarios/catalog/auth_time.yaml (AT-NNN)
// Spec:
//   - OIDC Core 1.0 §2 (ID Token, `auth_time` claim)
//   - OIDC Core 1.0 §3.1.2.1 (`max_age`, `prompt`)
//   - OIDC Core 1.0 §5.5.1.1 (`auth_time` essential claim)
//   - OIDC Registration 1.0 §2 (`require_auth_time`, `default_max_age`)

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

func TestScenario_AT_001_RequestMaxAgeForcesAuthTime(t *testing.T) {
	t.Parallel()
	atFlowAssertAuthTime(t, withAuthorizeExtra("max_age", "999"))
}

func TestScenario_AT_002_PromptLoginForcesAuthTime(t *testing.T) {
	t.Parallel()
	atFlowAssertAuthTime(t, withAuthorizeExtra("prompt", "login"))
}

func TestScenario_AT_003_MaxAgeZeroForcesAuthTime(t *testing.T) {
	t.Parallel()
	atFlowAssertAuthTime(t, withAuthorizeExtra("max_age", "0"))
}

func TestScenario_AT_004_ClientDefaultMaxAgeZeroForcesAuthTime(t *testing.T) {
	t.Parallel()
	zero := int64(0)
	atFlowAssertAuthTime(t, withClientMutator(func(c *store.Client) {
		c.DefaultMaxAge = &zero
	}))
}

func TestScenario_AT_005_ClientRequireAuthTimeForcesAuthTime(t *testing.T) {
	t.Parallel()
	atFlowAssertAuthTime(t, withClientMutator(func(c *store.Client) {
		c.RequireAuthTime = true
	}))
}

func TestScenario_AT_006_ClientDefaultMaxAgePositiveForcesAuthTime(t *testing.T) {
	t.Parallel()
	maxAge := int64(3600)
	atFlowAssertAuthTime(t, withClientMutator(func(c *store.Client) {
		c.DefaultMaxAge = &maxAge
	}))
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
// counterpart of AT-007. CIBA's helper does not expose a public
// approve hook the test can call directly today, so this row is a
// catalog-binding sentinel; the actual coverage lives in
// internal/tokenendpoint TestHandleCIBA_IDTokenStampsAuthTime.
func TestScenario_AT_008_CIBAIDTokenCarriesAuthTime(t *testing.T) {
	t.Parallel()
	t.Skip("covered by internal/tokenendpoint TestHandleCIBA_IDTokenStampsAuthTime")
}

type atFlowConfig struct {
	authorizeExtra urlValuesMutator
	clientMutator  func(*store.Client)
}

type urlValuesMutator func(map[string][]string)

func withAuthorizeExtra(k, v string) func(*atFlowConfig) {
	return func(cfg *atFlowConfig) {
		cfg.authorizeExtra = func(values map[string][]string) {
			values[k] = []string{v}
		}
	}
}

func withClientMutator(fn func(*store.Client)) func(*atFlowConfig) {
	return func(cfg *atFlowConfig) {
		cfg.clientMutator = fn
	}
}

func atFlowAssertAuthTime(t *testing.T, opts ...func(*atFlowConfig)) {
	t.Helper()

	cfg := &atFlowConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	const (
		clientID     = "rp-at"
		callback     = "https://rp.testkit.invalid/callback"
		clientSecret = "rp-at-secret"
	)
	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithStrictOfflineAccess()))
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile", "email", "offline_access"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	if cfg.clientMutator != nil {
		cfg.clientMutator(rp)
		if err := tk.Store.UpdateClient(context.Background(), rp); err != nil {
			t.Fatalf("UpdateClient: %v", err)
		}
	}

	pkce := scenariokit.NewPKCEPair("")
	params := scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		Scope:       "openid profile offline_access",
		PKCE:        pkce,
	}
	if cfg.authorizeExtra != nil {
		params.Extra = map[string][]string{}
		cfg.authorizeExtra(params.Extra)
	}

	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, params)
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
	if tok.StatusCode != 200 {
		t.Fatalf("/token status=%d body=%v", tok.StatusCode, tok.Raw)
	}
	if tok.IDToken == "" {
		t.Fatal("id_token missing")
	}
	claims := decodeScenarioJWTClaims(t, tok.IDToken)
	if _, ok := claims["auth_time"]; !ok {
		t.Fatalf("auth_time missing from id_token claims=%v", claims)
	}
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
