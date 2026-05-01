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
	"net/url"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

func TestScenario_JARM_001_DiscoverySurfaceAdvertised(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JARM-001")
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

func TestScenario_JARM_020_AudEqualsClientID(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JARM-020")
}

func TestScenario_JARM_021_ExpClaimIsNumber(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JARM-021")
}

func TestScenario_JARM_022_IssEqualsIssuer(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JARM-022")
}

func TestScenario_JARM_023_StateRoundTripped(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JARM-023")
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

func TestScenario_JARM_050_QueryJwtErrorRedirect(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JARM-050")
}

func TestScenario_JARM_051_FragmentJwtErrorRedirect(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JARM-051")
}

func TestScenario_JARM_052_FormPostJwtErrorRendered(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JARM-052")
}

func TestScenario_JARM_053_WebMessageJwtErrorRendered(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JARM-053")
}

func TestScenario_JARM_054_ExpiredSecretAllTransports(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JARM-054")
}
