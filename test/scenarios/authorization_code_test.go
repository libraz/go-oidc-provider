package scenarios_test

// Catalog: test/scenarios/catalog/authorization_code.yaml (AC-NNN)
// Spec:
//   - RFC 6749 §4.1 — Authorization Code Grant
//   - RFC 6749 §4.1.3 — Access Token Request
//   - RFC 6749 §5.1 / §5.2 — Token Response & Error Format
//   - OpenID Connect Core 1.0 §3.1.3 — Token Endpoint
//   - RFC 8414 / RFC 6750 — Bearer Token Usage
//   - RFC 7636 — PKCE (cross-reference for redirect_uri reuse semantics)

import (
	"net/http"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

func TestScenario_AC_001_MultiURISuccessReturnsTokens(t *testing.T) {
	t.Parallel()

	const (
		clientID    = "rp-ac-001"
		callback    = "https://rp.testkit.invalid/callback"
		altCallback = "https://rp.testkit.invalid/alt"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-ac-001-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithStrictOfflineAccess()))
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback, altCallback},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}
	if flow.State != scenariokit.DefaultState {
		t.Errorf("state=%q want %q", flow.State, scenariokit.DefaultState)
	}

	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     rp.ID,
		ClientSecret: clientSecret,
	})
	if tok.StatusCode != http.StatusOK {
		t.Fatalf("/token status=%d body=%v", tok.StatusCode, tok.Raw)
	}
	if tok.AccessToken == "" {
		t.Error("access_token missing")
	}
	if tok.IDToken == "" {
		t.Error("id_token missing")
	}
	if tok.ExpiresIn <= 0 {
		t.Errorf("expires_in=%d, want > 0", tok.ExpiresIn)
	}
	if tok.TokenType == "" {
		t.Error("token_type missing")
	}
	if tok.Scope == "" {
		t.Error("scope missing")
	}
	if tok.RefreshToken != "" {
		t.Errorf("refresh_token unexpectedly present (offline_access not requested): %q", tok.RefreshToken)
	}
}

func TestScenario_AC_002_NoOfflineAccessEntitiesResolved(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-002")
}

func TestScenario_AC_003_OfflineAccessIssuesRefreshToken(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-003")
}

func TestScenario_AC_004_TokenResponseIsNoStore(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-004")
}

func TestScenario_AC_005_ExpiredCodeRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-005")
}

func TestScenario_AC_006_ReplayedCodeRevokesGrant(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-006")
}

func TestScenario_AC_007_FirstExchangeMarksCodeConsumed(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-007")
}

func TestScenario_AC_008_ClientMismatchRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-008")
}

func TestScenario_AC_009_UnsupportedGrantTypeRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-009")
}

func TestScenario_AC_010_RedirectURIMismatchRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-010")
}

func TestScenario_AC_011_MultiURIClientMustSendRedirectURI(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-011")
}

func TestScenario_AC_012_AccountNotFoundRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-012")
}

func TestScenario_AC_013_SingleURIWithoutAllowOmitRequiresParam(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-013")
}

func TestScenario_AC_014_SingleURIAllowOmitSuccess(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-014")
}

func TestScenario_AC_015_SingleURIAllowOmitNoOfflineEntities(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-015")
}

func TestScenario_AC_016_SingleURIAllowOmitOfflineEntities(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-016")
}

func TestScenario_AC_017_SingleURIAllowOmitNoStore(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-017")
}

func TestScenario_AC_018_SingleURIAllowOmitExpiredCode(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-018")
}

func TestScenario_AC_019_SingleURIAllowOmitReplayedCode(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-019")
}

func TestScenario_AC_020_SingleURIAllowOmitMarksConsumed(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-020")
}

func TestScenario_AC_021_SingleURIAllowOmitClientMismatch(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-021")
}

func TestScenario_AC_022_SingleURIAllowOmitUnsupportedGrant(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-022")
}

func TestScenario_AC_023_SingleURIAllowOmitRedirectURIMismatch(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-023")
}

func TestScenario_AC_024_SingleURIAllowOmitAccountNotFound(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-024")
}

func TestScenario_AC_025_EmptyBodyMissingGrantType(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-025")
}

func TestScenario_AC_026_AuthCodeWithoutCodeParam(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-026")
}

func TestScenario_AC_027_MultiURIWithoutRedirectURIParam(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-027")
}

func TestScenario_AC_028_UnknownCodeRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-028")
}

func TestScenario_AC_029_DownstreamExceptionReturnsServerError(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-029")
}
