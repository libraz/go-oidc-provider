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
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op/testkit"
)

func TestScenario_UI_001_JWTUserinfoRequiresEndpointEnabled(t *testing.T) {
	t.Parallel()
	t.Skip("pending: UI-001")
}

func TestScenario_UI_002_GETReturnsClaimsHonoringRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: UI-002")
}

func TestScenario_UI_003_POSTReturnsSameBody(t *testing.T) {
	t.Parallel()
	t.Skip("pending: UI-003")
}

func TestScenario_UI_004_RequestContextEntitiesPopulated(t *testing.T) {
	t.Parallel()
	t.Skip("pending: UI-004")
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
	t.Skip("pending: UI-007")
}

func TestScenario_UI_008_ClientGoneReturnsInvalidToken(t *testing.T) {
	t.Parallel()
	t.Skip("pending: UI-008")
}

func TestScenario_UI_009_AccountGoneReturnsInvalidToken(t *testing.T) {
	t.Parallel()
	t.Skip("pending: UI-009")
}

func TestScenario_UI_010_RequestNarrowsScopeAllowed(t *testing.T) {
	t.Parallel()
	t.Skip("pending: UI-010")
}

func TestScenario_UI_011_RequestExpandsScopeForbidden(t *testing.T) {
	t.Parallel()
	t.Skip("pending: UI-011")
}

func TestScenario_UI_012_NoBearerEnumeratesBothChallenges(t *testing.T) {
	t.Parallel()
	t.Skip("pending: UI-012")
}

func TestScenario_UI_013_MultipleBearerCarriersRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: UI-013")
}

func TestScenario_UI_014_AuthorizationHeaderOnePartRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: UI-014")
}

func TestScenario_UI_015_AuthorizationHeaderTooManyPartsRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: UI-015")
}

func TestScenario_UI_016_WrongAuthSchemeRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: UI-016")
}

func TestScenario_UI_017_EmptyTokenViaQueryRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: UI-017")
}

func TestScenario_UI_018_EmptyTokenViaBodyRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: UI-018")
}

func TestScenario_UI_019_EmptyBodyAndNoHeaderRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: UI-019")
}
