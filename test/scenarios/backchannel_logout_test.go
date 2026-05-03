package scenarios_test

// Catalog: test/scenarios/catalog/backchannel_logout.yaml (BCL-NNN)
// Spec:
//   - OIDC Back-Channel Logout 1.0
//   - OIDC Core 1.0 §2, §3.1.3.6
//   - OIDC Discovery 1.0
//   - OIDC Front-Channel Logout 1.0 / Session Management 1.0
//   - RFC 8417, RFC 7519, RFC 7515

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/libraz/go-oidc-provider/op/testkit"
)

// TestScenario_BCL_001_LogoutTokenShapeWithSid is OOS — see catalog
// out_of_scope_reason.
func TestScenario_BCL_001_LogoutTokenShapeWithSid(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: BCL-001 (see catalog out_of_scope_reason)")
}

// TestScenario_BCL_002_LogoutTokenOmitsSidWhenNotRequired is OOS — see
// catalog out_of_scope_reason.
func TestScenario_BCL_002_LogoutTokenOmitsSidWhenNotRequired(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: BCL-002 (see catalog out_of_scope_reason)")
}

// TestScenario_BCL_003_DeliveryFailureSurfacedToOperators is OOS —
// see catalog out_of_scope_reason.
func TestScenario_BCL_003_DeliveryFailureSurfacedToOperators(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: BCL-003 (see catalog out_of_scope_reason)")
}

// TestScenario_BCL_004_DiscoveryAdvertisesBCLSupport pins OIDC
// Back-Channel Logout 1.0 §3 plus the OIDC Discovery §3 metadata: a
// BCL-capable OP advertises end_session_endpoint together with
// backchannel_logout_supported=true and
// backchannel_logout_session_supported=true. v1.0 always emits these
// because the BCL coordinator is unconditionally wired.
//
// Spec: OIDC BCL §3 / OIDC Discovery §3.
func TestScenario_BCL_004_DiscoveryAdvertisesBCLSupport(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		tk.Server.URL+"/.well-known/openid-configuration", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	doc := map[string]any{}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	if got, _ := doc["end_session_endpoint"].(string); got == "" {
		t.Errorf("end_session_endpoint missing or empty (doc=%v)", doc)
	}
	if got, _ := doc["backchannel_logout_supported"].(bool); !got {
		t.Errorf("backchannel_logout_supported=%v want true (doc=%v)", doc["backchannel_logout_supported"], doc)
	}
	if got, _ := doc["backchannel_logout_session_supported"].(bool); !got {
		t.Errorf("backchannel_logout_session_supported=%v want true", doc["backchannel_logout_session_supported"])
	}
}

// TestScenario_BCL_005_AuthorizeIDTokenCarriesSid is OOS — see catalog
// out_of_scope_reason.
func TestScenario_BCL_005_AuthorizeIDTokenCarriesSid(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: BCL-005 (see catalog out_of_scope_reason)")
}

// TestScenario_BCL_006_CodeGrantIDTokenCarriesSid is OOS — see catalog
// out_of_scope_reason.
func TestScenario_BCL_006_CodeGrantIDTokenCarriesSid(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: BCL-006 (see catalog out_of_scope_reason)")
}

// TestScenario_BCL_007_RefreshGrantIDTokenCarriesSid is OOS — see
// catalog out_of_scope_reason.
func TestScenario_BCL_007_RefreshGrantIDTokenCarriesSid(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: BCL-007 (see catalog out_of_scope_reason)")
}

// TestScenario_BCL_008_GlobalLogoutFansOutToVisitedClients is OOS —
// see catalog out_of_scope_reason.
func TestScenario_BCL_008_GlobalLogoutFansOutToVisitedClients(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: BCL-008 (see catalog out_of_scope_reason)")
}

// TestScenario_BCL_009_TargetedLogoutOnlyContactsInitiator is OOS —
// see catalog out_of_scope_reason.
func TestScenario_BCL_009_TargetedLogoutOnlyContactsInitiator(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: BCL-009 (see catalog out_of_scope_reason)")
}

// TestScenario_BCL_010_ClientWithoutBCLUriIsSkipped is OOS — see
// catalog out_of_scope_reason.
func TestScenario_BCL_010_ClientWithoutBCLUriIsSkipped(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: BCL-010 (see catalog out_of_scope_reason)")
}
