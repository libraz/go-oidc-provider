package scenarios_test

// Catalog: test/scenarios/catalog/discovery.yaml (DIS-NNN)
// Spec:
//   - OpenID Connect Discovery 1.0 §3, §4
//   - RFC 8414 — OAuth 2.0 Authorization Server Metadata
//   - RFC 8615 — Well-Known URIs
//   - RFC 9207 — `authorization_response_iss_parameter_supported`

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

const wellKnownOIDC = "/.well-known/openid-configuration"

// fetchDiscovery issues a GET against the OP's discovery endpoint and
// returns the status code, response headers, and decoded JSON document.
// The body is closed before returning so callers do not have to manage
// it.
func fetchDiscovery(tb testing.TB, base string) (int, http.Header, map[string]any) {
	tb.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, base+wellKnownOIDC, http.NoBody)
	if err != nil {
		tb.Fatalf("NewRequest: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		tb.Fatalf("GET %s: %v", req.URL, err)
	}
	defer resp.Body.Close()

	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		tb.Fatalf("decode discovery body: %v", err)
	}
	return resp.StatusCode, resp.Header.Clone(), doc
}

// TestScenario_DIS_001_DiscoveryServedWith200JSON checks that the
// discovery endpoint replies 200 with `application/json`.
//
// Spec: OIDC Discovery §4 / RFC 8414 §3.
func TestScenario_DIS_001_DiscoveryServedWith200JSON(t *testing.T) {
	t.Parallel()

	p := testkit.NewProvider(t)

	status, headers, _ := fetchDiscovery(t, p.Server.URL)
	if status != http.StatusOK {
		t.Fatalf("status=%d want 200", status)
	}
	if got := headers.Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Errorf("Content-Type=%q want application/json prefix", got)
	}
}

// TestScenario_DIS_020_MandatoryOIDCMetadataFieldsPresent verifies the
// hard-required OIDC Discovery §3 fields are in every default response.
//
// Spec: OIDC Discovery §3.
func TestScenario_DIS_020_MandatoryOIDCMetadataFieldsPresent(t *testing.T) {
	t.Parallel()

	p := testkit.NewProvider(t)

	_, _, doc := fetchDiscovery(t, p.Server.URL)

	required := []string{
		"issuer",
		"authorization_endpoint",
		"token_endpoint",
		"jwks_uri",
		"response_types_supported",
		"subject_types_supported",
		"id_token_signing_alg_values_supported",
	}
	for _, key := range required {
		if _, ok := doc[key]; !ok {
			t.Errorf("discovery doc missing required field %q", key)
		}
	}
	if got, _ := doc["issuer"].(string); got != p.Issuer {
		t.Errorf("issuer=%q want %q", got, p.Issuer)
	}
}

// TestScenario_DIS_022_FeatureEndpointsAdvertisedWhenEnabled covers the
// catalog row's positive and negative facets: opt-in feature endpoints
// MUST appear in discovery iff the matching feature is enabled.
//
// `end_session_endpoint` is excluded from the "hidden by default" facet
// because the OP enables RP-Initiated Logout by default;
// `backchannel_authentication_endpoint` is excluded until the CIBA
// feature lands.
//
// Spec: RFC 8414 §3, RFC 9126 §5, RFC 7662 §2.
func TestScenario_DIS_022_FeatureEndpointsAdvertisedWhenEnabled(t *testing.T) {
	t.Parallel()

	t.Run("hidden by default", func(t *testing.T) {
		t.Parallel()
		p := testkit.NewProvider(t)
		_, _, doc := fetchDiscovery(t, p.Server.URL)
		hidden := []string{
			"pushed_authorization_request_endpoint",
			"introspection_endpoint",
			"revocation_endpoint",
			"device_authorization_endpoint",
		}
		for _, key := range hidden {
			if _, ok := doc[key]; ok {
				t.Errorf("discovery doc must NOT advertise %q without the corresponding feature", key)
			}
		}
	})

	t.Run("PAR + Introspect enabled", func(t *testing.T) {
		t.Parallel()
		p := testkit.NewProvider(t,
			testkit.WithOptions(
				op.WithFeature(feature.PAR),
				op.WithFeature(feature.Introspect),
			),
		)
		_, _, doc := fetchDiscovery(t, p.Server.URL)
		parURL, _ := doc["pushed_authorization_request_endpoint"].(string)
		if !strings.HasPrefix(parURL, p.Issuer) || !strings.HasSuffix(parURL, "/par") {
			t.Errorf("pushed_authorization_request_endpoint=%q must be advertised under issuer", parURL)
		}
		introspectURL, _ := doc["introspection_endpoint"].(string)
		if !strings.HasPrefix(introspectURL, p.Issuer) || !strings.HasSuffix(introspectURL, "/introspect") {
			t.Errorf("introspection_endpoint=%q must be advertised under issuer", introspectURL)
		}
	})
}

// --- Pending bindings --------------------------------------------------
//
// The functions below establish a 1:1 mapping between catalog rows in
// test/scenarios/catalog/discovery.yaml and Go test names. They Skip
// until the behaviour test is wired so `scripts/scenario.sh coverage`
// reports the binding.
//
// To activate one: replace the t.Skip body with the actual assertions,
// flip the row's status to "active" in discovery.yaml, and update the
// test function's doc comment with the spec citation.

// TestScenario_DIS_002_DiscoveryDoesNotBindEntities verifies that the
// discovery endpoint is unauthenticated and stateless: a fresh GET
// MUST NOT mint a session cookie, MUST NOT emit a client/session/token
// audit event, and MUST NOT depend on any prior entity in the store.
//
// Spec: OIDC Discovery §4 (the document is published at a well-known
// location and is not gated by any authentication context).
func TestScenario_DIS_002_DiscoveryDoesNotBindEntities(t *testing.T) {
	t.Parallel()

	audit := scenariokit.NewAuditCapture()
	p := testkit.NewProvider(t, testkit.WithOptions(op.WithAuditLogger(audit.Logger())))

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, p.Server.URL+wellKnownOIDC, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	if cookies := resp.Cookies(); len(cookies) != 0 {
		t.Errorf("discovery response set %d cookie(s); the endpoint must be stateless: %+v", len(cookies), cookies)
	}
	for _, ev := range audit.Events() {
		// The discovery handler is unauthenticated and stateless;
		// any client/session/token-bound audit event leaking from
		// it would be a regression. Audit events for OP self-state
		// (e.g. provider startup) are permitted.
		switch {
		case strings.HasPrefix(ev.Name, "client."),
			strings.HasPrefix(ev.Name, "session."),
			strings.HasPrefix(ev.Name, "token."),
			strings.HasPrefix(ev.Name, "grant."),
			strings.HasPrefix(ev.Name, "login."):
			t.Errorf("discovery emitted audit event %q (must not bind to any client/session/token entity)", ev.Name)
		}
	}
}

func TestScenario_DIS_003_EmbedderExtraPropertiesMerge(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DIS-003")
}

func TestScenario_DIS_004_EmbedderCannotOverrideOPControlledFields(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DIS-004")
}

func TestScenario_DIS_010_KnownErrorReturnsJSONEnvelope(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DIS-010")
}

func TestScenario_DIS_011_DiscoveryErrorAuditEvent(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DIS-011")
}

func TestScenario_DIS_012_UnknownExceptionReturnsServerError(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DIS-012")
}

func TestScenario_DIS_013_ServerErrorAuditEvent(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DIS-013")
}

func TestScenario_DIS_021_RFC8414MetadataFieldsPresent(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DIS-021")
}

// TestScenario_DIS_030_IssParameterSupportedWhenIssFeatureOn verifies
// that when the issuer-identification feature is enabled (the default),
// the discovery document advertises
// `authorization_response_iss_parameter_supported: true`. RPs key off
// this flag to know they can/should validate the redirect-level `iss`
// parameter.
//
// Spec: RFC 9207 §3 (discovery field). Cross-ref:
// issuer_identification#ISS-001.
func TestScenario_DIS_030_IssParameterSupportedWhenIssFeatureOn(t *testing.T) {
	t.Parallel()

	p := testkit.NewProvider(t)

	_, _, doc := fetchDiscovery(t, p.Server.URL)
	got, ok := doc["authorization_response_iss_parameter_supported"]
	if !ok {
		t.Fatalf("authorization_response_iss_parameter_supported missing; iss feature is on by default")
	}
	b, isBool := got.(bool)
	if !isBool || !b {
		t.Errorf("authorization_response_iss_parameter_supported=%v want true", got)
	}
}

func TestScenario_DIS_031_EncryptionMetadataAdvertisedWhenFeatureOn(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DIS-031")
}

// TestScenario_DIS_032_JARMMetadataAdvertisedWhenFeatureOn verifies
// that when the JARM feature is enabled, the discovery document
// advertises `authorization_signing_alg_values_supported` (so RPs can
// pin a verification alg) and that `response_modes_supported` includes
// the JARM modes `jwt`, `query.jwt`, `fragment.jwt`, and
// `form_post.jwt`. The encryption-side fields
// (`authorization_encryption_*`) are gated on the encryption feature
// and are covered separately by DIS-031.
//
// Spec: JARM (OpenID Foundation FAPI 2.0).
func TestScenario_DIS_032_JARMMetadataAdvertisedWhenFeatureOn(t *testing.T) {
	t.Parallel()

	p := testkit.NewProvider(t, testkit.WithOptions(op.WithFeature(feature.JARM)))

	_, _, doc := fetchDiscovery(t, p.Server.URL)

	algs, _ := doc["authorization_signing_alg_values_supported"].([]any)
	if len(algs) == 0 {
		t.Fatalf("authorization_signing_alg_values_supported missing/empty: %v",
			doc["authorization_signing_alg_values_supported"])
	}

	modes, _ := doc["response_modes_supported"].([]any)
	if len(modes) == 0 {
		t.Fatalf("response_modes_supported missing/empty: %v", doc["response_modes_supported"])
	}
	want := map[string]bool{
		"jwt":           false,
		"query.jwt":     false,
		"fragment.jwt":  false,
		"form_post.jwt": false,
	}
	for _, raw := range modes {
		mode, _ := raw.(string)
		if _, ok := want[mode]; ok {
			want[mode] = true
		}
	}
	for mode, present := range want {
		if !present {
			t.Errorf("response_modes_supported=%v must include JARM mode %q", modes, mode)
		}
	}
}

func TestScenario_DIS_033_WebMessageResponseModeAdvertisedWhenOn(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DIS-033")
}

func TestScenario_DIS_034_DeviceAuthorizationEndpointWhenDeviceOn(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DIS-034")
}

// TestScenario_DIS_035_PAREndpointAdvertisedWhenPAROn verifies that
// when the PAR feature (RFC 9126) is enabled, the discovery document
// advertises `pushed_authorization_request_endpoint` and exposes
// `require_pushed_authorization_requests` as a boolean. RPs key off
// these fields to discover the PAR URL and to learn whether direct
// /authorize calls are still permitted.
//
// Spec: RFC 9126 §5 (discovery metadata).
func TestScenario_DIS_035_PAREndpointAdvertisedWhenPAROn(t *testing.T) {
	t.Parallel()

	p := testkit.NewProvider(t, testkit.WithOptions(op.WithFeature(feature.PAR)))

	_, _, doc := fetchDiscovery(t, p.Server.URL)

	parURL, ok := doc["pushed_authorization_request_endpoint"].(string)
	if !ok || parURL == "" {
		t.Fatalf("pushed_authorization_request_endpoint missing/empty: %v",
			doc["pushed_authorization_request_endpoint"])
	}
	if !strings.HasSuffix(parURL, "/par") && !strings.Contains(parURL, "/par") {
		t.Errorf("pushed_authorization_request_endpoint=%q must reference a /par path", parURL)
	}
	// RFC 9126 §5 lists require_pushed_authorization_requests as an
	// OPTIONAL boolean defaulting to false. When advertised it MUST be
	// a JSON boolean; absence is equivalent to false.
	if require, present := doc["require_pushed_authorization_requests"]; present {
		if _, isBool := require.(bool); !isBool {
			t.Errorf("require_pushed_authorization_requests=%v must be boolean", require)
		}
	}
}

func TestScenario_DIS_036_RequestObjectMetadataConsistent(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DIS-036")
}

func TestScenario_DIS_040_DiscoveryEndpointsAreCORSOpen(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DIS-040")
}

func TestScenario_DIS_041_OAuthMirrorMatchesOIDCConfig(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DIS-041")
}
