package scenarios_test

// Catalog: test/scenarios/catalog/discovery.yaml (DIS-NNN)
// Spec:
//   - OpenID Connect Discovery 1.0 §3, §4
//   - RFC 8414 — OAuth 2.0 Authorization Server Metadata
//   - RFC 8615 — Well-Known URIs
//   - RFC 9207 — `authorization_response_iss_parameter_supported`

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
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

// TestScenario_DIS_003_EmbedderExtraPropertiesMerge verifies that
// embedder-injected static metadata (RFC 8414 §2 "service_documentation")
// AND arbitrary passthrough keys reach the discovery JSON at the top
// level. The OP merges the embedder-supplied map into the document at
// build time so RPs see the union of OP-controlled fields and
// embedder extensions.
//
// Spec: OIDC Discovery §4 / RFC 8414 §3.
func TestScenario_DIS_003_EmbedderExtraPropertiesMerge(t *testing.T) {
	t.Parallel()

	p := testkit.NewProvider(t,
		testkit.WithOptions(
			op.WithDiscoveryMetadata(op.DiscoveryMetadata{
				ServiceDocumentation: "https://idp.example.com/docs",
				Extra: map[string]any{
					"x_custom_thing": "frobnicate",
				},
			}),
		),
	)

	_, _, doc := fetchDiscovery(t, p.Server.URL)
	if got, _ := doc["service_documentation"].(string); got != "https://idp.example.com/docs" {
		t.Errorf("service_documentation=%q want %q",
			got, "https://idp.example.com/docs")
	}
	if got, _ := doc["x_custom_thing"].(string); got != "frobnicate" {
		t.Errorf("x_custom_thing=%q want %q (passthrough Extra key did not reach the wire)",
			got, "frobnicate")
	}
}

// TestScenario_DIS_004_EmbedderCannotOverrideOPControlledFields pins
// the override-deny invariant: an embedder MUST NOT be able to inject
// a value for an OP-controlled field through op.WithDiscoveryMetadata.
// op.New surfaces a configuration error that names the offending key,
// so a typo cannot silently shadow a protocol-defining field.
//
// Spec: RFC 8414 §3 (the OP owns the protocol-shaping metadata).
func TestScenario_DIS_004_EmbedderCannotOverrideOPControlledFields(t *testing.T) {
	t.Parallel()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	cookieKey := make([]byte, 32)
	if _, err := rand.Read(cookieKey); err != nil {
		t.Fatalf("generate cookie key: %v", err)
	}

	const offending = "authorization_endpoint"
	_, err = op.New(
		op.WithIssuer("https://idp.testkit.invalid"),
		op.WithStore(inmem.New()),
		op.WithKeyset(op.Keyset{{KeyID: "dis-004-sig", Signer: priv}}),
		op.WithCookieKeys(cookieKey),
		op.WithDiscoveryMetadata(op.DiscoveryMetadata{
			Extra: map[string]any{
				offending: "https://attacker.example.com/auth",
			},
		}),
	)
	if err == nil {
		t.Fatal("expected error when WithDiscoveryMetadata.Extra overrides authorization_endpoint, got nil")
	}
	var typed *op.Error
	if !errors.As(err, &typed) {
		t.Fatalf("err = %v, want *op.Error", err)
	}
	if !strings.Contains(err.Error(), offending) {
		t.Errorf("err = %v, want it to mention %q", err, offending)
	}
}

// TestScenario_DIS_010_KnownErrorReturnsJSONEnvelope is OOS — see catalog out_of_scope_reason.
func TestScenario_DIS_010_KnownErrorReturnsJSONEnvelope(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DIS-010 (see catalog out_of_scope_reason)")
}

// TestScenario_DIS_011_DiscoveryErrorAuditEvent is OOS — see catalog out_of_scope_reason.
func TestScenario_DIS_011_DiscoveryErrorAuditEvent(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DIS-011 (see catalog out_of_scope_reason)")
}

// TestScenario_DIS_012_UnknownExceptionReturnsServerError is OOS — see catalog out_of_scope_reason.
func TestScenario_DIS_012_UnknownExceptionReturnsServerError(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DIS-012 (see catalog out_of_scope_reason)")
}

// TestScenario_DIS_013_ServerErrorAuditEvent is OOS — see catalog out_of_scope_reason.
func TestScenario_DIS_013_ServerErrorAuditEvent(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DIS-013 (see catalog out_of_scope_reason)")
}

// TestScenario_DIS_021_RFC8414MetadataFieldsPresent verifies that
// every RFC 8414 §2 metadata field the catalog row enumerates is
// served when the OP is configured for it. The fields split into two
// classes:
//
//   - Default-on: response_modes_supported (gated on the JARM feature
//     in the current implementation), grant_types_supported,
//     token_endpoint_auth_methods_supported. The first is enabled here
//     by turning on the JARM feature; the latter two are present in
//     every default discovery document.
//   - Embedder-supplied: service_documentation, ui_locales_supported,
//     op_policy_uri, op_tos_uri. Injected via op.WithDiscoveryMetadata.
//
// Spec: RFC 8414 §2.
func TestScenario_DIS_021_RFC8414MetadataFieldsPresent(t *testing.T) {
	t.Parallel()

	const (
		wantServiceDoc = "https://idp.example.com/docs"
		wantPolicy     = "https://idp.example.com/policy"
		wantTOS        = "https://idp.example.com/tos"
	)
	wantLocales := []string{"ja-JP", "en-US"}

	p := testkit.NewProvider(t,
		testkit.WithOptions(
			op.WithFeature(feature.JARM),
			op.WithDiscoveryMetadata(op.DiscoveryMetadata{
				ServiceDocumentation: wantServiceDoc,
				OPPolicyURI:          wantPolicy,
				OPTermsOfServiceURI:  wantTOS,
				UILocalesSupported:   wantLocales,
			}),
		),
	)

	_, _, doc := fetchDiscovery(t, p.Server.URL)

	// Default-on RFC 8414 §2 array fields. grant_types_supported and
	// token_endpoint_auth_methods_supported are advertised by every
	// build; response_modes_supported is JARM-gated and the option
	// above turns the feature on.
	for _, key := range []string{
		"response_modes_supported",
		"grant_types_supported",
		"token_endpoint_auth_methods_supported",
	} {
		arr, ok := doc[key].([]any)
		if !ok {
			t.Errorf("%s missing or not an array: %T (%v)", key, doc[key], doc[key])
			continue
		}
		if len(arr) == 0 {
			t.Errorf("%s is empty: %v", key, arr)
		}
	}

	// Embedder-supplied scalar fields.
	stringChecks := map[string]string{
		"service_documentation": wantServiceDoc,
		"op_policy_uri":         wantPolicy,
		"op_tos_uri":            wantTOS,
	}
	for key, want := range stringChecks {
		got, _ := doc[key].(string)
		if got != want {
			t.Errorf("%s=%q want %q", key, got, want)
		}
	}

	// Embedder-supplied locale list — JSON array of strings.
	locales, ok := doc["ui_locales_supported"].([]any)
	if !ok {
		t.Fatalf("ui_locales_supported missing or not an array: %T (%v)",
			doc["ui_locales_supported"], doc["ui_locales_supported"])
	}
	if len(locales) != len(wantLocales) {
		t.Fatalf("ui_locales_supported len=%d want %d (%v)",
			len(locales), len(wantLocales), locales)
	}
	for i, want := range wantLocales {
		if locales[i] != want {
			t.Errorf("ui_locales_supported[%d]=%v want %q", i, locales[i], want)
		}
	}
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

// TestScenario_DIS_031_EncryptionMetadataAdvertisedWhenFeatureOn is OOS — see catalog out_of_scope_reason.
func TestScenario_DIS_031_EncryptionMetadataAdvertisedWhenFeatureOn(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DIS-031 (see catalog out_of_scope_reason)")
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

// TestScenario_DIS_036_RequestObjectMetadataConsistent pins the
// JAR-related discovery fields to feature.JAR enablement. With JAR
// off, the OP MUST advertise request_parameter_supported=false and
// request_uri_parameter_supported=false; the
// request_object_signing_alg_values_supported and
// require_request_uri_registration fields are omitted entirely
// because there is no request-object verification chain to advertise.
// With JAR on, both *_supported booleans flip to true, the OP
// advertises a non-empty request_object_signing_alg_values_supported
// (RFC 9101 §10.1), and require_request_uri_registration=true
// reflects the FAPI 2.0 Message Signing posture that every
// request_uri MUST be preregistered.
//
// Spec: RFC 9101 §10.1 / OIDC Core §16.2.
func TestScenario_DIS_036_RequestObjectMetadataConsistent(t *testing.T) {
	t.Parallel()

	t.Run("JAR off", func(t *testing.T) {
		t.Parallel()
		p := testkit.NewProvider(t)
		_, _, doc := fetchDiscovery(t, p.Server.URL)

		if got, _ := doc["request_parameter_supported"].(bool); got {
			t.Errorf("request_parameter_supported=%v want false (JAR off)", got)
		}
		if got, _ := doc["request_uri_parameter_supported"].(bool); got {
			t.Errorf("request_uri_parameter_supported=%v want false (JAR off)", got)
		}
		if _, present := doc["request_object_signing_alg_values_supported"]; present {
			t.Errorf("request_object_signing_alg_values_supported must be omitted when JAR is off; doc[%q]=%v",
				"request_object_signing_alg_values_supported",
				doc["request_object_signing_alg_values_supported"])
		}
		if _, present := doc["require_request_uri_registration"]; present {
			t.Errorf("require_request_uri_registration must be omitted when JAR is off; doc[%q]=%v",
				"require_request_uri_registration",
				doc["require_request_uri_registration"])
		}
	})

	t.Run("JAR on", func(t *testing.T) {
		t.Parallel()
		p := testkit.NewProvider(t, testkit.WithOptions(op.WithFeature(feature.JAR)))
		_, _, doc := fetchDiscovery(t, p.Server.URL)

		reqParam, ok := doc["request_parameter_supported"].(bool)
		if !ok || !reqParam {
			t.Errorf("request_parameter_supported=%v want true (JAR on)", doc["request_parameter_supported"])
		}
		reqURI, ok := doc["request_uri_parameter_supported"].(bool)
		if !ok || !reqURI {
			t.Errorf("request_uri_parameter_supported=%v want true (JAR on)", doc["request_uri_parameter_supported"])
		}
		reqReg, ok := doc["require_request_uri_registration"].(bool)
		if !ok || !reqReg {
			t.Errorf("require_request_uri_registration=%v want true (JAR on, FAPI 2.0 Message Signing posture)",
				doc["require_request_uri_registration"])
		}
		algs, _ := doc["request_object_signing_alg_values_supported"].([]any)
		if len(algs) == 0 {
			t.Errorf("request_object_signing_alg_values_supported missing/empty when JAR is on: %v",
				doc["request_object_signing_alg_values_supported"])
		}
	})
}

// TestScenario_DIS_040_DiscoveryEndpointsAreCORSOpen verifies that
// the well-known discovery endpoint is CORS-open: a GET from any
// Origin receives Access-Control-Allow-Origin (echoed or "*") with
// Vary: Origin, and a preflight OPTIONS allows GET. The OP MUST
// expose the document to any RP regardless of allowlist
// configuration, because RPs and library tooling fetch it before any
// trust relationship has been established. The cors_test.go
// COR-001 / COR-002 rows pin the same surface; this row reasserts it
// from the discovery feature so a regression in the discovery mount
// is caught on the discovery side too.
//
// Spec: OIDC Discovery §5 / Fetch CORS.
func TestScenario_DIS_040_DiscoveryEndpointsAreCORSOpen(t *testing.T) {
	t.Parallel()

	p := testkit.NewProvider(t)
	const probeOrigin = "https://random.invalid"

	// Actual GET: response must echo (or wildcard) the Origin and
	// stamp Vary: Origin so a shared cache cannot conflate origins.
	getStatus, getHeaders := corsRequestFrom(t, http.MethodGet,
		p.Server.URL+wellKnownOIDC, probeOrigin, http.MethodGet)
	if getStatus != http.StatusOK {
		t.Fatalf("GET status=%d want 200", getStatus)
	}
	allow := getHeaders.Get("Access-Control-Allow-Origin")
	if allow != probeOrigin && allow != "*" {
		t.Errorf("GET Access-Control-Allow-Origin=%q want %q or *", allow, probeOrigin)
	}
	if vary := getHeaders.Get("Vary"); !strings.Contains(vary, "Origin") {
		t.Errorf("GET Vary=%q must include Origin", vary)
	}

	// Preflight OPTIONS: must succeed and advertise GET.
	optStatus, optHeaders := corsRequestFrom(t, http.MethodOptions,
		p.Server.URL+wellKnownOIDC, probeOrigin, http.MethodGet)
	if optStatus != http.StatusNoContent && optStatus != http.StatusOK {
		t.Fatalf("preflight status=%d want 204 or 200", optStatus)
	}
	if methods := optHeaders.Get("Access-Control-Allow-Methods"); !strings.Contains(methods, http.MethodGet) {
		t.Errorf("preflight Access-Control-Allow-Methods=%q must allow GET", methods)
	}
	if optHeaders.Get("Access-Control-Allow-Origin") == "" {
		t.Errorf("preflight missing Access-Control-Allow-Origin")
	}
}

func TestScenario_DIS_041_OAuthMirrorMatchesOIDCConfig(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DIS-041")
}
