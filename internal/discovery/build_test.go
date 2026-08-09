package discovery_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/discovery"
)

// TestValidateIssuer enforces the OIDC Discovery 1.0 §3 / FAPI 2.0
// §5.4 shape constraints on the issuer URL. The matrix fixes the
// allowed shapes (https, no trailing slash, no query / fragment) and
// the loopback-only carve-out for the http scheme (development boots
// with a plain-text issuer must still surface as a misconfiguration
// in production). Each row drives a single ValidateIssuer call.
func TestValidateIssuer(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		issuer  string
		wantErr bool
	}{
		{"empty", "", true},
		{"plain-https", "https://idp.example.com", false},
		{"https-with-port", "https://idp.example.com:8443", false},
		{"https-with-path", "https://idp.example.com/oidc", false},
		{"trailing-slash", "https://idp.example.com/", true},
		{"trailing-slash-with-path", "https://idp.example.com/oidc/", true},
		{"with-query", "https://idp.example.com/?foo=bar", true},
		{"with-fragment", "https://idp.example.com/#x", true},
		{"http-public", "http://idp.example.com", true},
		{"http-localhost", "http://localhost:8080", true},
		{"http-loopback-v4", "http://127.0.0.1:8080", false},
		{"http-loopback-v4-secondary", "http://127.0.0.2:8080", false},
		{"http-loopback-v6", "http://[::1]:8080", false},
		{"http-private-ip", "http://10.0.0.1", true},
		{"unknown-scheme", "ftp://idp.example.com", true},
		{"relative", "/oidc", true},
		{"https-uppercase-scheme", "HTTPS://idp.example.com", true},
		{"https-mixedcase-scheme", "HtTpS://idp.example.com", true},
		{"https-uppercase-host", "https://IDP.EXAMPLE.COM", true},
		{"https-mixedcase-host-with-path", "https://IDP.example.com/oidc", true},
		{"https-default-port", "https://idp.example.com:443", true},
		{"https-default-port-with-path", "https://idp.example.com:443/oidc", true},
		{"http-default-port-loopback", "http://127.0.0.1:80", true},
		{"path-traversal", "https://idp.example.com/a/../b", true},
		{"path-dot-segment", "https://idp.example.com/a/./b", true},
		{"path-double-slash", "https://idp.example.com//oidc", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := discovery.ValidateIssuer(tc.issuer)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ValidateIssuer(%q) = nil, want error", tc.issuer)
				}
				if !errors.Is(err, discovery.ErrIssuerInvalid) {
					t.Errorf("ValidateIssuer(%q) error = %v, want errors.Is ErrIssuerInvalid", tc.issuer, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateIssuer(%q) unexpected error: %v", tc.issuer, err)
			}
		})
	}
}

func TestBuild_FormsAbsoluteURLs(t *testing.T) {
	t.Parallel()

	doc := discovery.Build(discovery.Input{
		Issuer:      "https://idp.example.com",
		MountPrefix: "/oidc",
		Endpoints: discovery.EndpointPaths{
			JWKS:       "/jwks",
			Authorize:  "/auth",
			Token:      "/token",
			UserInfo:   "/userinfo",
			EndSession: "/end_session",
		},
		Features:        discovery.Features{AuthorizeEndpoint: true},
		GrantsSupported: []string{"authorization_code", "refresh_token"},
	})

	cases := map[string]string{
		doc.Issuer:                "https://idp.example.com",
		doc.AuthorizationEndpoint: "https://idp.example.com/oidc/auth",
		doc.TokenEndpoint:         "https://idp.example.com/oidc/token",
		doc.UserInfoEndpoint:      "https://idp.example.com/oidc/userinfo",
		doc.JWKSURI:               "https://idp.example.com/oidc/jwks",
		doc.EndSessionEndpoint:    "https://idp.example.com/oidc/end_session",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("got %q want %q", got, want)
		}
	}
	if !doc.BackchannelLogoutSupported {
		t.Error("backchannel_logout_supported must be true")
	}
	if doc.BackchannelLogoutSessionSupported {
		t.Error("backchannel_logout_session_supported must be false without RP-specific SID lineage")
	}
}

func TestBuild_RootMountPrefix(t *testing.T) {
	t.Parallel()

	doc := discovery.Build(discovery.Input{
		Issuer:      "https://idp.example.com",
		MountPrefix: "/",
		Endpoints: discovery.EndpointPaths{
			JWKS:      "/jwks",
			Authorize: "/auth",
			Token:     "/token",
		},
		Features: discovery.Features{AuthorizeEndpoint: true},
	})
	if got := doc.AuthorizationEndpoint; got != "https://idp.example.com/auth" {
		t.Errorf("authorization_endpoint=%q", got)
	}
	if got := doc.JWKSURI; got != "https://idp.example.com/jwks" {
		t.Errorf("jwks_uri=%q", got)
	}
}

func TestBuild_OmitsDisabledFeatureEndpoints(t *testing.T) {
	t.Parallel()

	doc := discovery.Build(discovery.Input{
		Issuer:      "https://idp.example.com",
		MountPrefix: "/oidc",
		Endpoints: discovery.EndpointPaths{
			JWKS:       "/jwks",
			Authorize:  "/auth",
			Token:      "/token",
			Introspect: "/introspect",
			Revoke:     "/revoke",
			PAR:        "/par",
		},
		Features: discovery.Features{}, // all disabled
	})
	if doc.IntrospectionEndpoint != "" {
		t.Error("introspection endpoint must be omitted when feature disabled")
	}
	if doc.RevocationEndpoint != "" {
		t.Error("revocation endpoint must be omitted when feature disabled")
	}
	if doc.PushedAuthorizationRequestEndpoint != "" {
		t.Error("PAR endpoint must be omitted when feature disabled")
	}
	if doc.RequestParameterSupported || doc.RequestURIParameterSupported {
		t.Error("JAR parameters must be false when feature disabled")
	}
}

func TestBuild_EmitsEndpointsWhenFeaturesEnabled(t *testing.T) {
	t.Parallel()

	doc := discovery.Build(discovery.Input{
		Issuer:      "https://idp.example.com",
		MountPrefix: "/oidc",
		Endpoints: discovery.EndpointPaths{
			JWKS:       "/jwks",
			Authorize:  "/auth",
			Token:      "/token",
			Introspect: "/introspect",
			Revoke:     "/revoke",
			PAR:        "/par",
		},
		Features: discovery.Features{
			PAR: true, JAR: true, Introspect: true, Revoke: true,
		},
	})
	if got := doc.IntrospectionEndpoint; got != "https://idp.example.com/oidc/introspect" {
		t.Errorf("introspection_endpoint=%q", got)
	}
	if got := doc.RevocationEndpoint; got != "https://idp.example.com/oidc/revoke" {
		t.Errorf("revocation_endpoint=%q", got)
	}
	if got := doc.PushedAuthorizationRequestEndpoint; got != "https://idp.example.com/oidc/par" {
		t.Errorf("par_endpoint=%q", got)
	}
	if !doc.RequestParameterSupported || !doc.RequestURIParameterSupported {
		t.Error("JAR parameters must be true when feature enabled")
	}
}

func TestBuild_EmitsRequirePARWhenConfigured(t *testing.T) {
	t.Parallel()

	doc := discovery.Build(discovery.Input{
		Issuer:      "https://idp.example.com",
		MountPrefix: "/oidc",
		Endpoints: discovery.EndpointPaths{
			JWKS:      "/jwks",
			Authorize: "/auth",
			Token:     "/token",
			PAR:       "/par",
		},
		Features:   discovery.Features{PAR: true},
		RequirePAR: true,
	})
	if !doc.RequirePushedAuthorizationRequests {
		t.Fatal("require_pushed_authorization_requests must be true when RequirePAR is configured")
	}
}

func TestBuild_StaticPolicyValues(t *testing.T) {
	t.Parallel()

	doc := discovery.Build(discovery.Input{
		Issuer:      "https://idp.example.com",
		MountPrefix: "/oidc",
		Endpoints:   discovery.EndpointPaths{JWKS: "/jwks", Authorize: "/auth", Token: "/token"},
		Features:    discovery.Features{AuthorizeEndpoint: true},
	})
	if len(doc.ResponseTypesSupported) != 1 || doc.ResponseTypesSupported[0] != "code" {
		t.Errorf("response_types_supported=%v want [code]", doc.ResponseTypesSupported)
	}
	if len(doc.IDTokenSigningAlgValuesSupported) != 1 || doc.IDTokenSigningAlgValuesSupported[0] != "ES256" {
		t.Errorf("id_token_signing_alg=%v want [ES256]", doc.IDTokenSigningAlgValuesSupported)
	}
	if len(doc.CodeChallengeMethodsSupported) != 1 || doc.CodeChallengeMethodsSupported[0] != "S256" {
		t.Errorf("code_challenge_methods=%v want [S256]", doc.CodeChallengeMethodsSupported)
	}
}

// TestBuild_OmitsAuthorizeSurfacesForMachineToMachineGrants covers the
// grant set of a client_credentials-only deployment: the router mounts
// neither /authorize nor /end_session, and no session teardown can ever
// emit a Logout Token, so none of those surfaces may be advertised.
// response_types_supported stays present but empty because RFC 8414 §2
// marks it REQUIRED with no carve-out.
//
// Spec: RFC 8414 §2 / OpenID Connect RP-Initiated Logout 1.0 §2 /
// OpenID Connect Back-Channel Logout 1.0 §2.
func TestBuild_OmitsAuthorizeSurfacesForMachineToMachineGrants(t *testing.T) {
	t.Parallel()

	doc := discovery.Build(discovery.Input{
		Issuer:      "https://idp.example.com",
		MountPrefix: "/oidc",
		Endpoints: discovery.EndpointPaths{
			JWKS:       "/jwks",
			Authorize:  "/auth",
			Token:      "/token",
			EndSession: "/end_session",
		},
		Features:        discovery.Features{}, // AuthorizeEndpoint off.
		GrantsSupported: []string{"client_credentials"},
	})
	if doc.AuthorizationEndpoint != "" {
		t.Errorf("authorization_endpoint=%q, want it omitted when no grant mounts /authorize", doc.AuthorizationEndpoint)
	}
	if doc.EndSessionEndpoint != "" {
		t.Errorf("end_session_endpoint=%q, want it omitted when no grant mounts /authorize", doc.EndSessionEndpoint)
	}
	if doc.BackchannelLogoutSupported {
		t.Error("backchannel_logout_supported must be false when no session can be terminated")
	}
	if doc.ResponseTypesSupported == nil {
		t.Fatal("response_types_supported = nil, want an empty non-nil array (RFC 8414 §2 marks it REQUIRED)")
	}
	if len(doc.ResponseTypesSupported) != 0 {
		t.Errorf("response_types_supported=%v, want empty", doc.ResponseTypesSupported)
	}

	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var wire map[string]any
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, absent := range []string{
		"authorization_endpoint",
		"end_session_endpoint",
		"backchannel_logout_supported",
	} {
		if _, present := wire[absent]; present {
			t.Errorf("%s must not appear on the wire for a machine-to-machine grant set", absent)
		}
	}
	types, ok := wire["response_types_supported"].([]any)
	if !ok {
		t.Fatalf("response_types_supported = %#v, want a JSON array", wire["response_types_supported"])
	}
	if len(types) != 0 {
		t.Errorf("response_types_supported=%v, want []", types)
	}
}

// TestBuild_EmitsAuthorizeSurfacesForInteractiveGrants is the positive
// half of [TestBuild_OmitsAuthorizeSurfacesForMachineToMachineGrants]:
// an OP whose grant set mounts /authorize advertises the full set.
func TestBuild_EmitsAuthorizeSurfacesForInteractiveGrants(t *testing.T) {
	t.Parallel()

	doc := discovery.Build(discovery.Input{
		Issuer:      "https://idp.example.com",
		MountPrefix: "/oidc",
		Endpoints: discovery.EndpointPaths{
			JWKS:       "/jwks",
			Authorize:  "/auth",
			Token:      "/token",
			EndSession: "/end_session",
		},
		Features:        discovery.Features{AuthorizeEndpoint: true},
		GrantsSupported: []string{"authorization_code", "client_credentials"},
	})
	if got := doc.AuthorizationEndpoint; got != "https://idp.example.com/oidc/auth" {
		t.Errorf("authorization_endpoint=%q", got)
	}
	if got := doc.EndSessionEndpoint; got != "https://idp.example.com/oidc/end_session" {
		t.Errorf("end_session_endpoint=%q", got)
	}
	if !doc.BackchannelLogoutSupported {
		t.Error("backchannel_logout_supported must be true when /authorize is mounted")
	}
	if len(doc.ResponseTypesSupported) != 1 || doc.ResponseTypesSupported[0] != "code" {
		t.Errorf("response_types_supported=%v want [code]", doc.ResponseTypesSupported)
	}
}

func TestBuild_ProfileFiltersTokenAuthMethods(t *testing.T) {
	t.Parallel()

	doc := discovery.Build(discovery.Input{
		Issuer:      "https://idp.example.com",
		MountPrefix: "/oidc",
		Endpoints: discovery.EndpointPaths{
			JWKS: "/jwks", Authorize: "/auth", Token: "/token",
			Introspect: "/introspect", Revoke: "/revoke",
		},
		Features: discovery.Features{MTLS: true, Introspect: true, Revoke: true},
		// FAPI 2.0 §3.1.3 narrowing: secret_basic and secret_post must
		// not appear even though MTLS is enabled.
		ProfileAllowedAuthMethods: []string{"private_key_jwt"},
	})
	for _, banned := range []string{"client_secret_basic", "client_secret_post", "none"} {
		for _, got := range doc.TokenEndpointAuthMethodsSupported {
			if got == banned {
				t.Errorf("token_endpoint_auth_methods_supported still contains %q", banned)
			}
		}
	}
	if got := doc.TokenEndpointAuthMethodsSupported; len(got) != 1 || got[0] != "private_key_jwt" {
		t.Errorf("token_endpoint_auth_methods_supported=%v want [private_key_jwt]", got)
	}
	// Introspection / revocation lists mirror the filtered token list,
	// so the same bans must apply there too.
	for _, got := range doc.IntrospectionEndpointAuthMethodsSupported {
		if got == "client_secret_basic" {
			t.Errorf("introspection_endpoint_auth_methods_supported still contains client_secret_basic")
		}
	}
	for _, got := range doc.RevocationEndpointAuthMethodsSupported {
		if got == "client_secret_basic" {
			t.Errorf("revocation_endpoint_auth_methods_supported still contains client_secret_basic")
		}
	}
}

func TestBuild_NoProfileLeavesAuthMethodsAlone(t *testing.T) {
	t.Parallel()

	doc := discovery.Build(discovery.Input{
		Issuer:      "https://idp.example.com",
		MountPrefix: "/oidc",
		Endpoints:   discovery.EndpointPaths{JWKS: "/jwks", Authorize: "/auth", Token: "/token"},
	})
	// Default list is the secret pair when nothing else is configured;
	// passing a nil ProfileAllowedAuthMethods MUST NOT strip them.
	hasBasic := false
	for _, m := range doc.TokenEndpointAuthMethodsSupported {
		if m == "client_secret_basic" {
			hasBasic = true
			break
		}
	}
	if !hasBasic {
		t.Errorf("token_endpoint_auth_methods_supported = %v, want it to retain client_secret_basic when no profile is set",
			doc.TokenEndpointAuthMethodsSupported)
	}
}

func TestBuild_ClaimsSupported_OmittedByDefault(t *testing.T) {
	t.Parallel()

	doc := discovery.Build(discovery.Input{
		Issuer:      "https://idp.example.com",
		MountPrefix: "/oidc",
		Endpoints:   discovery.EndpointPaths{JWKS: "/jwks", Authorize: "/auth", Token: "/token"},
	})
	if doc.ClaimsSupported != nil {
		t.Errorf("claims_supported = %v, want nil when WithClaimsSupported is not configured", doc.ClaimsSupported)
	}
}

func TestBuild_ClaimsSupported_PreservesEmbedderList(t *testing.T) {
	t.Parallel()

	want := []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "email"}
	doc := discovery.Build(discovery.Input{
		Issuer:          "https://idp.example.com",
		MountPrefix:     "/oidc",
		Endpoints:       discovery.EndpointPaths{JWKS: "/jwks", Authorize: "/auth", Token: "/token"},
		ClaimsSupported: want,
	})
	if len(doc.ClaimsSupported) != len(want) {
		t.Fatalf("claims_supported len=%d want %d (%v)", len(doc.ClaimsSupported), len(want), doc.ClaimsSupported)
	}
	for i, c := range want {
		if doc.ClaimsSupported[i] != c {
			t.Errorf("claims_supported[%d]=%q want %q", i, doc.ClaimsSupported[i], c)
		}
	}
}

func TestBuild_ClaimsSupported_EmptySlicePreserved(t *testing.T) {
	t.Parallel()

	doc := discovery.Build(discovery.Input{
		Issuer:          "https://idp.example.com",
		MountPrefix:     "/oidc",
		Endpoints:       discovery.EndpointPaths{JWKS: "/jwks", Authorize: "/auth", Token: "/token"},
		ClaimsSupported: []string{},
	})
	if doc.ClaimsSupported == nil {
		t.Errorf("claims_supported = nil, want empty non-nil slice (embedder explicitly opted in with empty list)")
	}
	if len(doc.ClaimsSupported) != 0 {
		t.Errorf("claims_supported = %v, want empty slice", doc.ClaimsSupported)
	}
}

// baseInput returns a minimal [discovery.Input] suitable for the
// metadata-passthrough table tests. Each row layers its own
// [discovery.Metadata] on top of this baseline.
func baseInput() discovery.Input {
	return discovery.Input{
		Issuer:      "https://idp.example.com",
		MountPrefix: "/oidc",
		Endpoints: discovery.EndpointPaths{
			JWKS:      "/jwks",
			Authorize: "/auth",
			Token:     "/token",
			UserInfo:  "/userinfo",
		},
		Features:        discovery.Features{AuthorizeEndpoint: true},
		GrantsSupported: []string{"authorization_code"},
		ScopesSupported: []string{"openid"},
	}
}

// TestBuild_Metadata_NoneSupplied verifies that the four named static
// metadata keys ("service_documentation", "op_policy_uri", "op_tos_uri",
// "ui_locales_supported") and any embedder-supplied passthrough keys
// stay absent from the wire when the embedder did not configure
// [discovery.Metadata]. The omitempty JSON tags carry the load.
//
// Spec: RFC 8414 §2.
func TestBuild_Metadata_NoneSupplied(t *testing.T) {
	t.Parallel()

	doc := discovery.Build(baseInput())
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var wire map[string]any
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{
		"service_documentation", "op_policy_uri",
		"op_tos_uri", "ui_locales_supported",
	} {
		if _, present := wire[key]; present {
			t.Errorf("wire %q should be omitted when no metadata is supplied", key)
		}
	}
}

// TestBuild_ACRValues_OmittedByDefault confirms the JSON wire omits
// acr_values_supported when Input.ACRValuesSupported is nil. OIDC
// Discovery 1.0 §3 lists the field as OPTIONAL; an OP that has not
// enumerated its trust framework MUST NOT advertise an empty array.
//
// Spec: OIDC Discovery 1.0 §3.
func TestBuild_ACRValues_OmittedByDefault(t *testing.T) {
	t.Parallel()

	doc := discovery.Build(baseInput())
	if doc.ACRValuesSupported != nil {
		t.Errorf("ACRValuesSupported = %v, want nil when WithACRValuesSupported is not configured", doc.ACRValuesSupported)
	}
	wire, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal discovery document: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(wire, &raw); err != nil {
		t.Fatalf("unmarshal discovery document: %v", err)
	}
	if _, present := raw["acr_values_supported"]; present {
		t.Errorf("wire JSON contains acr_values_supported key when no values configured: %s", wire)
	}
}

// TestBuild_ACRValues_RoundTrips confirms that a configured slice is
// echoed onto the wire in the supplied order. The order matters
// because an OIDF federation profile may rank acr values from
// strongest to weakest and clients honour the rank when they pick a
// requested acr_values entry.
//
// Spec: OIDC Discovery 1.0 §3 / OIDC Core 1.0 §2.
func TestBuild_ACRValues_RoundTrips(t *testing.T) {
	t.Parallel()

	want := []string{
		"urn:mace:incommon:iap:silver",
		"urn:mace:incommon:iap:bronze",
	}
	in := baseInput()
	in.ACRValuesSupported = want
	doc := discovery.Build(in)
	if len(doc.ACRValuesSupported) != len(want) {
		t.Fatalf("ACRValuesSupported len=%d want %d (%v)", len(doc.ACRValuesSupported), len(want), doc.ACRValuesSupported)
	}
	for i, v := range want {
		if doc.ACRValuesSupported[i] != v {
			t.Errorf("ACRValuesSupported[%d]=%q want %q", i, doc.ACRValuesSupported[i], v)
		}
	}
	// Confirm the wire JSON carries the values in the same order.
	wire, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal discovery document: %v", err)
	}
	var raw struct {
		ACRValuesSupported []string `json:"acr_values_supported"`
	}
	if err := json.Unmarshal(wire, &raw); err != nil {
		t.Fatalf("unmarshal discovery document: %v", err)
	}
	if len(raw.ACRValuesSupported) != len(want) {
		t.Fatalf("wire acr_values_supported len=%d want %d (%s)", len(raw.ACRValuesSupported), len(want), wire)
	}
	for i, v := range want {
		if raw.ACRValuesSupported[i] != v {
			t.Errorf("wire acr_values_supported[%d]=%q want %q", i, raw.ACRValuesSupported[i], v)
		}
	}
}

// TestBuild_Metadata_ServiceDocumentationRoundTrips confirms that the
// embedder's "service_documentation" URL appears in the JSON exactly
// once with the supplied value. RFC 8414 §2 lists the field as
// RECOMMENDED.
func TestBuild_Metadata_ServiceDocumentationRoundTrips(t *testing.T) {
	t.Parallel()

	in := baseInput()
	in.Metadata.ServiceDocumentation = "https://idp.example.com/docs"
	doc := discovery.Build(in)
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var wire map[string]any
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	got, _ := wire["service_documentation"].(string)
	if got != "https://idp.example.com/docs" {
		t.Errorf("service_documentation=%q want %q", got, "https://idp.example.com/docs")
	}
}

// TestBuild_Metadata_UILocalesSupportedAsArray pins
// "ui_locales_supported" to the JSON-array shape RFC 8414 §2 requires.
// A bare string would silently break RP locale negotiation.
func TestBuild_Metadata_UILocalesSupportedAsArray(t *testing.T) {
	t.Parallel()

	in := baseInput()
	in.Metadata.UILocalesSupported = []string{"ja-JP", "en-US"}
	doc := discovery.Build(in)
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var wire map[string]any
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	arr, ok := wire["ui_locales_supported"].([]any)
	if !ok {
		t.Fatalf("ui_locales_supported is not a JSON array: %T (%v)",
			wire["ui_locales_supported"], wire["ui_locales_supported"])
	}
	if len(arr) != 2 || arr[0] != "ja-JP" || arr[1] != "en-US" {
		t.Errorf("ui_locales_supported=%v want [ja-JP en-US]", arr)
	}
}

// TestBuild_Metadata_ExtraPassthrough confirms that an unknown metadata
// key from [discovery.Metadata.Extra] reaches the wire at the top level
// with its supplied JSON value. RFC 8414 §2 explicitly permits unknown
// metadata members.
func TestBuild_Metadata_ExtraPassthrough(t *testing.T) {
	t.Parallel()

	in := baseInput()
	in.Metadata.Extra = map[string]any{
		"x_custom_thing": "frobnicate",
	}
	doc := discovery.Build(in)
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var wire map[string]any
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	got, _ := wire["x_custom_thing"].(string)
	if got != "frobnicate" {
		t.Errorf("x_custom_thing=%q want %q", got, "frobnicate")
	}
}

// TestBuild_Metadata_MarshalDoesNotMutateExtra confirms that repeated
// marshal calls on the same [discovery.Document] do not double-merge or
// drop the embedder's Extra entries. The merge happens in
// [discovery.Document.MarshalJSON] without mutating the source map.
func TestBuild_Metadata_MarshalDoesNotMutateExtra(t *testing.T) {
	t.Parallel()

	in := baseInput()
	in.Metadata.Extra = map[string]any{"x_custom": "v"}
	doc := discovery.Build(in)
	for i := range 3 {
		body, err := json.Marshal(doc)
		if err != nil {
			t.Fatalf("marshal[%d]: %v", i, err)
		}
		var wire map[string]any
		if err := json.Unmarshal(body, &wire); err != nil {
			t.Fatalf("unmarshal[%d]: %v", i, err)
		}
		if got, _ := wire["x_custom"].(string); got != "v" {
			t.Errorf("iteration %d: x_custom=%q want v", i, got)
		}
	}
}

// TestOPControlledFieldNames_CoversCriticalFields pins the deny-list
// returned by [discovery.OPControlledFieldNames] so a refactor that
// drops a critical field from [discovery.Document] also fails this
// test. The list is the contract that
// op.WithDiscoveryMetadata's override-deny check consults.
func TestOPControlledFieldNames_CoversCriticalFields(t *testing.T) {
	t.Parallel()

	got := discovery.OPControlledFieldNames()
	gotSet := make(map[string]struct{}, len(got))
	for _, n := range got {
		gotSet[n] = struct{}{}
	}
	for _, want := range []string{
		"issuer",
		"authorization_endpoint",
		"token_endpoint",
		"jwks_uri",
		"response_types_supported",
		"grant_types_supported",
		"subject_types_supported",
		"id_token_signing_alg_values_supported",
		"scopes_supported",
		"code_challenge_methods_supported",
		"token_endpoint_auth_methods_supported",
	} {
		if _, present := gotSet[want]; !present {
			t.Errorf("OPControlledFieldNames missing %q (got %v)", want, got)
		}
	}
}

// TestBuild_SubjectTypes_PublicOnlyByDefault confirms the discovery
// document advertises only "public" in subject_types_supported when
// the OP is not configured for pairwise.
//
// Spec: OIDC Core 1.0 §8 / OIDC Discovery 1.0 §3.
func TestBuild_SubjectTypes_PublicOnlyByDefault(t *testing.T) {
	t.Parallel()

	doc := discovery.Build(baseInput())
	want := []string{"public"}
	if len(doc.SubjectTypesSupported) != len(want) || doc.SubjectTypesSupported[0] != want[0] {
		t.Errorf("subject_types_supported = %v, want %v", doc.SubjectTypesSupported, want)
	}
}

// TestBuild_SubjectTypes_PairwiseAdvertisedWhenEnabled confirms that
// PairwiseEnabled appends "pairwise" so RPs and OIDC conformance
// tooling discover the OP's per-RP subject capability. Without this
// the OP would issue pairwise subs at /token while telling RPs it
// only supports public, breaking the §8 contract.
//
// Spec: OIDC Core 1.0 §8 / OIDC Discovery 1.0 §3.
func TestBuild_SubjectTypes_PairwiseAdvertisedWhenEnabled(t *testing.T) {
	t.Parallel()

	in := baseInput()
	in.PairwiseEnabled = true
	doc := discovery.Build(in)
	want := []string{"public", "pairwise"}
	if len(doc.SubjectTypesSupported) != len(want) {
		t.Fatalf("subject_types_supported = %v, want %v", doc.SubjectTypesSupported, want)
	}
	for i, w := range want {
		if doc.SubjectTypesSupported[i] != w {
			t.Errorf("subject_types_supported[%d] = %q, want %q", i, doc.SubjectTypesSupported[i], w)
		}
	}
}

// TestBuild_CIBA_OmittedWhenGrantOff confirms the four CIBA Core 1.0
// §3 metadata fields stay absent from the wire when the OP does not
// advertise the CIBA grant. An OP that mounted /bc-authorize without
// configuring the grant would tell RPs the endpoint exists while
// quietly serving 404 — the discovery side mirrors the router gating.
func TestBuild_CIBA_OmittedWhenGrantOff(t *testing.T) {
	t.Parallel()

	doc := discovery.Build(baseInput())
	if doc.BackchannelAuthenticationEndpoint != "" {
		t.Errorf("backchannel_authentication_endpoint=%q want empty when CIBA grant disabled", doc.BackchannelAuthenticationEndpoint)
	}
	if len(doc.BackchannelTokenDeliveryModesSupported) != 0 {
		t.Errorf("backchannel_token_delivery_modes_supported=%v want nil when CIBA grant disabled", doc.BackchannelTokenDeliveryModesSupported)
	}
	if doc.BackchannelUserCodeParameterSupported {
		t.Errorf("backchannel_user_code_parameter_supported=true want false when CIBA grant disabled")
	}
	if len(doc.BackchannelAuthenticationRequestSigningAlgValuesSupported) != 0 {
		t.Errorf("backchannel_authentication_request_signing_alg_values_supported=%v want nil when CIBA grant disabled", doc.BackchannelAuthenticationRequestSigningAlgValuesSupported)
	}
}

// TestBuild_CIBA_EmitsEndpointWhenGrantOn confirms the discovery
// builder advertises /bc-authorize, the poll-only delivery mode list,
// and the user-code-disabled flag when [Features.CIBAGrant] is true.
//
// Spec: OpenID Connect Client-Initiated Backchannel Authentication
// Flow Core 1.0 §3.
func TestBuild_CIBA_EmitsEndpointWhenGrantOn(t *testing.T) {
	t.Parallel()

	in := baseInput()
	in.Endpoints.Backchannel = "/bc-authorize"
	in.Features.CIBAGrant = true
	doc := discovery.Build(in)
	if got, want := doc.BackchannelAuthenticationEndpoint, "https://idp.example.com/oidc/bc-authorize"; got != want {
		t.Errorf("backchannel_authentication_endpoint=%q want %q", got, want)
	}
	if want := []string{"poll"}; len(doc.BackchannelTokenDeliveryModesSupported) != 1 || doc.BackchannelTokenDeliveryModesSupported[0] != want[0] {
		t.Errorf("backchannel_token_delivery_modes_supported=%v want %v", doc.BackchannelTokenDeliveryModesSupported, want)
	}
	if doc.BackchannelUserCodeParameterSupported {
		t.Errorf("backchannel_user_code_parameter_supported=true want false (library does not validate user_code)")
	}
	if len(doc.BackchannelAuthenticationRequestSigningAlgValuesSupported) != 0 {
		t.Errorf("backchannel_authentication_request_signing_alg_values_supported=%v want nil when JAR disabled", doc.BackchannelAuthenticationRequestSigningAlgValuesSupported)
	}
}

// TestBuild_CIBA_EmitsRequestSigningAlgsWhenJAROn confirms the CIBA
// authentication-request signing alg list mirrors the JAR alg posture
// and is emitted only when both features are configured.
//
// Spec: CIBA Core 1.0 §7.1.1 (signed authentication request) +
// RFC 9101 §10.1.
func TestBuild_CIBA_EmitsRequestSigningAlgsWhenJAROn(t *testing.T) {
	t.Parallel()

	in := baseInput()
	in.Endpoints.Backchannel = "/bc-authorize"
	in.Features.CIBAGrant = true
	in.Features.JAR = true
	doc := discovery.Build(in)
	want := []string{"RS256", "PS256", "ES256", "EdDSA"}
	got := doc.BackchannelAuthenticationRequestSigningAlgValuesSupported
	if len(got) != len(want) {
		t.Fatalf("backchannel_authentication_request_signing_alg_values_supported len=%d want %d (%v)", len(got), len(want), got)
	}
	for i, v := range want {
		if got[i] != v {
			t.Errorf("backchannel_authentication_request_signing_alg_values_supported[%d]=%q want %q", i, got[i], v)
		}
	}
}

// TestBuild_ACRValues_DefensiveCopy confirms Build clones the input
// slice so a mutation through the caller's backing array cannot
// silently change the published wire. The discovery layer is the
// last line of defence; the op layer also clones at intake.
func TestBuild_ACRValues_DefensiveCopy(t *testing.T) {
	t.Parallel()

	want := []string{"urn:example:acr:high", "urn:example:acr:low"}
	in := baseInput()
	in.ACRValuesSupported = append([]string(nil), want...)
	doc := discovery.Build(in)
	in.ACRValuesSupported[0] = "MUTATED"
	if doc.ACRValuesSupported[0] != want[0] {
		t.Errorf("ACRValuesSupported[0] = %q, want it to be insulated from caller mutation", doc.ACRValuesSupported[0])
	}
}
