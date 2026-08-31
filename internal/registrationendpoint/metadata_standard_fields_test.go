package registrationendpoint_test

import (
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

// fullStandardMetadata returns a registration document carrying the
// OpenID Connect Dynamic Client Registration 1.0 §2 metadata set — the
// shape a general-purpose RP library emits when every knob it models is
// configured.
//
// Two members of §2 are deliberately absent. sector_identifier_uri makes
// the OP fetch the document before it answers, which would put a network
// call in this test's path, and it is only meaningful for a pairwise
// registration this OP is not configured for; jwks is mutually exclusive
// with the jwks_uri below.
//
//nolint:gosec // G101: "client_secret_basic" is the OIDC DCR auth-method name, not a secret.
func fullStandardMetadata() map[string]any {
	return map[string]any{
		"redirect_uris":                              []string{"https://rp.test.invalid/callback"},
		"response_types":                             []string{"code"},
		"grant_types":                                []string{"authorization_code", "refresh_token"},
		"application_type":                           "web",
		"contacts":                                   []string{"ops@rp.test.invalid"},
		"client_name":                                "Standard RP",
		"logo_uri":                                   "https://rp.test.invalid/logo.png",
		"client_uri":                                 "https://rp.test.invalid/",
		"policy_uri":                                 "https://rp.test.invalid/privacy",
		"tos_uri":                                    "https://rp.test.invalid/terms",
		"jwks_uri":                                   "https://rp.test.invalid/jwks.json",
		"subject_type":                               "public",
		"id_token_signed_response_alg":               "ES256",
		"id_token_encrypted_response_alg":            "RSA-OAEP-256",
		"id_token_encrypted_response_enc":            "A256GCM",
		"userinfo_signed_response_alg":               "ES256",
		"userinfo_encrypted_response_alg":            "RSA-OAEP-256",
		"userinfo_encrypted_response_enc":            "A128GCM",
		"request_object_signing_alg":                 "ES256",
		"request_object_encryption_alg":              "ECDH-ES",
		"request_object_encryption_enc":              "A256GCM",
		"token_endpoint_auth_method":                 "client_secret_basic",
		"token_endpoint_auth_signing_alg":            "ES256",
		"default_max_age":                            3600,
		"require_auth_time":                          true,
		"default_acr_values":                         []string{"urn:example:acr:silver"},
		"initiate_login_uri":                         "https://rp.test.invalid/login",
		"request_uris":                               []string{"https://rp.test.invalid/request.jwt"},
		"scope":                                      "openid",
		"post_logout_redirect_uris":                  []string{"https://rp.test.invalid/logout"},
		"backchannel_logout_uri":                     "https://rp.test.invalid/backchannel-logout",
		"software_id":                                "standard-rp",
		"software_version":                           "1.4.2",
		"authorization_signed_response_alg":          "ES256",
		"introspection_signed_response_alg":          "ES256",
		"dpop_bound_access_tokens":                   false,
		"tls_client_certificate_bound_access_tokens": false,
		"require_pushed_authorization_requests":      false,
	}
}

// TestRegister_AcceptsFullStandardMetadataSet pins that an RP sending
// the standard metadata set can onboard. Refusing a member the OP does
// not model would lock out every client library that fills in the
// specification's fields rather than this OP's subset, and RFC 7591 §2
// requires the server to ignore metadata it does not understand.
func TestRegister_AcceptsFullStandardMetadataSet(t *testing.T) {
	t.Parallel()

	f := newFixture(t, op.RegistrationOption{})
	_, iat := f.issueIAT(t, op.InitialAccessTokenSpec{})

	resp := f.post(t, fullStandardMetadata(), iat)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 201 body=%s", resp.StatusCode, raw)
	}
	got := decodeBody(t, resp)
	clientID, _ := got["client_id"].(string)
	if clientID == "" {
		t.Fatalf("registration response carries no client_id: %v", got)
	}
	stored, err := f.prov.Store.GetClient(context.Background(), clientID)
	if err != nil {
		t.Fatalf("GetClient(%q): %v", clientID, err)
	}
	if stored.ClientName != "Standard RP" {
		t.Errorf("ClientName=%q, want the submitted value", stored.ClientName)
	}
}

func TestIntrospectionSignedResponseAlg_RoundTripsAndNormalizesNone(t *testing.T) {
	t.Parallel()

	f := newFixture(t, op.RegistrationOption{})
	body := minimalMetadata()
	body["introspection_signed_response_alg"] = "ES256"
	created := f.register(t, body)

	read := f.manage(t, http.MethodGet, created.registrationClientURI, created.registrationAccessToken, nil)
	if read.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(read.Body)
		read.Body.Close()
		t.Fatalf("GET: status=%d want 200 body=%s", read.StatusCode, raw)
	}
	readBody := decodeBody(t, read)
	read.Body.Close()
	if got := readBody["introspection_signed_response_alg"]; got != "ES256" {
		t.Fatalf("GET introspection_signed_response_alg=%v want ES256", got)
	}

	updated := f.manage(t, http.MethodPut, created.registrationClientURI, created.registrationAccessToken, map[string]any{
		"redirect_uris":                     []string{"https://rp.test.invalid/callback"},
		"introspection_signed_response_alg": "none",
	})
	if updated.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(updated.Body)
		updated.Body.Close()
		t.Fatalf("PUT none: status=%d want 200 body=%s", updated.StatusCode, raw)
	}
	updatedBody := decodeBody(t, updated)
	updated.Body.Close()
	if _, ok := updatedBody["introspection_signed_response_alg"]; ok {
		t.Fatalf("PUT none must normalize to JSON and omit field: %v", updatedBody)
	}
	client, err := f.prov.Store.Clients().GetClient(context.Background(), created.clientID)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if client.IntrospectionSignedResponseAlg != "" {
		t.Fatalf("stored IntrospectionSignedResponseAlg=%q want empty", client.IntrospectionSignedResponseAlg)
	}
}

func TestIntrospectionSignedResponseAlg_OmittedPUTClearsExistingMetadata(t *testing.T) {
	t.Parallel()

	f := newFixture(t, op.RegistrationOption{})
	created := f.register(t, map[string]any{
		"redirect_uris":                     []string{"https://rp.test.invalid/callback"},
		"introspection_signed_response_alg": "ES256",
	})

	updated := f.manage(t, http.MethodPut, created.registrationClientURI, created.registrationAccessToken, map[string]any{
		"redirect_uris": []string{"https://rp.test.invalid/callback"},
	})
	if updated.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(updated.Body)
		updated.Body.Close()
		t.Fatalf("PUT omitted signed alg: status=%d want 200 body=%s", updated.StatusCode, raw)
	}
	updatedBody := decodeBody(t, updated)
	updated.Body.Close()
	if _, ok := updatedBody["introspection_signed_response_alg"]; ok {
		t.Fatalf("PUT omission must clear introspection_signed_response_alg in response: %v", updatedBody)
	}

	client, err := f.prov.Store.Clients().GetClient(context.Background(), created.clientID)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if client.IntrospectionSignedResponseAlg != "" {
		t.Fatalf("stored IntrospectionSignedResponseAlg=%q want empty after omitted PUT", client.IntrospectionSignedResponseAlg)
	}
}

// TestRegister_IgnoresUnmodelledMembers pins the RFC 7591 §2 rule
// directly: a member the OP has no meaning for is dropped, not
// answered with an error and not echoed back as though it had been
// accepted.
func TestRegister_IgnoresUnmodelledMembers(t *testing.T) {
	t.Parallel()

	f := newFixture(t, op.RegistrationOption{})
	_, iat := f.issueIAT(t, op.InitialAccessTokenSpec{})

	body := minimalMetadata()
	body["frontchannel_logout_uri"] = "https://rp.test.invalid/frontchannel-logout"
	body["vendor_specific_setting"] = "whatever the RP's own console writes here"

	resp := f.post(t, body, iat)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 201 body=%s", resp.StatusCode, raw)
	}
	got := decodeBody(t, resp)
	for _, member := range []string{"frontchannel_logout_uri", "vendor_specific_setting"} {
		if _, ok := got[member]; ok {
			t.Errorf("response echoes %q, which the OP neither validates nor stores", member)
		}
	}
}

// TestRegister_RefusesValuesTheOPWillNotHonour covers the other half of
// the tolerance rule. A member the OP parses but does not store still
// carries a meaning, and answering "accepted" to a request the OP will
// not act on leaves the client believing in a protection or a response
// format it will never see.
func TestRegister_RefusesValuesTheOPWillNotHonour(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		member string
		value  any
	}{
		{
			name:   "userinfo response signed with an algorithm the OP does not hold",
			member: "userinfo_signed_response_alg",
			value:  "RS256",
		},
		{
			name:   "introspection response signed with an algorithm the OP does not hold",
			member: "introspection_signed_response_alg",
			value:  "HS256",
		},
		{
			name:   "per-client DPoP enforcement the OP does not apply",
			member: "dpop_bound_access_tokens",
			value:  true,
		},
		{
			name:   "per-client certificate binding the OP does not apply",
			member: "tls_client_certificate_bound_access_tokens",
			value:  true,
		},
		{
			name:   "per-client pushed-authorization enforcement the OP does not apply",
			member: "require_pushed_authorization_requests",
			value:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t, op.RegistrationOption{})
			_, iat := f.issueIAT(t, op.InitialAccessTokenSpec{})

			body := minimalMetadata()
			body[tc.member] = tc.value
			resp := f.post(t, body, iat)
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusBadRequest {
				raw, _ := io.ReadAll(resp.Body)
				t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, raw)
			}
			got := decodeBody(t, resp)
			if got["error"] != "invalid_client_metadata" {
				t.Errorf("error=%v want invalid_client_metadata", got["error"])
			}
		})
	}
}

// TestManage_Update_AppliesTheSameToleranceRule pins that the update
// path answers unmodelled and unhonourable members the same way the
// registration path does. The two share a parser, and a client that
// onboarded with a metadata set must be able to resubmit it.
func TestManage_Update_AppliesTheSameToleranceRule(t *testing.T) {
	t.Parallel()

	f := newFixture(t, op.RegistrationOption{})
	created := f.register(t, nil)

	accepted := fullStandardMetadata()
	resp := f.manage(t, http.MethodPut, created.registrationClientURI, created.registrationAccessToken, accepted)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("standard metadata set: status=%d want 200 body=%s", resp.StatusCode, raw)
	}
	// A successful update rotates the registration access token and
	// revokes the previous one, so the second call has to present the
	// token this response carried. Reusing the original would answer
	// 401 before the metadata is ever parsed, and the assertion below
	// would pass or fail for a reason that has nothing to do with the
	// signing alg.
	rotated, _ := decodeBody(t, resp)["registration_access_token"].(string)
	if rotated == "" {
		t.Fatal("update response carried no rotated registration_access_token")
	}

	refused := fullStandardMetadata()
	refused["userinfo_signed_response_alg"] = "RS256"
	rejected := f.manage(t, http.MethodPut, created.registrationClientURI, rotated, refused)
	defer rejected.Body.Close()
	if rejected.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(rejected.Body)
		t.Fatalf("unsupported signing alg: status=%d want 400 body=%s", rejected.StatusCode, raw)
	}
	if got := decodeBody(t, rejected); got["error"] != "invalid_client_metadata" {
		t.Errorf("error=%v want invalid_client_metadata", got["error"])
	}
}

// TestManage_Update_RefusesPerClientCertificateBinding pins the update
// half of the enforcement-flag rule for
// tls_client_certificate_bound_access_tokens. The OP binds an access
// token to whatever certificate the request presented; it holds no
// per-client switch that could make the binding mandatory. Accepting the
// member on a PUT would answer 200 to a request for a protection that
// does not exist, and the client would go on believing every token it
// receives is certificate-bound.
func TestManage_Update_RefusesPerClientCertificateBinding(t *testing.T) {
	t.Parallel()

	f := newFixture(t, op.RegistrationOption{})
	created := f.register(t, nil)

	refused := minimalMetadata()
	refused["tls_client_certificate_bound_access_tokens"] = true
	resp := f.manage(t, http.MethodPut, created.registrationClientURI, created.registrationAccessToken, refused)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, raw)
	}
	if got := decodeBody(t, resp); got["error"] != "invalid_client_metadata" {
		t.Errorf("error=%v want invalid_client_metadata", got["error"])
	}

	// The omitted form still onboards: the member is refused only when it
	// asks for the enforcement, never as an unknown member.
	accepted := f.manage(t, http.MethodPut, created.registrationClientURI, created.registrationAccessToken, minimalMetadata())
	defer accepted.Body.Close()
	if accepted.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(accepted.Body)
		t.Fatalf("omitted member: status=%d want 200 body=%s", accepted.StatusCode, raw)
	}
}
