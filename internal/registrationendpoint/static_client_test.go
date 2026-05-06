//nolint:testpackage // exercises unexported validatePolicy through the public ValidateStaticClient seam.
package registrationendpoint

import (
	"errors"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
)

// TestValidateStaticClient_AcceptsValidConfidentialSeed pins the happy
// path: a confidential client with default grant types, code response
// type, and an https redirect_uri flows through the validator
// unchanged.
func TestValidateStaticClient_AcceptsValidConfidentialSeed(t *testing.T) {
	t.Parallel()

	c := store.Client{
		ID:                      "demo-confidential",
		RedirectURIs:            []string{"https://app.example.com/cb"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid"},
		TokenEndpointAuthMethod: "client_secret_basic",
		Source:                  store.ClientSourceStatic,
	}
	if err := ValidateStaticClient(c, StaticClientValidationOptions{
		AllowedGrantTypes:    []string{"authorization_code", "refresh_token"},
		AllowedResponseTypes: []string{"code"},
	}); err != nil {
		t.Fatalf("ValidateStaticClient: %v", err)
	}
}

// TestValidateStaticClient_RejectsHTTPRedirectURI pins the construction-
// time refusal of an http:// redirect_uri on a non-loopback host. The
// rule mirrors validateRedirectURIs which DCR drives.
func TestValidateStaticClient_RejectsHTTPRedirectURI(t *testing.T) {
	t.Parallel()

	c := store.Client{
		ID:                      "demo-spa",
		RedirectURIs:            []string{"http://app.example.com/cb"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		PublicClient:            true,
		Source:                  store.ClientSourceStatic,
	}
	err := ValidateStaticClient(c, StaticClientValidationOptions{
		AllowedGrantTypes:    []string{"authorization_code", "refresh_token"},
		AllowedResponseTypes: []string{"code"},
	})
	if err == nil {
		t.Fatal("expected validation error for plaintext redirect_uri, got nil")
	}
	sve, ok := AsStaticClientValidationError(err)
	if !ok {
		t.Fatalf("expected *StaticClientValidationError, got %T", err)
	}
	if sve.Code != codeInvalidRedirectURI {
		t.Errorf("Code = %q, want %q", sve.Code, codeInvalidRedirectURI)
	}
}

// TestValidateStaticClient_RejectsBackchannelLogoutHTTP pins the rule
// that a plaintext backchannel_logout_uri is refused at construction
// time — the deliverer's TLS-only posture is enforced symmetrically
// across the static-seed path and the /register handler.
func TestValidateStaticClient_RejectsBackchannelLogoutHTTP(t *testing.T) {
	t.Parallel()

	c := store.Client{
		ID:                      "demo-spa",
		RedirectURIs:            []string{"https://app.example.com/cb"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		PublicClient:            true,
		BackchannelLogoutURI:    "http://rp.example.com/logout",
		Source:                  store.ClientSourceStatic,
	}
	err := ValidateStaticClient(c, StaticClientValidationOptions{
		AllowedGrantTypes:    []string{"authorization_code", "refresh_token"},
		AllowedResponseTypes: []string{"code"},
	})
	if err == nil {
		t.Fatal("expected validation error for plaintext backchannel_logout_uri, got nil")
	}
	sve, ok := AsStaticClientValidationError(err)
	if !ok {
		t.Fatalf("expected *StaticClientValidationError, got %T", err)
	}
	if sve.Code != codeInvalidClientMetadata {
		t.Errorf("Code = %q, want %q", sve.Code, codeInvalidClientMetadata)
	}
	if !strings.Contains(sve.Description, "backchannel_logout_uri") {
		t.Errorf("Description = %q, want it to mention backchannel_logout_uri", sve.Description)
	}
}

// TestValidateStaticClient_RejectsUnknownGrantType pins the
// AllowedGrantTypes whitelist behaviour: a grant outside the configured
// set surfaces as invalid_client_metadata so the embedder cannot persist
// a static seed that requests a grant the OP refuses to mount.
func TestValidateStaticClient_RejectsUnknownGrantType(t *testing.T) {
	t.Parallel()

	c := store.Client{
		ID:                      "demo-spa",
		RedirectURIs:            []string{"https://app.example.com/cb"},
		GrantTypes:              []string{"password"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		PublicClient:            true,
		Source:                  store.ClientSourceStatic,
	}
	err := ValidateStaticClient(c, StaticClientValidationOptions{
		AllowedGrantTypes:    []string{"authorization_code", "refresh_token"},
		AllowedResponseTypes: []string{"code"},
	})
	if err == nil {
		t.Fatal("expected validation error for unknown grant_type, got nil")
	}
	sve, ok := AsStaticClientValidationError(err)
	if !ok {
		t.Fatalf("expected *StaticClientValidationError, got %T", err)
	}
	if !strings.Contains(sve.Description, "grant_type") {
		t.Errorf("Description = %q, want it to mention grant_type", sve.Description)
	}
}

// TestValidateStaticClient_RejectsLoopbackTextualWithoutOptIn pins the
// default RFC 8252 §7.3 posture: textual "http://localhost" is refused
// unless the embedder opts in via AllowLocalhostLoopback.
func TestValidateStaticClient_RejectsLoopbackTextualWithoutOptIn(t *testing.T) {
	t.Parallel()

	c := store.Client{
		ID:                      "demo-native",
		RedirectURIs:            []string{"http://localhost:8080/cb"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		PublicClient:            true,
		Source:                  store.ClientSourceStatic,
	}
	err := ValidateStaticClient(c, StaticClientValidationOptions{
		AllowedGrantTypes:      []string{"authorization_code", "refresh_token"},
		AllowedResponseTypes:   []string{"code"},
		AllowLocalhostLoopback: false,
	})
	if err == nil {
		t.Fatal("expected validation error for http://localhost without opt-in, got nil")
	}
}

// TestValidateStaticClient_AcceptsLoopbackTextualWithOptIn pins the
// opt-in path: textual "http://localhost" flows through unchanged when
// AllowLocalhostLoopback is true.
func TestValidateStaticClient_AcceptsLoopbackTextualWithOptIn(t *testing.T) {
	t.Parallel()

	c := store.Client{
		ID:                      "demo-native",
		RedirectURIs:            []string{"http://localhost:8080/cb"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		PublicClient:            true,
		Source:                  store.ClientSourceStatic,
	}
	if err := ValidateStaticClient(c, StaticClientValidationOptions{
		AllowedGrantTypes:      []string{"authorization_code", "refresh_token"},
		AllowedResponseTypes:   []string{"code"},
		AllowLocalhostLoopback: true,
	}); err != nil {
		t.Fatalf("ValidateStaticClient with opt-in: %v", err)
	}
}

// TestValidateStaticClient_RejectsPairwiseWithoutOption pins the rule
// that subject_type=pairwise requires the embedder to opt in via
// PairwiseEnabled. Without the flag the validator refuses the seed so
// the OP never mints subjects in a strategy that was never wired.
func TestValidateStaticClient_RejectsPairwiseWithoutOption(t *testing.T) {
	t.Parallel()

	c := store.Client{
		ID:                      "demo-spa",
		RedirectURIs:            []string{"https://app.example.com/cb"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		PublicClient:            true,
		SubjectType:             "pairwise",
		Source:                  store.ClientSourceStatic,
	}
	err := ValidateStaticClient(c, StaticClientValidationOptions{
		AllowedGrantTypes:    []string{"authorization_code", "refresh_token"},
		AllowedResponseTypes: []string{"code"},
		PairwiseEnabled:      false,
	})
	if err == nil {
		t.Fatal("expected validation error for pairwise without opt-in, got nil")
	}
	sve, ok := AsStaticClientValidationError(err)
	if !ok {
		t.Fatalf("expected *StaticClientValidationError, got %T", err)
	}
	if !strings.Contains(sve.Description, "pairwise") {
		t.Errorf("Description = %q, want it to mention pairwise", sve.Description)
	}
}

// TestValidateStaticClient_AcceptsCIBAClientWithoutRedirectURIs pins the
// CIBA-only carve-out: a static seed whose grants are exclusively
// non-redirect (CIBA, refresh_token) is admitted with an empty
// RedirectURIs slice because the client never visits /authorize. DCR
// blocks the same shape via Deps.AllowedGrantTypes; the static path
// trusts the embedder's choice and skips the redirect_uris-required
// gate.
func TestValidateStaticClient_AcceptsCIBAClientWithoutRedirectURIs(t *testing.T) {
	t.Parallel()

	//nolint:gosec // G101: test fixture; "private_key_jwt" is an OIDC auth-method label, not a credential.
	c := store.Client{
		ID:                      "demo-ciba",
		GrantTypes:              []string{"urn:openid:params:grant-type:ciba", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "private_key_jwt",
		Source:                  store.ClientSourceStatic,
	}
	if err := ValidateStaticClient(c, StaticClientValidationOptions{
		AllowedGrantTypes:    []string{"authorization_code", "refresh_token", "urn:openid:params:grant-type:ciba"},
		AllowedResponseTypes: []string{"code"},
	}); err != nil {
		t.Fatalf("ValidateStaticClient with CIBA-only grants: %v", err)
	}
}

// TestValidateStaticClient_RejectsAuthorizationCodeWithoutRedirectURIs
// pins the converse rule: when the seed's grants include
// authorization_code (or implicit), redirect_uris MUST be supplied.
// The DCR validator's redirect_uris-required gate fires here too so
// the structural contract stays uniform across the static and DCR
// paths.
func TestValidateStaticClient_RejectsAuthorizationCodeWithoutRedirectURIs(t *testing.T) {
	t.Parallel()

	c := store.Client{
		ID:                      "demo-spa",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		PublicClient:            true,
		Source:                  store.ClientSourceStatic,
	}
	err := ValidateStaticClient(c, StaticClientValidationOptions{
		AllowedGrantTypes:    []string{"authorization_code", "refresh_token"},
		AllowedResponseTypes: []string{"code"},
	})
	if err == nil {
		t.Fatal("expected validation error for authorization_code without redirect_uris, got nil")
	}
	if !strings.Contains(err.Error(), "redirect_uris") {
		t.Errorf("err = %v, want it to mention redirect_uris", err)
	}
}

// TestStaticClientValidationError_ImplementsError pins that the typed
// error satisfies the error interface so callers can branch via
// errors.As without an explicit type assertion.
func TestStaticClientValidationError_ImplementsError(t *testing.T) {
	t.Parallel()

	var err error = &StaticClientValidationError{
		Code:        "invalid_client_metadata",
		Description: "test",
	}
	if err.Error() == "" {
		t.Fatal("Error() returned empty string")
	}
	var sve *StaticClientValidationError
	if !errors.As(err, &sve) {
		t.Fatal("errors.As did not match *StaticClientValidationError")
	}
	if sve.Code != "invalid_client_metadata" {
		t.Errorf("Code = %q, want invalid_client_metadata", sve.Code)
	}
}
