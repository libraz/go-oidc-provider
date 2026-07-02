package op

// The tests in this file live in package op (not op_test) so they
// can call the unexported [ClientSeed.seed] method and pin the
// invariants the public surface guarantees. Embedders never invoke
// seed() directly; the library calls it from
// op.WithStaticClients (landing in a follow-up wave).

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
)

// TestPublicClient_SeedFields pins the public-client invariants:
// PublicClient: true, auth method "none", Source ClientSourceStatic,
// and identity-preserving slices for redirects / scopes / grants /
// response types.
func TestPublicClient_SeedFields(t *testing.T) {
	t.Parallel()

	c := PublicClient{
		ID:           "demo-spa",
		RedirectURIs: []string{"https://app.example.com/cb"},
		Scopes:       []string{"openid", "profile"},
	}
	got, err := c.seed()
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if got.ID != "demo-spa" {
		t.Errorf("ID = %q, want %q", got.ID, "demo-spa")
	}
	if !got.PublicClient {
		t.Errorf("PublicClient = false, want true")
	}
	if got.Source != store.ClientSourceStatic {
		t.Errorf("Source = %q, want %q", got.Source, store.ClientSourceStatic)
	}
	if got.TokenEndpointAuthMethod != AuthNone.String() {
		t.Errorf("TokenEndpointAuthMethod = %q, want %q",
			got.TokenEndpointAuthMethod, AuthNone.String())
	}
	if got.SecretHash != "" {
		t.Errorf("SecretHash must be empty for a public client, got %q", got.SecretHash)
	}
	if !equalStrings(got.RedirectURIs, []string{"https://app.example.com/cb"}) {
		t.Errorf("RedirectURIs = %v", got.RedirectURIs)
	}
	if !equalStrings(got.Scopes, []string{"openid", "profile"}) {
		t.Errorf("Scopes = %v", got.Scopes)
	}
	if !equalStrings(got.GrantTypes, []string{"authorization_code", "refresh_token"}) {
		t.Errorf("GrantTypes default = %v", got.GrantTypes)
	}
	if !equalStrings(got.ResponseTypes, []string{"code"}) {
		t.Errorf("ResponseTypes default = %v", got.ResponseTypes)
	}
}

// TestPublicClient_SeedRespectsExplicitGrants asserts a non-empty
// GrantTypes / ResponseTypes input replaces the default rather than
// being merged.
func TestPublicClient_SeedRespectsExplicitGrants(t *testing.T) {
	t.Parallel()

	c := PublicClient{
		ID:            "demo-spa",
		RedirectURIs:  []string{"https://app.example.com/cb"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
	}
	got, err := c.seed()
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if !equalStrings(got.GrantTypes, []string{"authorization_code"}) {
		t.Errorf("GrantTypes override = %v", got.GrantTypes)
	}
}

// TestConfidentialClient_SeedHashesSecret pins the central
// invariant: the plaintext Secret leaves only as a hash, the
// resolved AuthMethod is written to TokenEndpointAuthMethod, and
// Source is ClientSourceStatic.
func TestConfidentialClient_SeedHashesSecret(t *testing.T) {
	t.Parallel()

	const plaintext = "demo-confidential-secret"
	c := ConfidentialClient{
		ID:           "demo-confidential",
		Secret:       plaintext,
		RedirectURIs: []string{"https://app.example.com/cb"},
		Scopes:       []string{"openid"},
	}
	got, err := c.seed()
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if got.Source != store.ClientSourceStatic {
		t.Errorf("Source = %q, want %q", got.Source, store.ClientSourceStatic)
	}
	if got.PublicClient {
		t.Errorf("PublicClient = true, want false for a confidential client")
	}
	if got.TokenEndpointAuthMethod != AuthClientSecretBasic.String() {
		t.Errorf("default AuthMethod = %q, want %q",
			got.TokenEndpointAuthMethod, AuthClientSecretBasic.String())
	}
	if got.SecretHash == "" {
		t.Fatalf("SecretHash must not be empty")
	}
	if got.SecretHash == plaintext {
		t.Fatalf("SecretHash must not equal plaintext: %q", got.SecretHash)
	}
	if strings.Contains(got.SecretHash, plaintext) {
		t.Fatalf("SecretHash must not embed the plaintext: %q", got.SecretHash)
	}
	// Argon2id encoding starts with $argon2id$. Pinning the prefix
	// guards against a future change that swaps the algorithm
	// without updating the secret-verification adapter.
	if !strings.HasPrefix(got.SecretHash, "$argon2id$") {
		t.Errorf("SecretHash format unexpected: %q", got.SecretHash)
	}
}

// TestConfidentialClient_SeedHonoursAuthMethod asserts an explicit
// AuthMethod overrides the default and is written verbatim to the
// store record.
func TestConfidentialClient_SeedHonoursAuthMethod(t *testing.T) {
	t.Parallel()

	c := ConfidentialClient{
		ID:           "demo-confidential-post",
		Secret:       "demo-confidential-secret",
		AuthMethod:   AuthClientSecretPost,
		RedirectURIs: []string{"https://app.example.com/cb"},
	}
	got, err := c.seed()
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if got.TokenEndpointAuthMethod != AuthClientSecretPost.String() {
		t.Errorf("explicit AuthMethod lost: got %q want %q",
			got.TokenEndpointAuthMethod, AuthClientSecretPost.String())
	}
}

// TestConfidentialClient_SeedCopiesAuthSigningAlg pins that
// TokenEndpointAuthSigningAlg round-trips through seed() onto the
// store record. The field is only meaningful when the client
// authenticates with private_key_jwt, but ConfidentialClient carries
// it so callers can share seed construction code with
// [PrivateKeyJWTClient]; a seed() that dropped the field would
// silently widen the OP's accepted client_assertion "alg" set for
// this client.
func TestConfidentialClient_SeedCopiesAuthSigningAlg(t *testing.T) {
	t.Parallel()

	c := ConfidentialClient{
		ID:                          "demo-conf-alg",
		Secret:                      "s3cret-please-rotate",
		RedirectURIs:                []string{"https://app.example.com/cb"},
		Scopes:                      []string{"openid"},
		TokenEndpointAuthSigningAlg: "ES256",
	}
	got, err := c.seed()
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if got.TokenEndpointAuthSigningAlg != "ES256" {
		t.Errorf("TokenEndpointAuthSigningAlg = %q, want %q",
			got.TokenEndpointAuthSigningAlg, "ES256")
	}
}

// TestPrivateKeyJWTClient_SeedFields pins the private_key_jwt
// invariants: TokenEndpointAuthMethod set to private_key_jwt, JWKS
// embedded inline byte-for-byte, Source ClientSourceStatic, and no
// PublicClient/SecretHash fields populated.
func TestPrivateKeyJWTClient_SeedFields(t *testing.T) {
	t.Parallel()

	jwks := []byte(`{"keys":[{"kty":"EC","crv":"P-256","kid":"k1","x":"abc","y":"def"}]}`)
	c := PrivateKeyJWTClient{
		ID:           "demo-fapi",
		JWKS:         jwks,
		RedirectURIs: []string{"https://app.example.com/cb"},
		Scopes:       []string{"openid"},
	}
	got, err := c.seed()
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if got.TokenEndpointAuthMethod != AuthPrivateKeyJWT.String() {
		t.Errorf("TokenEndpointAuthMethod = %q, want %q",
			got.TokenEndpointAuthMethod, AuthPrivateKeyJWT.String())
	}
	if !bytes.Equal(got.JWKs, jwks) {
		t.Errorf("JWKs = %s, want %s", string(got.JWKs), string(jwks))
	}
	if got.Source != store.ClientSourceStatic {
		t.Errorf("Source = %q, want %q", got.Source, store.ClientSourceStatic)
	}
	if got.PublicClient {
		t.Errorf("PublicClient = true, want false for a private_key_jwt client")
	}
	if got.SecretHash != "" {
		t.Errorf("SecretHash must be empty for a private_key_jwt client, got %q", got.SecretHash)
	}
}

// TestPrivateKeyJWTClient_SeedDefensiveCopy asserts the JWKS bytes
// stored on the [store.Client] are a copy of the input slice: a
// later mutation of the caller's buffer must not race with the
// stored record.
func TestPrivateKeyJWTClient_SeedDefensiveCopy(t *testing.T) {
	t.Parallel()

	original := []byte(`{"keys":[{"kty":"EC","kid":"k1"}]}`)
	c := PrivateKeyJWTClient{
		ID:   "demo-fapi",
		JWKS: original,
	}
	got, err := c.seed()
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	original[0] = 'X'
	if got.JWKs[0] != '{' {
		t.Errorf("seed() did not defensively copy JWKS: got %q want '{'", got.JWKs[0])
	}
}

// equalStrings reports whether a and b contain the same elements in
// the same order. Wraps [slices.Equal] so callers in this file read
// at the same level of abstraction as the rest of the assertions.
func equalStrings(a, b []string) bool {
	return slices.Equal(a, b)
}

// TestPublicClient_SeedCopiesMetadataFields confirms the post-logout,
// back-channel logout, and Dynamic Client Registration metadata
// fields round-trip through seed() onto [store.Client] verbatim. The
// test backstops the I1 expansion: dropping a field from the seed
// type or forgetting to copy it through breaks the chain that
// /end_session and the back-channel coordinator rely on.
func TestPublicClient_SeedCopiesMetadataFields(t *testing.T) {
	t.Parallel()

	c := PublicClient{
		ID:                               "demo-spa",
		RedirectURIs:                     []string{"https://app.example.com/cb"},
		Scopes:                           []string{"openid"},
		PostLogoutRedirectURIs:           []string{"https://app.example.com/post-logout"},
		BackchannelLogoutURI:             "https://app.example.com/bcl",
		BackchannelLogoutSessionRequired: true,
		ApplicationType:                  "web",
		SubjectType:                      "public",
	}
	got, err := c.seed()
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if !equalStrings(got.PostLogoutRedirectURIs, []string{"https://app.example.com/post-logout"}) {
		t.Errorf("PostLogoutRedirectURIs = %v", got.PostLogoutRedirectURIs)
	}
	if got.BackchannelLogoutURI != "https://app.example.com/bcl" {
		t.Errorf("BackchannelLogoutURI = %q", got.BackchannelLogoutURI)
	}
	if !got.BackchannelLogoutSessionRequired {
		t.Errorf("BackchannelLogoutSessionRequired = false, want true")
	}
	if got.ApplicationType != "web" {
		t.Errorf("ApplicationType = %q", got.ApplicationType)
	}
	if got.SubjectType != "public" {
		t.Errorf("SubjectType = %q", got.SubjectType)
	}

	// Defensive-copy invariant: mutating the caller's slice MUST NOT
	// rewrite the seeded record (mirrors the existing RedirectURIs
	// behaviour).
	c.PostLogoutRedirectURIs[0] = "https://attacker.example/cb"
	if got.PostLogoutRedirectURIs[0] != "https://app.example.com/post-logout" {
		t.Errorf("seed() did not defensively copy PostLogoutRedirectURIs: %q", got.PostLogoutRedirectURIs[0])
	}
}

// TestConfidentialClient_SeedCopiesMetadataFields mirrors the
// PublicClient test for the confidential variant.
func TestConfidentialClient_SeedCopiesMetadataFields(t *testing.T) {
	t.Parallel()

	c := ConfidentialClient{
		ID:                               "demo-conf",
		Secret:                           "s3cret-please-rotate",
		RedirectURIs:                     []string{"https://app.example.com/cb"},
		Scopes:                           []string{"openid"},
		PostLogoutRedirectURIs:           []string{"https://app.example.com/post-logout"},
		BackchannelLogoutURI:             "https://app.example.com/bcl",
		BackchannelLogoutSessionRequired: true,
		ApplicationType:                  "web",
		SubjectType:                      "public",
	}
	got, err := c.seed()
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if !equalStrings(got.PostLogoutRedirectURIs, []string{"https://app.example.com/post-logout"}) {
		t.Errorf("PostLogoutRedirectURIs = %v", got.PostLogoutRedirectURIs)
	}
	if got.BackchannelLogoutURI != "https://app.example.com/bcl" {
		t.Errorf("BackchannelLogoutURI = %q", got.BackchannelLogoutURI)
	}
	if !got.BackchannelLogoutSessionRequired {
		t.Errorf("BackchannelLogoutSessionRequired = false, want true")
	}
	if got.ApplicationType != "web" {
		t.Errorf("ApplicationType = %q", got.ApplicationType)
	}
	if got.SubjectType != "public" {
		t.Errorf("SubjectType = %q", got.SubjectType)
	}
}

// TestPrivateKeyJWTClient_SeedCopiesMetadataFields mirrors the
// PublicClient test for the private_key_jwt variant.
func TestPrivateKeyJWTClient_SeedCopiesMetadataFields(t *testing.T) {
	t.Parallel()

	c := PrivateKeyJWTClient{
		ID:                               "demo-fapi",
		JWKS:                             []byte(`{"keys":[]}`),
		RedirectURIs:                     []string{"https://app.example.com/cb"},
		Scopes:                           []string{"openid"},
		PostLogoutRedirectURIs:           []string{"https://app.example.com/post-logout"},
		BackchannelLogoutURI:             "https://app.example.com/bcl",
		BackchannelLogoutSessionRequired: true,
		ApplicationType:                  "web",
		SubjectType:                      "public",
	}
	got, err := c.seed()
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if !equalStrings(got.PostLogoutRedirectURIs, []string{"https://app.example.com/post-logout"}) {
		t.Errorf("PostLogoutRedirectURIs = %v", got.PostLogoutRedirectURIs)
	}
	if got.BackchannelLogoutURI != "https://app.example.com/bcl" {
		t.Errorf("BackchannelLogoutURI = %q", got.BackchannelLogoutURI)
	}
	if !got.BackchannelLogoutSessionRequired {
		t.Errorf("BackchannelLogoutSessionRequired = false, want true")
	}
	if got.ApplicationType != "web" {
		t.Errorf("ApplicationType = %q", got.ApplicationType)
	}
	if got.SubjectType != "public" {
		t.Errorf("SubjectType = %q", got.SubjectType)
	}
}

// _ static interface assertion: the three builders satisfy the
// ClientSeed interface. A future refactor that drops a method from
// any of them fails this line at compile time.
var (
	_ ClientSeed = PublicClient{}
	_ ClientSeed = ConfidentialClient{}
	_ ClientSeed = PrivateKeyJWTClient{}
)
