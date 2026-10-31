//nolint:testpackage // exercises unexported validationError codes through ValidateClientMetadataDocument.
package registrationendpoint

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"os"
	"slices"
	"testing"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
)

const testDocumentURL = "https://app.example.com/oauth/client-metadata.json"

// documentJSON marshals a metadata document whose client_id is
// testDocumentURL, with a loopback redirect_uri unless fields override it.
func documentJSON(t *testing.T, fields map[string]any) []byte {
	t.Helper()
	doc := map[string]any{
		"client_id":     testDocumentURL,
		"redirect_uris": []string{"http://127.0.0.1:3000/callback"},
	}
	for k, v := range fields {
		if v == nil {
			delete(doc, k)
			continue
		}
		doc[k] = v
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

func ecJWKS(t *testing.T, private bool) json.RawMessage {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	var key any = priv.Public()
	if private {
		key = priv
	}
	raw, err := json.Marshal(josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{{Key: key, KeyID: "k1", Algorithm: "ES256", Use: "sig"}}})
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return raw
}

// requireDocumentRejected asserts the document fails validation with the
// supplied wire code.
func requireDocumentRejected(t *testing.T, raw []byte, opts MetadataDocumentOptions, wantCode string) {
	t.Helper()
	c, err := ValidateClientMetadataDocument(raw, testDocumentURL, opts)
	if err == nil {
		t.Fatalf("ValidateClientMetadataDocument accepted %s: %+v", raw, c)
	}
	ve, ok := asValidationError(err)
	if !ok {
		t.Fatalf("error %T %v is not a validationError", err, err)
	}
	if ve.code != wantCode {
		t.Fatalf("code = %q, want %q (%v)", ve.code, wantCode, err)
	}
}

func TestValidateClientMetadataDocument_MCPExampleUnderZeroOptions(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("testdata/mcp-client-metadata.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	c, err := ValidateClientMetadataDocument(raw, testDocumentURL, MetadataDocumentOptions{})
	if err != nil {
		t.Fatalf("ValidateClientMetadataDocument: %v", err)
	}
	if c.ID != testDocumentURL {
		t.Errorf("ID = %q, want %q", c.ID, testDocumentURL)
	}
	if !c.PublicClient || c.TokenEndpointAuthMethod != "none" {
		t.Errorf("auth = %q public=%v, want none/public", c.TokenEndpointAuthMethod, c.PublicClient)
	}
	if c.ApplicationType != applicationTypeNative {
		t.Errorf("application_type = %q, want native for loopback-only redirect_uris", c.ApplicationType)
	}
	if want := []string{"http://127.0.0.1:3000/callback", "http://localhost:3000/callback"}; !slices.Equal(c.RedirectURIs, want) {
		t.Errorf("redirect_uris = %v, want %v", c.RedirectURIs, want)
	}
	if !slices.Equal(c.GrantTypes, []string{"authorization_code"}) || !slices.Equal(c.ResponseTypes, []string{"code"}) {
		t.Errorf("grant/response = %v/%v", c.GrantTypes, c.ResponseTypes)
	}
	if c.ClientName != "Example MCP Client" || c.Source != "" || c.SecretHash != "" {
		t.Errorf("unexpected client fields: name=%q source=%q secret=%q", c.ClientName, c.Source, c.SecretHash)
	}
}

func TestValidateClientMetadataDocument_RootMustBeObject(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"", "   ", "[]", `[{"client_id":"` + testDocumentURL + `"}]`, "42", "null", `"x"`} {
		requireDocumentRejected(t, []byte(raw), MetadataDocumentOptions{}, codeInvalidClientMetadata)
	}
}

func TestValidateClientMetadataDocument_EmptyObjectRejected(t *testing.T) {
	t.Parallel()
	requireDocumentRejected(t, []byte("{}"), MetadataDocumentOptions{}, codeInvalidClientMetadata)
}

func TestValidateClientMetadataDocument_ClientIDMustMatchExactly(t *testing.T) {
	t.Parallel()
	for _, id := range []string{
		testDocumentURL + "/",
		"https://APP.example.com/oauth/client-metadata.json",
		"https://app.example.com/oauth/client-metadata.json?x=1",
		"",
	} {
		requireDocumentRejected(t, documentJSON(t, map[string]any{"client_id": id}), MetadataDocumentOptions{}, codeInvalidClientMetadata)
	}
	// An upper-case host is compared as a string: the document must echo it.
	upper := "https://APP.example.com/oauth/client-metadata.json"
	raw := documentJSON(t, map[string]any{"client_id": upper})
	if _, err := ValidateClientMetadataDocument(raw, upper, MetadataDocumentOptions{}); err != nil {
		t.Fatalf("matching upper-case client_id rejected: %v", err)
	}
}

func TestValidateClientMetadataDocument_SecretMembersRejected(t *testing.T) {
	t.Parallel()
	for _, member := range []map[string]any{
		{"client_secret": "s3cret"},
		{"client_secret_expires_at": 0},
	} {
		requireDocumentRejected(t, documentJSON(t, member), MetadataDocumentOptions{}, codeInvalidClientMetadata)
	}
}

func TestValidateClientMetadataDocument_SharedSecretAuthMethodRejected(t *testing.T) {
	t.Parallel()
	for _, method := range []string{"client_secret_basic", "client_secret_post", "client_secret_jwt", "tls_client_auth", "bogus"} {
		requireDocumentRejected(t, documentJSON(t, map[string]any{"token_endpoint_auth_method": method}), MetadataDocumentOptions{}, codeInvalidClientMetadata)
	}
}

func TestValidateClientMetadataDocument_AuthMethodIntersectsProfile(t *testing.T) {
	t.Parallel()
	opts := MetadataDocumentOptions{AllowedClientAuthMethods: []clientauth.Method{clientauth.MethodPrivateKeyJWT}}
	requireDocumentRejected(t, documentJSON(t, nil), opts, codeInvalidClientMetadata)

	opts = MetadataDocumentOptions{AllowedClientAuthMethods: []clientauth.Method{clientauth.MethodNone, clientauth.MethodSecretBasic}}
	if _, err := ValidateClientMetadataDocument(documentJSON(t, nil), testDocumentURL, opts); err != nil {
		t.Fatalf("none under a profile that admits it: %v", err)
	}
}

func TestValidateClientMetadataDocument_PrivateKeyJWT(t *testing.T) {
	t.Parallel()
	pkjwt := func(key string, value any) []byte {
		//nolint:gosec // G101 false positive: private_key_jwt is an auth-method label.
		fields := map[string]any{"token_endpoint_auth_method": "private_key_jwt"}
		if key != "" {
			fields[key] = value
		}
		return documentJSON(t, fields)
	}
	requireDocumentRejected(t, pkjwt("", nil), MetadataDocumentOptions{}, codeInvalidClientMetadata)

	c, err := ValidateClientMetadataDocument(pkjwt("jwks", ecJWKS(t, false)), testDocumentURL, MetadataDocumentOptions{})
	if err != nil {
		t.Fatalf("private_key_jwt with jwks: %v", err)
	}
	if c.PublicClient || c.TokenEndpointAuthMethod != "private_key_jwt" || len(c.JWKs) == 0 {
		t.Errorf("pkjwt client = public:%v method:%q jwks:%d", c.PublicClient, c.TokenEndpointAuthMethod, len(c.JWKs))
	}

	if _, err := ValidateClientMetadataDocument(pkjwt("jwks_uri", "https://app.example.com/jwks.json"), testDocumentURL, MetadataDocumentOptions{}); err != nil {
		t.Fatalf("private_key_jwt with jwks_uri: %v", err)
	}

	requireDocumentRejected(t, pkjwt("jwks", ecJWKS(t, true)), MetadataDocumentOptions{}, codeInvalidClientMetadata)
}

func TestValidateClientMetadataDocument_GrantTypes(t *testing.T) {
	t.Parallel()
	requireDocumentRejected(t, documentJSON(t, map[string]any{"grant_types": []string{"client_credentials"}}), MetadataDocumentOptions{}, codeInvalidClientMetadata)

	c, err := ValidateClientMetadataDocument(documentJSON(t, map[string]any{
		"grant_types": []string{"authorization_code", "client_credentials", "refresh_token"},
	}), testDocumentURL, MetadataDocumentOptions{})
	if err != nil {
		t.Fatalf("mixed grant_types: %v", err)
	}
	if want := []string{"authorization_code", "refresh_token"}; !slices.Equal(c.GrantTypes, want) {
		t.Errorf("grant_types = %v, want %v", c.GrantTypes, want)
	}

	c, err = ValidateClientMetadataDocument(documentJSON(t, nil), testDocumentURL, MetadataDocumentOptions{})
	if err != nil {
		t.Fatalf("default grant_types: %v", err)
	}
	if !slices.Equal(c.GrantTypes, []string{"authorization_code"}) {
		t.Errorf("default grant_types = %v, want [authorization_code]", c.GrantTypes)
	}
}

func TestValidateClientMetadataDocument_ResponseTypesCodeOnly(t *testing.T) {
	t.Parallel()
	for _, rts := range [][]string{{"code id_token"}, {"token"}, {"code", "id_token"}} {
		requireDocumentRejected(t, documentJSON(t, map[string]any{"response_types": rts}), MetadataDocumentOptions{}, codeInvalidClientMetadata)
	}
}

func TestValidateClientMetadataDocument_RedirectURIsRequired(t *testing.T) {
	t.Parallel()
	requireDocumentRejected(t, documentJSON(t, map[string]any{"redirect_uris": []string{}}), MetadataDocumentOptions{}, codeInvalidRedirectURI)
	requireDocumentRejected(t, documentJSON(t, map[string]any{"redirect_uris": nil}), MetadataDocumentOptions{}, codeInvalidRedirectURI)
}

func TestValidateClientMetadataDocument_BadRedirectURIRejectsDocument(t *testing.T) {
	t.Parallel()
	for _, uri := range []string{"http://app.example.com/cb", "https://app.example.com/cb#frag", "/relative"} {
		raw := documentJSON(t, map[string]any{"redirect_uris": []string{"http://127.0.0.1:3000/callback", uri}})
		requireDocumentRejected(t, raw, MetadataDocumentOptions{}, codeInvalidRedirectURI)
	}
}

func TestValidateClientMetadataDocument_LocalhostRedirectInfersNative(t *testing.T) {
	t.Parallel()
	c, err := ValidateClientMetadataDocument(documentJSON(t, map[string]any{
		"redirect_uris": []string{"http://localhost:3000/callback"},
	}), testDocumentURL, MetadataDocumentOptions{})
	if err != nil {
		t.Fatalf("localhost redirect: %v", err)
	}
	if c.ApplicationType != applicationTypeNative {
		t.Errorf("application_type = %q, want native", c.ApplicationType)
	}

	c, err = ValidateClientMetadataDocument(documentJSON(t, map[string]any{
		"redirect_uris": []string{"http://127.0.0.1:3000/callback", "https://app.example.com/cb"},
	}), testDocumentURL, MetadataDocumentOptions{})
	if err != nil {
		t.Fatalf("mixed redirect_uris: %v", err)
	}
	if c.ApplicationType != defaultApplicationType {
		t.Errorf("application_type = %q, want web when a redirect_uri is not loopback", c.ApplicationType)
	}
}

func TestValidateClientMetadataDocument_UnknownMembersIgnored(t *testing.T) {
	t.Parallel()
	raw := documentJSON(t, map[string]any{
		"code_challenge_methods_used": []string{"S256"},
		"x_vendor_extension":          map[string]any{"a": 1},
	})
	if _, err := ValidateClientMetadataDocument(raw, testDocumentURL, MetadataDocumentOptions{}); err != nil {
		t.Fatalf("unknown members: %v", err)
	}
}

func TestValidateClientMetadataDocument_SoftwareStatementRejected(t *testing.T) {
	t.Parallel()
	raw := documentJSON(t, map[string]any{"software_statement": "eyJhbGciOiJub25lIn0.e30."})
	requireDocumentRejected(t, raw, MetadataDocumentOptions{}, codeInvalidSoftwareStmt)
}
