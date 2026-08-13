package tokenendpoint_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/mtls"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// clientCredsForm builds the canonical client_credentials form body.
// scope is optional; an empty string omits the parameter so the OP
// falls back to the client's full registered set.
func clientCredsForm(scope string) url.Values {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	if scope != "" {
		form.Set("scope", scope)
	}
	return form
}

// clientCredsClient registers a confidential client with
// "client_credentials" in GrantTypes and a single-secret hash. The
// returned secret is the plaintext callers thread through Basic auth.
//
// We do not reuse [fixture.confidentialClientFixture] because that
// helper builds a client whose GrantTypes default to
// authorization_code + refresh_token, which would drive this grant's
// "grant not permitted" branch instead of the happy path.
func clientCredsClient(tb testing.TB, prov *testkit.Provider, scopes []string) (*store.Client, string) {
	tb.Helper()
	const secret = "shh-its-a-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		tb.Fatalf("Argon2id.Hash: %v", err)
	}
	client := prov.RegisterClient(tb, testkit.ClientFixture{
		ID:                      "client-cc",
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"client_credentials"},
		Scopes:                  scopes,
	})
	return client, secret
}

// TestClientCredentials_HappyPath confirms the canonical §4.4 flow:
// confidential client, registered for the grant, no scope param.
// The response body MUST carry a JWT-shaped access_token,
// token_type=Bearer, expires_in > 0, and the joined scope. It MUST
// NOT carry refresh_token or id_token (§4.4.3 + no end-user).
// newClientCredsFixture builds a fixture whose Provider actually enables
// the client_credentials grant. The default grant set is
// authorization_code + refresh_token, and the token endpoint rejects a
// grant_type outside the configured set before dispatch, so a
// client_credentials test that skipped this option would be asserting
// against unsupported_grant_type rather than the grant it means to
// exercise.
func newClientCredsFixture(tb testing.TB, opts ...op.Option) *fixture {
	tb.Helper()
	return newFixtureWithOptions(tb, append([]op.Option{clientCredsGrantsOption()}, opts...)...)
}

// clientCredsGrantsOption enables client_credentials alongside the
// library defaults.
func clientCredsGrantsOption() op.Option {
	return op.WithGrants(grant.AuthorizationCode, grant.RefreshToken, grant.ClientCredentials)
}

func TestClientCredentials_HappyPath(t *testing.T) {
	t.Parallel()

	f := newClientCredsFixture(t)
	client, secret := clientCredsClient(t, f.prov, []string{"read", "write"})

	resp := f.post(t, clientCredsForm(""), client.ID, secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	assertCacheControl(t, resp)
	body := decodeJSON(t, resp)
	if body["token_type"] != "Bearer" {
		t.Errorf("token_type=%v want Bearer", body["token_type"])
	}
	if got, _ := body["expires_in"].(float64); got <= 0 {
		t.Errorf("expires_in=%v want > 0", body["expires_in"])
	}
	if got := body["scope"]; got != "read write" {
		t.Errorf("scope=%v want %q", got, "read write")
	}
	at, _ := body["access_token"].(string)
	if at == "" {
		t.Fatal("access_token missing")
	}
	if _, has := body["refresh_token"]; has {
		t.Errorf("refresh_token must NOT be issued for client_credentials (RFC 6749 §4.4.3)")
	}
	if _, has := body["id_token"]; has {
		t.Errorf("id_token must NOT be issued for client_credentials (no end-user)")
	}

	// Verify the access token: signature, issuer, expiry, and that
	// "sub" equals the client_id (FAPI 2.0 baseline + RFC 9068 §2.2).
	verifier := &tokens.AccessTokenVerifier{
		Keys: mustKeySet(t, f.prov), Issuer: f.prov.Issuer, Clock: f.clock,
	}
	parsed, _, err := verifier.Verify(context.Background(), at)
	if err != nil {
		t.Fatalf("AccessTokenVerifier.Verify: %v", err)
	}
	if parsed.Subject != client.ID {
		t.Errorf("sub=%q want %q (subject must equal client_id)", parsed.Subject, client.ID)
	}
	if parsed.ClientID != client.ID {
		t.Errorf("client_id claim=%q want %q", parsed.ClientID, client.ID)
	}
	if parsed.AuthTime != 0 {
		t.Errorf("auth_time=%d want 0 (no end-user authentication)", parsed.AuthTime)
	}
}

func TestClientCredentials_AuthorizationDetailsAcceptedAndEchoed(t *testing.T) {
	t.Parallel()

	f := newClientCredsFixture(t, paymentAuthorizationDetailsOption())
	client, secret := clientCredsClient(t, f.prov, []string{"payments"})

	form := clientCredsForm("payments")
	form.Set("authorization_details", `[{"type":"payment","amount":"100"}]`)
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	details, ok := body["authorization_details"].([]any)
	if !ok || len(details) != 1 {
		t.Fatalf("authorization_details=%T %[1]v want one element", body["authorization_details"])
	}
	el, _ := details[0].(map[string]any)
	if el["type"] != "payment" || el["amount"] != "100" {
		t.Fatalf("authorization_details[0]=%v want payment amount=100", el)
	}
	claims := decodeJWTPayload(t, body["access_token"].(string))
	atDetails, ok := claims["authorization_details"].([]any)
	if !ok || len(atDetails) != 1 {
		t.Fatalf("access token authorization_details=%T %[1]v want one element", claims["authorization_details"])
	}
}

// TestClientCredentials_RequestedScopeSubset narrows the response
// scope to a subset of the client's registered set. The OP echoes the
// narrowed scope verbatim per RFC 6749 §3.3.
func TestClientCredentials_RequestedScopeSubset(t *testing.T) {
	t.Parallel()

	f := newClientCredsFixture(t)
	client, secret := clientCredsClient(t, f.prov, []string{"read", "write", "delete"})

	resp := f.post(t, clientCredsForm("read write"), client.ID, secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	if got := body["scope"]; got != "read write" {
		t.Errorf("scope=%v want %q", got, "read write")
	}
}

// TestClientCredentials_ScopeOutsideRegistered rejects a request whose
// scope contains an entry not on the client's registered set with
// 400 invalid_scope (RFC 6749 §5.2).
func TestClientCredentials_ScopeOutsideRegistered(t *testing.T) {
	t.Parallel()

	f := newClientCredsFixture(t)
	client, secret := clientCredsClient(t, f.prov, []string{"read"})

	resp := f.post(t, clientCredsForm("read write"), client.ID, secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400, body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	if got := decodeJSON(t, resp); got["error"] != "invalid_scope" {
		t.Errorf("error=%v want invalid_scope", got["error"])
	}
}

// TestClientCredentials_ScopeAllowedClientsRejected verifies that the
// /token endpoint enforces op.Scope.AllowedClients for client_credentials
// grants, not just authorization_code and refresh_token. The client has
// the scope in its registered set, but the global scope registry restricts
// it to a different client_id.
func TestClientCredentials_ScopeAllowedClientsRejected(t *testing.T) {
	t.Parallel()

	f := scopedFixture(t)
	client, secret := clientCredsClient(t, f.prov, []string{"billing:write"})

	resp := f.post(t, clientCredsForm("billing:write"), client.ID, secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400, body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	if got := decodeJSON(t, resp); got["error"] != "invalid_scope" {
		t.Errorf("error=%v want invalid_scope", got["error"])
	}
}

// TestClientCredentials_OpenIDScopeRejected guards the documented
// posture: there is no end-user identity to certify in this grant, so
// the OIDC "openid" scope is meaningless and rejected outright with
// invalid_scope. Without the check, a misconfigured embedder could
// silently mint id_tokens about a subject that is the client itself,
// which would confuse downstream RPs.
func TestClientCredentials_OpenIDScopeRejected(t *testing.T) {
	t.Parallel()

	f := newClientCredsFixture(t)
	client, secret := clientCredsClient(t, f.prov, []string{"openid", "read"})

	resp := f.post(t, clientCredsForm("openid"), client.ID, secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400, body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	if got := decodeJSON(t, resp); got["error"] != "invalid_scope" {
		t.Errorf("error=%v want invalid_scope", got["error"])
	}
}

// TestClientCredentials_PublicClient_UnauthorizedClient verifies the
// rejection of a public client that asks for client_credentials. The
// public client cannot present a secret (the auth layer's
// "PublicClient ↔ MethodNone" rule rejects any Basic / Post / JWT
// channel up front), so the request reaches the token endpoint with
// MethodNone and the body's client_id. The auth layer accepts the
// shape because the client is registered as public; the
// [clientcred.Authorize] step then rejects with ErrPublicClient,
// which the HTTP layer maps to 400 unauthorized_client per RFC 6749
// §5.2 ("the authenticated client is not authorized to use this
// authorization grant type"). The test name encodes the observed
// wire code so future refactors do not silently change it.
func TestClientCredentials_PublicClient_UnauthorizedClient(t *testing.T) {
	t.Parallel()

	f := newClientCredsFixture(t)
	client := f.prov.RegisterClient(t, testkit.ClientFixture{
		ID:           "client-cc-pub",
		PublicClient: true,
		GrantTypes:   []string{"client_credentials"},
		Scopes:       []string{"read"},
	})

	// The public client sends client_id in the body (no Basic). The
	// auth layer parses MethodNone and accepts it because the client
	// is registered as public; the grant authorizer then rejects with
	// ErrPublicClient → 400 unauthorized_client.
	form := clientCredsForm("")
	form.Set("client_id", client.ID)
	resp := f.post(t, form, "", "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400, body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	if body["error"] != "unauthorized_client" {
		t.Errorf("error=%v want unauthorized_client", body["error"])
	}
}

// TestClientCredentials_GrantNotInClientGrantTypes rejects a
// confidential client whose registration omits "client_credentials"
// from GrantTypes. The auth layer accepts the credentials, but the
// grant authorizer surfaces ErrGrantNotPermitted → 400
// unauthorized_client (RFC 6749 §5.2).
func TestClientCredentials_GrantNotInClientGrantTypes(t *testing.T) {
	t.Parallel()

	f := newClientCredsFixture(t)
	// f.confidentialClientFixture defaults to authorization_code +
	// refresh_token in GrantTypes, which is exactly the configuration
	// this test wants to exercise.
	client, secret := f.confidentialClientFixture(t)

	resp := f.post(t, clientCredsForm(""), client.ID, secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400, body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	if body["error"] != "unauthorized_client" {
		t.Errorf("error=%v want unauthorized_client", body["error"])
	}
}

// TestClientCredentials_DPoPBound verifies that a DPoP proof on the
// client_credentials request binds the issued access token via
// cnf.jkt. The wire token_type flips to "DPoP" because the binding
// is on the proof, not the cert.
func TestClientCredentials_DPoPBound(t *testing.T) {
	t.Parallel()

	f := dpopFixture(t)
	client, secret := clientCredsDPoPClient(t, f.prov)
	key := newDPoPKey(t)

	form := clientCredsForm("read")
	proof := makeDPoPProof(t, key, "POST", f.endpoint, f.clock.now, "jti-cc-dpop", "")
	resp := postWithDPoP(t, f.prov.HTTPClient(nil), f.endpoint, form, client.ID, secret, proof)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	if got := body["token_type"]; got != "DPoP" {
		t.Errorf("token_type=%v want DPoP", got)
	}
	if _, has := body["refresh_token"]; has {
		t.Errorf("refresh_token must NOT be present on client_credentials")
	}
	if _, has := body["id_token"]; has {
		t.Errorf("id_token must NOT be present on client_credentials")
	}

	at, _ := body["access_token"].(string)
	if at == "" {
		t.Fatal("access_token missing")
	}
	verifier := &tokens.AccessTokenVerifier{
		Keys: mustKeySet(t, f.prov), Issuer: f.prov.Issuer, Clock: f.clock,
	}
	parsed, _, err := verifier.Verify(context.Background(), at)
	if err != nil {
		t.Fatalf("Verify access token: %v", err)
	}
	if got := parsed.Confirmation["jkt"]; got != key.jkt {
		t.Errorf("cnf.jkt=%q want %q", got, key.jkt)
	}
	if parsed.Subject != client.ID {
		t.Errorf("sub=%q want %q (subject must equal client_id)", parsed.Subject, client.ID)
	}
}

// TestClientCredentials_MTLSBound verifies that an mTLS-presented
// cert on the request binds the issued access token via
// cnf.x5t#S256. The wire token_type stays "Bearer" because RFC 8705
// §3.1 keeps the bearer token_type for cert-bound tokens.
func TestClientCredentials_MTLSBound(t *testing.T) {
	t.Parallel()

	f := mtlsFixture(t)
	client, secret := clientCredsMTLSClient(t, f.prov)
	cert := generateMTLSLeaf(t)
	thumb := mtls.Thumbprint(cert)

	resp := postWithMTLS(t, f.prov, clientCredsForm("read"), client.ID, secret, cert)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", resp.StatusCode, decodeMTLSResp(t, resp))
	}
	body := decodeMTLSResp(t, resp)
	if got := body["token_type"]; got != "Bearer" {
		t.Errorf("token_type=%v want Bearer (mTLS keeps the bearer wire type)", got)
	}
	if _, has := body["refresh_token"]; has {
		t.Errorf("refresh_token must NOT be present on client_credentials")
	}
	if _, has := body["id_token"]; has {
		t.Errorf("id_token must NOT be present on client_credentials")
	}

	at, _ := body["access_token"].(string)
	if at == "" {
		t.Fatal("access_token missing")
	}
	verifier := &tokens.AccessTokenVerifier{
		Keys: mustKeySet(t, f.prov), Issuer: f.prov.Issuer, Clock: f.clock,
	}
	parsed, _, err := verifier.Verify(context.Background(), at)
	if err != nil {
		t.Fatalf("Verify access token: %v", err)
	}
	if got := parsed.Confirmation["x5t#S256"]; got != thumb {
		t.Errorf("cnf.x5t#S256=%q want %q", got, thumb)
	}
	if _, hasJKT := parsed.Confirmation["jkt"]; hasJKT {
		t.Errorf("cnf.jkt must not be present on an mTLS-bound token")
	}
	if parsed.Subject != client.ID {
		t.Errorf("sub=%q want %q (subject must equal client_id)", parsed.Subject, client.ID)
	}
}

// clientCredsDPoPClient seeds a confidential client whose registration
// permits the client_credentials grant against a DPoP-feature
// provider. Mirrors [clientCredsClient] but lives here so the DPoP /
// mTLS test functions stay self-contained.
func clientCredsDPoPClient(tb testing.TB, prov *testkit.Provider) (*store.Client, string) {
	tb.Helper()
	const secret = "shh-its-a-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		tb.Fatalf("Argon2id.Hash: %v", err)
	}
	client := prov.RegisterClient(tb, testkit.ClientFixture{
		ID:                      "client-cc-dpop",
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"client_credentials"},
		Scopes:                  []string{"read", "write"},
	})
	return client, secret
}

// clientCredsMTLSClient is the mTLS-fixture counterpart of
// [clientCredsDPoPClient].
func clientCredsMTLSClient(tb testing.TB, prov *testkit.Provider) (*store.Client, string) {
	tb.Helper()
	const secret = "shh-its-a-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		tb.Fatalf("Argon2id.Hash: %v", err)
	}
	client := prov.RegisterClient(tb, testkit.ClientFixture{
		ID:                      "client-cc-mtls",
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"client_credentials"},
		Scopes:                  []string{"read", "write"},
	})
	return client, secret
}

// TestClientCredentials_GidClaim_AbsentForSyntheticGrant pins the /
// RFC 7519 §4.3 wire invariant on the client_credentials path: the
// issuance call site passes an empty GrantID (RFC 6749 §4.4 has no
// authorize-side grant, so the library does not allocate one). The
// wire-form encoder applies omitempty to the "gid" claim, so the
// issued AT MUST NOT carry a "gid" key when the grant id is empty.
// This keeps the wire bytes unchanged for client_credentials callers
// under all three strategies and avoids advertising a synthetic grant
// to resource servers that have no use for it.
func TestClientCredentials_GidClaim_AbsentForSyntheticGrant(t *testing.T) {
	t.Parallel()

	f := newClientCredsFixture(t)
	client, secret := clientCredsClient(t, f.prov, []string{"read"})

	resp := f.post(t, clientCredsForm("read"), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	at, _ := body["access_token"].(string)
	if at == "" {
		t.Fatal("access_token missing")
	}
	verifier := &tokens.AccessTokenVerifier{
		Keys: mustKeySet(t, f.prov), Issuer: f.prov.Issuer, Clock: f.clock,
	}
	claims, _, err := verifier.Verify(context.Background(), at)
	if err != nil {
		t.Fatalf("AccessTokenVerifier.Verify: %v", err)
	}
	if claims.GrantID != "" {
		t.Errorf("gid claim=%q want empty (client_credentials synthesises no grant id)", claims.GrantID)
	}
}

// TestClientCredentials_OpaqueFormat_PersistsRow exercises the
// client_credentials path under the opaque-format option. The wire
// response carries a 43-character base64url string with no '.'
// separator, the [store.OpaqueAccessTokenStore] holds a matching row,
// and the row's GrantID column carries the empty grant id the
// client_credentials grant synthesises (RFC 6749 §4.4 has no
// authorize-side grant). The wire token_type stays "Bearer" because
// no DPoP / mTLS proof is presented in this test.
func TestClientCredentials_OpaqueFormat_PersistsRow(t *testing.T) {
	t.Parallel()

	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	prov := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(
			clientCredsGrantsOption(),
			op.WithAccessTokenFormat(op.AccessTokenFormatOpaque),
		),
	)
	f := &fixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/token",
		clock:    clock,
	}

	client, secret := clientCredsClient(t, f.prov, []string{"read", "write"})

	resp := f.post(t, clientCredsForm("read"), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	at, _ := body["access_token"].(string)
	if at == "" {
		t.Fatal("access_token missing")
	}
	if len(at) != 43 {
		t.Errorf("len(access_token)=%d want 43 (opaque format)", len(at))
	}
	if strings.Contains(at, ".") {
		t.Errorf("opaque access_token must not contain '.', got %q", at)
	}
	if got := body["token_type"]; got != "Bearer" {
		t.Errorf("token_type=%v want Bearer", got)
	}

	rec, err := f.prov.Store.OpaqueAccessTokens().Find(context.Background(), at)
	if err != nil {
		t.Fatalf("OpaqueAccessTokens.Find: %v", err)
	}
	// client_credentials synthesises no authorize-side grant; the
	// substore stores the empty string verbatim. RevokeByGrant("") is a
	// no-op so the cascade behaviour is unchanged from the JWT path.
	if rec.GrantID != "" {
		t.Errorf("rec.GrantID=%q want empty (client_credentials synthesises no grant)", rec.GrantID)
	}
	if rec.ClientID != client.ID {
		t.Errorf("rec.ClientID=%q want %q", rec.ClientID, client.ID)
	}
	if rec.Subject != client.ID {
		// RFC 9068 §2.2 / FAPI 2.0 baseline: client_credentials puts
		// client_id in the sub claim. The opaque path mirrors the
		// posture so introspection projects the same subject.
		t.Errorf("rec.Subject=%q want %q (subject must equal client_id)", rec.Subject, client.ID)
	}
	if !rec.AuthTime.IsZero() {
		t.Errorf("rec.AuthTime=%v want zero (client_credentials has no end-user auth_time)", rec.AuthTime)
	}
	if rec.Revoked {
		t.Errorf("rec.Revoked=true want false on freshly-issued opaque AT")
	}
}
