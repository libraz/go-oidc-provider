package endpointsupport_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// ccRevocationSecret is the fixture secret the client_credentials RP
// authenticates with.
//
//nolint:gosec // G101: test fixture, not a real credential.
const ccRevocationSecret = "rp-cc-revocation-secret"

// TestEndToEnd_ClientCredentialsJWTRevocationClosesReadPaths drives the
// RFC 7009 §2.1 contract for a machine-to-machine access token end to
// end: mint through grant_type=client_credentials, revoke at
// /oidc/revoke, then confirm both surfaces that consume a JWT access
// token treat it as withdrawn.
//
// The token shape is what makes this distinct from the grant-bound
// paths. client_credentials has no authorize-side grant, so the JWT
// carries no "gid" private claim and the only revocation record the OP
// can write for it is a per-jti denylist row. A reader that consults the
// tombstone substore only for tokens that DO carry a "gid" never reads
// that row, and the revoked token keeps working until its own exp — the
// exact window RFC 7009 exists to close.
//
// The default provider config is deliberate: JWT access-token format and
// the grant-tombstone strategy, which is the configuration that writes
// no per-token shadow row at mint time. The read side therefore has to
// close on the denylist row alone.
func TestEndToEnd_ClientCredentialsJWTRevocationClosesReadPaths(t *testing.T) {
	t.Parallel()

	hash, err := op.HashClientSecret(ccRevocationSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithFeature(feature.Revoke),
		op.WithFeature(feature.Introspect),
	))
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "rp-cc-revocation",
		SecretHash:              hash,
		Scopes:                  []string{"api"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"client_credentials"},
	})

	at := mintClientCredentialsToken(t, tk, rp.ID)

	// Precondition: the token really is the grantless JWT shape this
	// regression is about. Without it the assertions below would pass
	// through the grant-tombstone path and prove nothing.
	claims := decodeAccessTokenClaims(t, at)
	if jti, _ := claims["jti"].(string); jti == "" {
		t.Fatalf("access token carries no jti claim; claims=%v", claims)
	}
	if gid, present := claims["gid"]; present {
		t.Fatalf("client_credentials access token must not carry a gid claim; got %v", gid)
	}

	// Pre-revoke: introspection reports the token active.
	if active := introspectActiveFlag(t, tk, at, rp.ID); !active {
		t.Fatal("pre-revoke /introspect reported active=false; want true")
	}
	// Pre-revoke /userinfo is already 401 — a client_credentials subject
	// is a client, not an end user, so there are no claims to release.
	// The challenge is captured so the post-revoke assertion can prove it
	// changed for the right reason rather than matching the same 401.
	preStatus, preChallenge := userInfoProbe(t, tk, at)
	if preStatus != http.StatusUnauthorized {
		t.Fatalf("pre-revoke /userinfo status=%d want 401", preStatus)
	}
	if strings.Contains(preChallenge, "revoked") {
		t.Fatalf("pre-revoke /userinfo challenge already claims revocation: %q", preChallenge)
	}

	if status, body := postRevokeToken(t, tk, at, rp.ID); status != http.StatusOK || len(body) != 0 {
		t.Fatalf("/revoke status=%d body=%s want 200 + empty", status, body)
	}

	if active := introspectActiveFlag(t, tk, at, rp.ID); active {
		t.Error("post-revoke /introspect reported active=true; want false")
	}
	postStatus, postChallenge := userInfoProbe(t, tk, at)
	if postStatus != http.StatusUnauthorized {
		t.Fatalf("post-revoke /userinfo status=%d want 401", postStatus)
	}
	if !strings.Contains(postChallenge, `error="invalid_token"`) {
		t.Errorf("post-revoke /userinfo challenge=%q must declare invalid_token", postChallenge)
	}
	if !strings.Contains(postChallenge, "revoked") {
		t.Errorf("post-revoke /userinfo challenge=%q must attribute the rejection to revocation", postChallenge)
	}
}

// mintClientCredentialsToken exchanges the client's own credentials for
// an access token and returns the wire value.
func mintClientCredentialsToken(t *testing.T, tk *testkit.Provider, clientID string) string {
	t.Helper()
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"api"}}
	body := postForm(t, tk, "/oidc/token", form, clientID)
	if body.status != http.StatusOK {
		t.Fatalf("/token status=%d want 200; body=%s", body.status, body.raw)
	}
	var env map[string]any
	if err := json.Unmarshal(body.raw, &env); err != nil {
		t.Fatalf("/token body is not JSON: %v (raw=%s)", err, body.raw)
	}
	at, _ := env["access_token"].(string)
	if at == "" {
		t.Fatalf("client_credentials /token returned no access_token; body=%s", body.raw)
	}
	return at
}

// introspectActiveFlag POSTs token to /oidc/introspect and returns the
// "active" member of the RFC 7662 §2.2 response.
func introspectActiveFlag(t *testing.T, tk *testkit.Provider, token, clientID string) bool {
	t.Helper()
	res := postForm(t, tk, "/oidc/introspect", url.Values{"token": {token}}, clientID)
	if res.status != http.StatusOK {
		t.Fatalf("/introspect status=%d want 200; body=%s", res.status, res.raw)
	}
	var env map[string]any
	if err := json.Unmarshal(res.raw, &env); err != nil {
		t.Fatalf("/introspect body is not JSON: %v (raw=%s)", err, res.raw)
	}
	active, _ := env["active"].(bool)
	return active
}

// postRevokeToken POSTs token to /oidc/revoke without a
// token_type_hint and returns the status code plus raw body so the
// caller can assert the RFC 7009 §2.2 "200 + empty" shape.
func postRevokeToken(t *testing.T, tk *testkit.Provider, token, clientID string) (int, []byte) {
	t.Helper()
	res := postForm(t, tk, "/oidc/revoke", url.Values{"token": {token}}, clientID)
	return res.status, res.raw
}

// userInfoProbe presents bearer at /oidc/userinfo and returns the status
// code alongside the WWW-Authenticate challenge.
func userInfoProbe(t *testing.T, tk *testkit.Provider, bearer string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		tk.Server.URL+"/oidc/userinfo", nil)
	if err != nil {
		t.Fatalf("build /userinfo request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("GET /userinfo: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, resp.Header.Get("WWW-Authenticate")
}

// formResult bundles the two pieces of an endpoint response the
// revocation assertions need.
type formResult struct {
	status int
	raw    []byte
}

// postForm submits form to path under client_secret_basic authentication
// for clientID.
func postForm(t *testing.T, tk *testkit.Provider, path string, form url.Values, clientID string) formResult {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build %s request: %v", path, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, ccRevocationSecret)
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s body: %v", path, err)
	}
	return formResult{status: resp.StatusCode, raw: raw}
}

// decodeAccessTokenClaims pulls the payload out of a JWS Compact
// Serialisation without verifying it; the test only needs to inspect
// which claims the mint path stamped.
func decodeAccessTokenClaims(t *testing.T, jws string) map[string]any {
	t.Helper()
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		t.Fatalf("access token is not a JWS Compact Serialisation (parts=%d)", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode access token payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("unmarshal access token claims: %v", err)
	}
	return claims
}
