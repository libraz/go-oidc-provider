package scenarios_test

// Catalog: test/scenarios/catalog/par.yaml (PAR-NNN)
// Spec:
//   - RFC 9126 — OAuth 2.0 Pushed Authorization Requests
//   - RFC 9101 — JWT-Secured Authorization Request (JAR)
//   - OpenID Connect Core 1.0 §3.1.2
//   - OpenID Connect Discovery 1.0 §3

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

// parPlainFixture bundles a [testkit.Provider] with PAR enabled and a
// confidential client suitable for plain-form pushes. The helper centralises
// the common boilerplate so each scenario test reads as a sequence of
// HTTP-level assertions.
type parPlainFixture struct {
	tk       *testkit.Provider
	endpoint string
	client   *store.Client
	secret   string
}

// newPARPlainFixture returns a fresh fixture. JAR is intentionally NOT
// enabled so plain-push scenarios do not accidentally exercise the
// request-object code path.
func newPARPlainFixture(t *testing.T) *parPlainFixture {
	t.Helper()
	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithFeature(feature.PAR)))
	const secret = "rp-par-secret"
	hash, err := op.HashClientSecret(secret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	client := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "rp-par",
		SecretHash:              hash,
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	return &parPlainFixture{
		tk:       tk,
		endpoint: tk.Server.URL + "/oidc/par",
		client:   client,
		secret:   secret,
	}
}

// happyForm returns the canonical PKCE-bound /par form for the fixture's
// confidential client.
func (f *parPlainFixture) happyForm() (url.Values, scenariokit.PKCEPair) {
	pkce := scenariokit.NewPKCEPair("")
	form := url.Values{
		"client_id":             {f.client.ID},
		"response_type":         {"code"},
		"redirect_uri":          {f.client.RedirectURIs[0]},
		"scope":                 {"openid profile email"},
		"state":                 {"par-state"},
		"nonce":                 {"par-nonce"},
		"code_challenge":        {pkce.Challenge},
		"code_challenge_method": {pkce.Method},
	}
	return form, pkce
}

// post issues a POST to f.endpoint with the supplied form, optionally
// authenticated with HTTP Basic. It returns the raw response so each
// scenario can inspect status / body.
func (f *parPlainFixture) post(t *testing.T, form url.Values, basicID, basicSecret string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		f.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest /par: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicID != "" {
		req.SetBasicAuth(basicID, basicSecret)
	}
	resp, err := f.tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("Do /par: %v", err)
	}
	return resp
}

// publicClient seeds a public (no-secret) client on the fixture's
// provider. It is used by PAR-005 to drive the unregistered redirect
// rejection from a public-client wire shape.
func (f *parPlainFixture) publicClient(t *testing.T) *store.Client {
	t.Helper()
	return f.tk.RegisterClient(t, testkit.ClientFixture{
		ID:           "rp-par-public",
		PublicClient: true,
		RedirectURIs: []string{"https://rp.testkit.invalid/callback"},
		Scopes:       []string{"openid", "profile", "email"},
	})
}

// decodeJSONResp parses resp.Body as a JSON object map.
func decodeJSONResp(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	out := map[string]any{}
	if len(raw) == 0 {
		return out
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal %s: %v", raw, err)
	}
	return out
}

// parJARFixture extends [parPlainFixture] with a JAR-enabled provider and
// an ES256 keypair / public JWKS bound to the registered client. Tests
// that drive signed Request Objects build their JWT against
// [parJARFixture.signES256] and POST it to [parJARFixture.endpoint].
type parJARFixture struct {
	tk       *testkit.Provider
	endpoint string
	client   *store.Client
	secret   string
	priv     *ecdsa.PrivateKey
	kid      string
}

// newPARJARFixture builds a JAR-enabled fixture. The client's
// RequestObjectSigningAlg may be tightened by the caller via
// [parJARFixture.pinAlg]; by default it is empty (any allow-listed alg).
func newPARJARFixture(t *testing.T) *parJARFixture {
	t.Helper()
	tk := testkit.NewProvider(t,
		testkit.WithOptions(
			op.WithFeature(feature.PAR),
			op.WithFeature(feature.JAR),
		),
	)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	const kid = "rp-par-jar-kid"
	jwksRaw, err := json.Marshal(josev4.JSONWebKeySet{
		Keys: []josev4.JSONWebKey{{
			Key:       &priv.PublicKey,
			KeyID:     kid,
			Algorithm: string(josev4.ES256),
			Use:       "sig",
		}},
	})
	if err != nil {
		t.Fatalf("Marshal JWKS: %v", err)
	}
	const secret = "rp-par-jar-secret" //nolint:gosec // test fixture client secret, not a credential.
	hash, err := op.HashClientSecret(secret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	client := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "rp-par-jar",
		SecretHash:              hash,
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
		JWKs:                    jwksRaw,
	})
	return &parJARFixture{
		tk:       tk,
		endpoint: tk.Server.URL + "/oidc/par",
		client:   client,
		secret:   secret,
		priv:     priv,
		kid:      kid,
	}
}

// pinAlg sets the client's [store.Client.RequestObjectSigningAlg] so the
// JAR verifier rejects request objects signed under any other alg.
func (f *parJARFixture) pinAlg(t *testing.T, alg string) {
	t.Helper()
	updated := *f.client
	updated.RequestObjectSigningAlg = alg
	if err := f.tk.Store.UpdateClient(context.Background(), &updated); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	f.client = &updated
}

// publishPS256Key rewrites the client's published JWKS to include both
// the existing ES256 key and a freshly-generated PS256 key keyed by
// psKID. PAR-022 uses it to deliver an alg-mismatch attempt: the
// server admits PS256 generally but the client's pinned alg refuses
// anything except the pinned one.
func (f *parJARFixture) publishPS256Key(t *testing.T, psKID string) *rsa.PrivateKey {
	t.Helper()
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	jwksRaw, err := json.Marshal(josev4.JSONWebKeySet{
		Keys: []josev4.JSONWebKey{
			{
				Key:       &f.priv.PublicKey,
				KeyID:     f.kid,
				Algorithm: string(josev4.ES256),
				Use:       "sig",
			},
			{
				Key:       &rsaPriv.PublicKey,
				KeyID:     psKID,
				Algorithm: string(josev4.PS256),
				Use:       "sig",
			},
		},
	})
	if err != nil {
		t.Fatalf("Marshal JWKS: %v", err)
	}
	updated := *f.client
	updated.JWKs = jwksRaw
	if err := f.tk.Store.UpdateClient(context.Background(), &updated); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	f.client = &updated
	return rsaPriv
}

// happyClaims returns the standard request-object claim set every JAR
// scenario starts from. Tests mutate the returned map (drop a claim,
// override exp) before signing.
func (f *parJARFixture) happyClaims() (map[string]any, scenariokit.PKCEPair) {
	pkce := scenariokit.NewPKCEPair("")
	now := time.Now().UTC()
	claims := map[string]any{
		"iss":                   f.client.ID,
		"aud":                   f.tk.Issuer,
		"exp":                   now.Add(2 * time.Minute).Unix(),
		"iat":                   now.Unix(),
		"nbf":                   now.Unix(),
		"jti":                   "par-jti-" + now.Format("20060102T150405.000000000"),
		"client_id":             f.client.ID,
		"response_type":         "code",
		"redirect_uri":          f.client.RedirectURIs[0],
		"scope":                 "openid profile email",
		"state":                 "par-jar-state",
		"nonce":                 "par-jar-nonce",
		"code_challenge":        pkce.Challenge,
		"code_challenge_method": pkce.Method,
	}
	return claims, pkce
}

// signES256 serialises claims as a compact ES256 JWS using the fixture's
// keypair.
func (f *parJARFixture) signES256(t *testing.T, claims map[string]any) string {
	t.Helper()
	signer, err := josev4.NewSigner(
		josev4.SigningKey{
			Algorithm: josev4.ES256,
			Key: josev4.JSONWebKey{
				Key:       f.priv,
				KeyID:     f.kid,
				Algorithm: string(josev4.ES256),
				Use:       "sig",
			},
		},
		(&josev4.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatalf("NewSigner ES256: %v", err)
	}
	out, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("Serialize ES256: %v", err)
	}
	return out
}

// signPS256 serialises claims as a compact PS256 JWS using the supplied
// private key. PAR-022 uses this to drive the alg-mismatch path.
func (f *parJARFixture) signPS256(t *testing.T, priv *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	signer, err := josev4.NewSigner(
		josev4.SigningKey{
			Algorithm: josev4.PS256,
			Key: josev4.JSONWebKey{
				Key:       priv,
				KeyID:     kid,
				Algorithm: string(josev4.PS256),
				Use:       "sig",
			},
		},
		(&josev4.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatalf("NewSigner PS256: %v", err)
	}
	out, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("Serialize PS256: %v", err)
	}
	return out
}

// post issues a POST to f.endpoint with the supplied form authenticated
// via HTTP Basic against the fixture's confidential client.
func (f *parJARFixture) post(t *testing.T, form url.Values) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		f.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest /par: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(f.client.ID, f.secret)
	resp, err := f.tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("Do /par: %v", err)
	}
	return resp
}

// TestScenario_PAR_001_DiscoveryParOnly confirms that with PAR enabled
// and JAR disabled, the discovery document advertises
// pushed_authorization_request_endpoint and keeps
// request_uri_parameter_supported=false (the JAR-side request_uri
// surface is not active without [feature.JAR]). The
// request_object_signing_alg_values_supported list and
// require_pushed_authorization_requests flag are only emitted on the
// JAR / FAPI 2.0 paths and stay absent here.
//
// Spec: RFC 9126 §5.
func TestScenario_PAR_001_DiscoveryParOnly(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithFeature(feature.PAR)))
	status, _, doc := fetchDiscovery(t, tk.Server.URL)
	if status != http.StatusOK {
		t.Fatalf("status=%d want 200", status)
	}
	endpoint, _ := doc["pushed_authorization_request_endpoint"].(string)
	if endpoint == "" {
		t.Errorf("pushed_authorization_request_endpoint missing (doc=%v)", doc)
	}
	if got, ok := doc["request_uri_parameter_supported"].(bool); !ok || got {
		t.Errorf("request_uri_parameter_supported=%v want false", doc["request_uri_parameter_supported"])
	}
	if _, ok := doc["request_object_signing_alg_values_supported"]; ok {
		t.Errorf("request_object_signing_alg_values_supported should be absent without JAR (doc=%v)", doc)
	}
	if _, ok := doc["require_pushed_authorization_requests"]; ok {
		t.Errorf("require_pushed_authorization_requests should be absent in v1.0 (doc=%v)", doc)
	}
}

// TestScenario_PAR_002_DiscoveryRequirePAR is OOS — see catalog out_of_scope_reason.
func TestScenario_PAR_002_DiscoveryRequirePAR(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PAR-002 (see catalog out_of_scope_reason)")
}

// TestScenario_PAR_003_DiscoveryParPlusJar confirms the discovery
// surface when both PAR and JAR are enabled: the PAR endpoint is
// advertised, request_parameter_supported=true, and a non-empty
// request_object_signing_alg_values_supported list is emitted (the
// project-wide asymmetric allow-list).
//
// The catalog originally claimed request_uri_parameter_supported=false
// with PAR+JAR; v1.0's discovery builder advertises the JAR-style
// request_uri surface (true) whenever [feature.JAR] is enabled (the
// /authorize endpoint accepts request_uri produced by /par). This
// binding pins the actual v1.0 wire shape rather than the original
// catalog claim.
//
// Spec: RFC 9126 §5 / RFC 9101 §10.5.
func TestScenario_PAR_003_DiscoveryParPlusJar(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithFeature(feature.PAR),
		op.WithFeature(feature.JAR),
	))
	status, _, doc := fetchDiscovery(t, tk.Server.URL)
	if status != http.StatusOK {
		t.Fatalf("status=%d want 200", status)
	}
	if endpoint, _ := doc["pushed_authorization_request_endpoint"].(string); endpoint == "" {
		t.Errorf("pushed_authorization_request_endpoint missing (doc=%v)", doc)
	}
	if got, _ := doc["request_parameter_supported"].(bool); !got {
		t.Errorf("request_parameter_supported=%v want true", doc["request_parameter_supported"])
	}
	algs, _ := doc["request_object_signing_alg_values_supported"].([]any)
	if len(algs) == 0 {
		t.Errorf("request_object_signing_alg_values_supported is empty (doc=%v)", doc)
	}
}

// TestScenario_PAR_004_UnregisteredRedirectUriConfidential is OOS — see catalog out_of_scope_reason.
func TestScenario_PAR_004_UnregisteredRedirectUriConfidential(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PAR-004 (see catalog out_of_scope_reason)")
}

// TestScenario_PAR_005_UnregisteredRedirectUriPublicRejected confirms a
// public client that pushes a redirect_uri absent from its registered
// list is rejected with 400 invalid_request.
//
// v1.0 does not ship the RFC 9126 §2.4 opt-in for ad-hoc redirect_uris;
// every client (public OR confidential) must use a pre-registered URI,
// so the public-vs-confidential distinction the original catalog row
// implied does not exist on the wire.
//
// Spec: RFC 9126 §2.4 / RFC 6749 §3.1.2.
func TestScenario_PAR_005_UnregisteredRedirectUriPublicRejected(t *testing.T) {
	t.Parallel()

	f := newPARPlainFixture(t)
	pub := f.publicClient(t)
	form, _ := f.happyForm()
	form.Set("client_id", pub.ID)
	form.Set("redirect_uri", "https://attacker.example/cb")
	resp := f.post(t, form, "", "") // public client: no Basic auth
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	body := decodeJSONResp(t, resp)
	if got, _ := body["error"].(string); got != "invalid_request" {
		t.Errorf("error=%q want invalid_request (body=%v)", got, body)
	}
}

// TestScenario_PAR_006_MalformedRedirectUriRejected confirms a /par push
// whose redirect_uri is syntactically broken is rejected with 400
// invalid_request. v1.0 enforces the RFC 9126 §2.3 "redirect_uri must
// match a registered value" rule by exact-match comparison; a malformed
// URI cannot match any registered value, so the OP returns
// invalid_request with the canonical "not registered" description.
//
// Spec: RFC 6749 §3.1.2 / OIDC Core §3.1.2.1.
func TestScenario_PAR_006_MalformedRedirectUriRejected(t *testing.T) {
	t.Parallel()

	f := newPARPlainFixture(t)
	form, _ := f.happyForm()
	// "://no-scheme" is not parseable as an absolute URI; it cannot
	// exact-match any registered URI, so the validator rejects it.
	form.Set("redirect_uri", "://no-scheme")
	resp := f.post(t, form, f.client.ID, f.secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	body := decodeJSONResp(t, resp)
	if got, _ := body["error"].(string); got != "invalid_request" {
		t.Errorf("error=%q want invalid_request (body=%v)", got, body)
	}
}

// TestScenario_PAR_007_RedirectUriFragmentRejected confirms a /par push
// whose redirect_uri carries a fragment is rejected with 400
// invalid_request. RFC 6749 §3.1.2 forbids fragments in redirect_uri;
// the library enforces this implicitly via exact-match against the
// registered list (a registered URI never carries a fragment, so any
// fragment-bearing variant is unmatched and rejected).
//
// Spec: RFC 6749 §3.1.2.
func TestScenario_PAR_007_RedirectUriFragmentRejected(t *testing.T) {
	t.Parallel()

	f := newPARPlainFixture(t)
	form, _ := f.happyForm()
	form.Set("redirect_uri", f.client.RedirectURIs[0]+"#fragment")
	resp := f.post(t, form, f.client.ID, f.secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	body := decodeJSONResp(t, resp)
	if got, _ := body["error"].(string); got != "invalid_request" {
		t.Errorf("error=%q want invalid_request (body=%v)", got, body)
	}
}

// TestScenario_PAR_008_RequestParamRejectedInParOnly confirms a
// PAR-only deployment (JAR disabled) rejects a /par push that carries
// a "request" parameter.
//
// The catalog originally cited 400 request_not_supported; v1.0's
// /par handler rejects the unconfigured JAR path with
// invalid_request_object and the description "request is not
// supported by this OP". The PAR endpoint's wire taxonomy reuses the
// JAR-side error code rather than RFC 6749 §5.2's
// request_not_supported (which the project does not emit anywhere).
//
// Spec: RFC 9126 §3 / RFC 9101 §6.2.
func TestScenario_PAR_008_RequestParamRejectedInParOnly(t *testing.T) {
	t.Parallel()

	f := newPARPlainFixture(t)
	form, _ := f.happyForm()
	form.Set("request", "eyJhbGciOiJFUzI1NiJ9.body.sig")
	resp := f.post(t, form, f.client.ID, f.secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	body := decodeJSONResp(t, resp)
	if got, _ := body["error"].(string); got != "invalid_request_object" {
		t.Errorf("error=%q want invalid_request_object (body=%v)", got, body)
	}
}

// TestScenario_PAR_009_ContextEntityExposed is OOS — see catalog out_of_scope_reason.
func TestScenario_PAR_009_ContextEntityExposed(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PAR-009 (see catalog out_of_scope_reason)")
}

// TestScenario_PAR_010_PlainPushSuccess confirms a plain-form push (no
// JAR object) returns 201 Created with body {request_uri, expires_in},
// the request_uri matches the RFC 9126 §2.2 URN prefix, and the
// persisted record carries the authenticated client's ID and the wire
// parameters.
//
// v1.0 stores the validated request as a JSON [authorize.RequestSnapshot]
// (NOT an alg=none JWT envelope); the test asserts on the wire response
// shape and the round-trip to the substore so the storage encoding stays
// out of the public scenario contract.
//
// Spec: RFC 9126 §2.2.
func TestScenario_PAR_010_PlainPushSuccess(t *testing.T) {
	t.Parallel()

	f := newPARPlainFixture(t)
	form, _ := f.happyForm()
	resp := f.post(t, form, f.client.ID, f.secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status=%d want 201", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type=%q want application/json", got)
	}
	body := decodeJSONResp(t, resp)
	uri, _ := body["request_uri"].(string)
	if !strings.HasPrefix(uri, "urn:ietf:params:oauth:request_uri:") {
		t.Errorf("request_uri=%q does not match RFC 9126 §2.2 prefix", uri)
	}
	expires, _ := body["expires_in"].(float64)
	if expires <= 0 {
		t.Errorf("expires_in=%v want >0", body["expires_in"])
	}

	// Round-trip the persisted record via the public store API.
	rec, err := f.tk.Store.PushedAuthRequests().Find(context.Background(), uri)
	if err != nil {
		t.Fatalf("PARs.Find: %v", err)
	}
	if rec.ClientID != f.client.ID {
		t.Errorf("rec.ClientID=%q want %q", rec.ClientID, f.client.ID)
	}
	if rec.ConsumedAt != nil {
		t.Errorf("ConsumedAt=%v want nil before /authorize redemption", rec.ConsumedAt)
	}
	if len(rec.RawParams) == 0 {
		t.Error("RawParams empty: snapshot was not persisted")
	}
}

// TestScenario_PAR_011_RequestUriRejectedAtPAR confirms RFC 9126 §3:
// the /par endpoint MUST NOT accept a request_uri parameter. v1.0
// rejects with 400 invalid_request (the catalog originally cited
// request_uri_not_supported; that code is reserved by RFC 9101 §6.2 for
// the OP advertising it does not honour the JAR-style request_uri at
// /authorize, NOT for the PAR-side rejection).
//
// Spec: RFC 9126 §3.
func TestScenario_PAR_011_RequestUriRejectedAtPAR(t *testing.T) {
	t.Parallel()

	f := newPARPlainFixture(t)
	form, _ := f.happyForm()
	form.Set("request_uri", "urn:ietf:params:oauth:request_uri:abc123")
	resp := f.post(t, form, f.client.ID, f.secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	body := decodeJSONResp(t, resp)
	if got, _ := body["error"].(string); got != "invalid_request" {
		t.Errorf("error=%q want invalid_request (body=%v)", got, body)
	}
}

// TestScenario_PAR_012_UnknownRedirectUriRemapped confirms a
// confidential-client /par push whose redirect_uri is not on the
// client's registered list is rejected with 400 invalid_request. RFC
// 9126 §2.3 reserves invalid_redirect_uri for the registration step;
// the PAR endpoint remaps it to invalid_request because by the time
// the OP responds, the request was already authenticated as a known
// client and the wire-form code matches the rest of the
// /par error envelope. PAR-005 covers the public-client analogue;
// this row pins the same gate for confidential clients.
//
// Spec: RFC 9126 §2.3.
func TestScenario_PAR_012_UnknownRedirectUriRemapped(t *testing.T) {
	t.Parallel()

	f := newPARPlainFixture(t)
	form, _ := f.happyForm()
	form.Set("redirect_uri", "https://attacker.example/cb")
	resp := f.post(t, form, f.client.ID, f.secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	body := decodeJSONResp(t, resp)
	if got, _ := body["error"].(string); got != "invalid_request" {
		t.Errorf("error=%q want invalid_request (body=%v)", got, body)
	}
}

// TestScenario_PAR_013_AdapterFailurePassthrough is OOS — see catalog out_of_scope_reason.
func TestScenario_PAR_013_AdapterFailurePassthrough(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PAR-013 (see catalog out_of_scope_reason)")
}

// TestScenario_PAR_014_RequestUriConsumedNoJAR verifies that a plain
// PAR push followed by a /authorize visit eventually consumes the
// request_uri (single-use per RFC 9126 §2.2). v1.0 keeps the URI
// resolvable until an authorization code is emitted; once the code is
// persisted the substore Consume hook flips ConsumedAt so any further
// /authorize lookup rejects with invalid_request_uri.
//
// Spec: RFC 9126 §2.2.
func TestScenario_PAR_014_RequestUriConsumedNoJAR(t *testing.T) {
	t.Parallel()

	f := newPARPlainFixture(t)
	form, pkce := f.happyForm()
	resp := f.post(t, form, f.client.ID, f.secret)
	if resp.StatusCode != http.StatusCreated {
		body := decodeJSONResp(t, resp)
		resp.Body.Close()
		t.Fatalf("/par status=%d body=%v", resp.StatusCode, body)
	}
	parBody := decodeJSONResp(t, resp)
	resp.Body.Close()
	requestURI, _ := parBody["request_uri"].(string)
	if requestURI == "" {
		t.Fatal("/par response missing request_uri")
	}

	// Drive /authorize using the request_uri (RFC 9126 §2.3: only
	// client_id and request_uri are honoured on the /authorize side).
	flow := scenariokit.RunCodeFlow(t, f.tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    f.client.ID,
		RedirectURI: f.client.RedirectURIs[0],
		PKCE:        pkce,
		// Override response_type / scope with empty so the helper
		// stamps the canonical defaults; everything else is recovered
		// from the PAR snapshot.
		Extra: url.Values{"request_uri": {requestURI}},
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}

	// Post-emission: the URI is consumed. A fresh /authorize visit
	// must surface invalid_request_uri.
	postResp := getAuthorizePAR(t, f.tk, f.client.ID, requestURI)
	defer postResp.Body.Close()
	if postResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("post-consume /authorize status=%d want 400", postResp.StatusCode)
	}
	body := decodeJSONResp(t, postResp)
	if got, _ := body["error"].(string); got != "invalid_request_uri" {
		t.Errorf("error=%q want invalid_request_uri (body=%v)", got, body)
	}
}

// TestScenario_PAR_015_RequestUriConsumedWhenJAROptional confirms a
// client that pre-registered request_object_signing_alg may still
// push plain (non-JAR) form parameters and complete the round-trip:
// /par returns a request_uri, /authorize consumes it (303 with code),
// and a second /authorize visit with the same request_uri is rejected
// (single-use per RFC 9126 §2.2). The pre-registered alg only
// constrains JAR-signed pushes; the plain-form path is unaffected.
//
// Spec: RFC 9126 §2.2 / RFC 9101 §6.2.
func TestScenario_PAR_015_RequestUriConsumedWhenJAROptional(t *testing.T) {
	t.Parallel()

	f := newPARJARFixture(t)
	f.pinAlg(t, "ES256") // alg is registered but the push is plain-form.

	pkce := scenariokit.NewPKCEPair("")
	form := url.Values{
		"client_id":             {f.client.ID},
		"response_type":         {"code"},
		"redirect_uri":          {f.client.RedirectURIs[0]},
		"scope":                 {"openid profile email"},
		"state":                 {"par-state"},
		"nonce":                 {"par-nonce"},
		"code_challenge":        {pkce.Challenge},
		"code_challenge_method": {pkce.Method},
	}
	resp := f.post(t, form)
	if resp.StatusCode != http.StatusCreated {
		body := decodeJSONResp(t, resp)
		resp.Body.Close()
		t.Fatalf("/par status=%d body=%v", resp.StatusCode, body)
	}
	parBody := decodeJSONResp(t, resp)
	resp.Body.Close()
	requestURI, _ := parBody["request_uri"].(string)
	if requestURI == "" {
		t.Fatal("/par response missing request_uri")
	}

	flow := scenariokit.RunCodeFlow(t, f.tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    f.client.ID,
		RedirectURI: f.client.RedirectURIs[0],
		PKCE:        pkce,
		Extra:       url.Values{"request_uri": {requestURI}},
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}

	postResp := getAuthorizePAR(t, f.tk, f.client.ID, requestURI)
	defer postResp.Body.Close()
	if postResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("post-consume /authorize status=%d want 400", postResp.StatusCode)
	}
	body := decodeJSONResp(t, postResp)
	if got, _ := body["error"].(string); got != "invalid_request_uri" {
		t.Errorf("error=%q want invalid_request_uri (body=%v)", got, body)
	}
}

// TestScenario_PAR_016_ContextEntityWithJAR is OOS — see catalog out_of_scope_reason.
func TestScenario_PAR_016_ContextEntityWithJAR(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PAR-016 (see catalog out_of_scope_reason)")
}

// TestScenario_PAR_017_JARPushSuccess confirms a /par push carrying a
// signed Request Object returns 201 with {request_uri, expires_in}.
// v1.0 admits ES256 / PS256 / RS256 / EdDSA per the project allow-list
// (the catalog originally cited HS256, which the OP rejects at parse
// time per the JOSE policy); ES256 is the canonical FAPI 2.0 Message
// Signing alg and is what every other JAR scenario uses.
//
// Spec: RFC 9126 §2.1 / RFC 9101 §6.1.
func TestScenario_PAR_017_JARPushSuccess(t *testing.T) {
	t.Parallel()

	f := newPARJARFixture(t)
	claims, _ := f.happyClaims()
	signed := f.signES256(t, claims)
	form := url.Values{
		"client_id": {f.client.ID},
		"request":   {signed},
	}
	resp := f.post(t, form)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body := decodeJSONResp(t, resp)
		t.Fatalf("status=%d body=%v", resp.StatusCode, body)
	}
	body := decodeJSONResp(t, resp)
	uri, _ := body["request_uri"].(string)
	if !strings.HasPrefix(uri, "urn:ietf:params:oauth:request_uri:") {
		t.Errorf("request_uri=%q want urn:ietf:params:oauth:request_uri: prefix", uri)
	}
	if expires, _ := body["expires_in"].(float64); expires <= 0 {
		t.Errorf("expires_in=%v want >0", body["expires_in"])
	}
}

// TestScenario_PAR_018_JARDefaultExp is OOS — see catalog out_of_scope_reason.
func TestScenario_PAR_018_JARDefaultExp(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PAR-018 (see catalog out_of_scope_reason)")
}

// TestScenario_PAR_019_JARExpBelowMaxTTL is OOS — see catalog out_of_scope_reason.
func TestScenario_PAR_019_JARExpBelowMaxTTL(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PAR-019 (see catalog out_of_scope_reason)")
}

// TestScenario_PAR_020_JARExpClampedToMaxTTL is OOS — see catalog out_of_scope_reason.
func TestScenario_PAR_020_JARExpClampedToMaxTTL(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PAR-020 (see catalog out_of_scope_reason)")
}

// TestScenario_PAR_021_JAROverridesOuterParams confirms the RFC 9101
// §6.1 precedence rule for a /par push that pairs outer form parameters
// with a signed Request Object: every authorization parameter inside
// the JWT overrides the wire-form value of the same name, while wire
// values whose name is absent from the JWT survive (so a richer outer
// form does NOT silently overrule a leaner request object).
//
// v1.0's authorize parser only accepts response_type=code; passing
// response_type=code+token on the wire alongside response_type=code in
// the JWT is the canonical way to drive the override rule on the
// happy path. The earlier catalog text claimed the outer "nonce" was
// erased — the v1.0 merge keeps any wire value whose key is absent
// from the request object, so this test pins the actual contract.
//
// Spec: RFC 9101 §6.1 / RFC 9126 §2.1.
func TestScenario_PAR_021_JAROverridesOuterParams(t *testing.T) {
	t.Parallel()

	f := newPARJARFixture(t)
	claims, _ := f.happyClaims()
	// Request object explicitly carries response_type=code; the wire
	// will pair it with an unsupported response_type override that the
	// JWT must defeat.
	claims["response_type"] = "code"
	// Drop nonce from the JWT so the wire-side nonce can demonstrate
	// "absent from JWT → wire survives" semantics.
	delete(claims, "nonce")
	signed := f.signES256(t, claims)
	form := url.Values{
		"client_id":     {f.client.ID},
		"request":       {signed},
		"response_type": {"code token"},  // overruled by JWT response_type=code
		"nonce":         {"outer-nonce"}, // survives: not present in JWT
	}
	resp := f.post(t, form)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body := decodeJSONResp(t, resp)
		t.Fatalf("status=%d body=%v", resp.StatusCode, body)
	}
	body := decodeJSONResp(t, resp)
	uri, _ := body["request_uri"].(string)
	if uri == "" {
		t.Fatal("request_uri missing from /par response")
	}

	// Round-trip the snapshot via the public store API to confirm the
	// merged values were persisted correctly. RawParams is opaque to the
	// public surface, but the [op/store] interface specifies it is the
	// JSON-encoded validated request shape; tests are allowed to inspect
	// it as a black-box JSON document.
	rec, err := f.tk.Store.PushedAuthRequests().Find(context.Background(), uri)
	if err != nil {
		t.Fatalf("PARs.Find: %v", err)
	}
	var snap map[string]any
	if err := json.Unmarshal(rec.RawParams, &snap); err != nil {
		t.Fatalf("snapshot decode: %v (raw=%s)", err, rec.RawParams)
	}
	if got, _ := snap["response_type"].(string); got != "code" {
		t.Errorf("snapshot response_type=%q want code (JWT must override outer)", got)
	}
	if got, _ := snap["nonce"].(string); got != "outer-nonce" {
		t.Errorf("snapshot nonce=%q want outer-nonce (wire-only key must survive)", got)
	}
}

// TestScenario_PAR_022_PreregisteredAlgEnforced confirms RFC 9101 §6.1's
// pre-registered alg pin: when a client publishes
// request_object_signing_alg=ES256 and pushes a Request Object signed
// under PS256, the OP rejects with 400 invalid_request_object even
// though PS256 is on the OP's project-wide allow-list.
//
// (The catalog originally cited HS256/HS384, but the project's JOSE
// allow-list refuses HMAC algorithms entirely — they would fail at
// parse time, which exercises a different gate. ES256 vs PS256 is the
// asymmetric pairing that reaches the alg-pin check.)
//
// Spec: RFC 9101 §6.1 / OIDC Dynamic Client Registration §2.
func TestScenario_PAR_022_PreregisteredAlgEnforced(t *testing.T) {
	t.Parallel()

	f := newPARJARFixture(t)
	f.pinAlg(t, "ES256")
	const psKID = "rp-par-jar-ps-kid"
	psPriv := f.publishPS256Key(t, psKID)
	claims, _ := f.happyClaims()
	signed := f.signPS256(t, psPriv, psKID, claims)
	form := url.Values{
		"client_id": {f.client.ID},
		"request":   {signed},
	}
	resp := f.post(t, form)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	body := decodeJSONResp(t, resp)
	if got, _ := body["error"].(string); got != "invalid_request_object" {
		t.Errorf("error=%q want invalid_request_object (body=%v)", got, body)
	}
}

// TestScenario_PAR_023_ClientIDConsistency confirms a Request Object
// whose embedded "client_id" claim disagrees with the authenticated
// client_id is rejected.
//
// v1.0 surfaces this on the wire as 400 invalid_request (the JAR
// merger emits jar.ErrClientIDMismatch and the parendpoint translates
// it to invalid_request, on the rationale that a client_id mismatch is
// not a request-object-format failure but a wire/JWT consistency
// violation). The catalog originally cited invalid_request_object;
// this binding pins the actual code v1.0 emits.
//
// Spec: RFC 9126 §2.1 / RFC 9101 §6.1.
func TestScenario_PAR_023_ClientIDConsistency(t *testing.T) {
	t.Parallel()

	f := newPARJARFixture(t)
	claims, _ := f.happyClaims()
	// Keep iss == authenticated client (so assertIssuer passes), but
	// claim a different client_id inside the JWT body. The JAR merge
	// step then surfaces ErrClientIDMismatch.
	claims["client_id"] = "rp-par-jar-other"
	signed := f.signES256(t, claims)
	form := url.Values{
		"client_id": {f.client.ID},
		"request":   {signed},
	}
	resp := f.post(t, form)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	body := decodeJSONResp(t, resp)
	if got, _ := body["error"].(string); got != "invalid_request" {
		t.Errorf("error=%q want invalid_request (body=%v)", got, body)
	}
}

// TestScenario_PAR_024_RedirectUriRemapWithJAR confirms a JAR-signed
// /par push whose redirect_uri is unknown to the client registration
// is rejected with 400 invalid_request. The merge step folds the JWT
// claims onto the wire form before validation, so the unregistered
// redirect_uri carried inside the request object reaches the same
// gate that PAR-005 / PAR-012 cover for plain pushes.
//
// Spec: RFC 9126 §2.3.
func TestScenario_PAR_024_RedirectUriRemapWithJAR(t *testing.T) {
	t.Parallel()

	f := newPARJARFixture(t)
	claims, _ := f.happyClaims()
	claims["redirect_uri"] = "https://attacker.example/cb"
	signed := f.signES256(t, claims)
	form := url.Values{
		"client_id": {f.client.ID},
		"request":   {signed},
	}
	resp := f.post(t, form)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	body := decodeJSONResp(t, resp)
	if got, _ := body["error"].(string); got != "invalid_request" {
		t.Errorf("error=%q want invalid_request (body=%v)", got, body)
	}
}

// TestScenario_PAR_025_AdapterFailureWithJAR is OOS — see catalog out_of_scope_reason.
func TestScenario_PAR_025_AdapterFailureWithJAR(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PAR-025 (see catalog out_of_scope_reason)")
}

// TestScenario_PAR_026_RequestUriConsumedWithJAR mirrors PAR-014 for
// the JAR-signed push: after a Request Object push, the OP issues a
// request_uri; consuming it at /authorize succeeds; a second /authorize
// after the code has been emitted is rejected with invalid_request_uri.
//
// Spec: RFC 9126 §2.2 / RFC 9101 §6.1.
func TestScenario_PAR_026_RequestUriConsumedWithJAR(t *testing.T) {
	t.Parallel()

	f := newPARJARFixture(t)
	claims, pkce := f.happyClaims()
	signed := f.signES256(t, claims)
	form := url.Values{
		"client_id": {f.client.ID},
		"request":   {signed},
	}
	resp := f.post(t, form)
	if resp.StatusCode != http.StatusCreated {
		body := decodeJSONResp(t, resp)
		resp.Body.Close()
		t.Fatalf("/par status=%d body=%v", resp.StatusCode, body)
	}
	parBody := decodeJSONResp(t, resp)
	resp.Body.Close()
	requestURI, _ := parBody["request_uri"].(string)
	if requestURI == "" {
		t.Fatal("/par response missing request_uri")
	}

	flow := scenariokit.RunCodeFlow(t, f.tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    f.client.ID,
		RedirectURI: f.client.RedirectURIs[0],
		PKCE:        pkce,
		Extra:       url.Values{"request_uri": {requestURI}},
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}

	postResp := getAuthorizePAR(t, f.tk, f.client.ID, requestURI)
	defer postResp.Body.Close()
	if postResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("post-consume /authorize status=%d want 400", postResp.StatusCode)
	}
	body := decodeJSONResp(t, postResp)
	if got, _ := body["error"].(string); got != "invalid_request_uri" {
		t.Errorf("error=%q want invalid_request_uri (body=%v)", got, body)
	}
}

// TestScenario_PAR_027_RequestUriLifecycleErrors verifies that an
// /authorize request carrying an unknown request_uri (never issued by
// /par) is rejected with 400 invalid_request_uri. The "consumed"
// branch of the same code path is covered by PAR-014 / PAR-026; the
// "expired" branch shares a single store gate (Find returns
// ErrNotFound once the record is GC'd) and is therefore equivalent to
// the unknown-uri path on the wire.
//
// State preservation is NOT asserted: v1.0 renders the PAR-resolution
// failure as a pre-redirect-trust browser error envelope (no state
// echo), because the request_uri parameter is the only client_id-bound
// witness on /authorize and its rejection means the OP cannot trust
// any other parameter to be intact.
//
// Spec: RFC 9126 §2.2 / RFC 9101 §6.2.
func TestScenario_PAR_027_RequestUriLifecycleErrors(t *testing.T) {
	t.Parallel()

	f := newPARPlainFixture(t)
	resp := getAuthorizePAR(t, f.tk, f.client.ID,
		"urn:ietf:params:oauth:request_uri:never-issued-12345")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	body := decodeJSONResp(t, resp)
	if got, _ := body["error"].(string); got != "invalid_request_uri" {
		t.Errorf("error=%q want invalid_request_uri (body=%v)", got, body)
	}
}

// getAuthorizePAR issues a GET /authorize?client_id=...&request_uri=...
// against tk. It mirrors the helper in
// internal/parendpoint/end_to_end_test.go but is private to the
// scenarios package so the black-box scope stays intact.
func getAuthorizePAR(t *testing.T, tk *testkit.Provider, clientID, requestURI string) *http.Response {
	t.Helper()
	values := url.Values{"client_id": {clientID}, "request_uri": {requestURI}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		tk.Server.URL+"/oidc/auth?"+values.Encode(), http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest /authorize: %v", err)
	}
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("Do /authorize: %v", err)
	}
	return resp
}
