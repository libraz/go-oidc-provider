package scenarios_test

// Catalog: test/scenarios/catalog/client_auth.yaml (CA-<sub>-NNN)
// Spec:
//   - RFC 6749 §2.3, §5.2 — Client Authentication
//   - RFC 6749 Appendix B — application/x-www-form-urlencoded encoding
//   - RFC 7521 — Assertion Framework
//   - RFC 7523 — JWT Profile for Client Authentication
//   - RFC 8705 §2 — OAuth 2.0 Mutual-TLS Client Authentication
//   - RFC 7591 — Dynamic Client Registration
//   - OIDC Core 1.0 §9 — Client Authentication
//   - draft-ietf-oauth-attestation-based-client-auth

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

// scenarioAuditCapture wraps a slog logger that emits audit events
// as JSON records into a bytes.Buffer. Tests that assert on emitted
// audit events build a Provider through this capture so the wire
// layout observed by an embedder's slog handler is what the test
// sees. Mirrors the helper in [internal/tokenendpoint/audit_test.go]
// so a reader who knows that suite can navigate here without
// re-learning the capture surface.
type scenarioAuditCapture struct {
	mu  sync.Mutex
	buf *bytes.Buffer
}

func newScenarioAuditCapture() *scenarioAuditCapture {
	return &scenarioAuditCapture{buf: &bytes.Buffer{}}
}

func (c *scenarioAuditCapture) logger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(&lockedWriter{c: c}, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

func (c *scenarioAuditCapture) findEvents(name string) []map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []map[string]any
	dec := json.NewDecoder(strings.NewReader(c.buf.String()))
	for dec.More() {
		var rec map[string]any
		if err := dec.Decode(&rec); err != nil {
			return out
		}
		if rec["audit"] != "true" {
			continue
		}
		if rec["event"] == name {
			out = append(out, rec)
		}
	}
	return out
}

func (c *scenarioAuditCapture) dump() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

// lockedWriter serialises slog writes against scenarioAuditCapture's
// buffer so concurrent emissions during table-driven sub-tests do not
// produce interleaved JSON lines.
type lockedWriter struct {
	c *scenarioAuditCapture
}

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.c.mu.Lock()
	defer w.c.mu.Unlock()
	return w.c.buf.Write(p)
}

// caTokenResponse captures the wire shape every CA-* assertion needs:
// HTTP status, the parsed JSON envelope, the WWW-Authenticate challenge
// header (relevant to CA-COMMON-06), and the cache-control envelope
// RFC 6749 §5.1 / OIDC Core §3.1.3.4 require on every token-endpoint
// response (relevant to CA-COMMON-07).
type caTokenResponse struct {
	StatusCode   int
	Body         map[string]any
	WWWAuth      string
	CacheControl string
	Pragma       string
}

// postTokenForm POSTs form to /oidc/token after letting decorate mutate
// the request (e.g. to set Authorization: Basic). It does not fail the
// test on a non-2xx status because the CA-* suite is intentionally
// driving error paths.
func postTokenForm(t *testing.T, tk *testkit.Provider, form url.Values, decorate func(*http.Request)) caTokenResponse {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build /token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if decorate != nil {
		decorate(req)
	}
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /token body: %v", err)
	}
	out := caTokenResponse{
		StatusCode:   resp.StatusCode,
		WWWAuth:      resp.Header.Get("WWW-Authenticate"),
		CacheControl: resp.Header.Get("Cache-Control"),
		Pragma:       resp.Header.Get("Pragma"),
	}
	out.Body = map[string]any{}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &out.Body); err != nil {
			t.Fatalf("body is not JSON: %v (raw=%q)", err, string(body))
		}
	}
	return out
}

// registerCASecretClient seeds a confidential client with the supplied
// auth method, hashing secret with the public op helper.
func registerCASecretClient(t *testing.T, tk *testkit.Provider, id, secret, method string) {
	t.Helper()
	hash, err := op.HashClientSecret(secret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      id,
		SecretHash:              hash,
		TokenEndpointAuthMethod: method,
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
	})
}

// pkjwtKeypair bundles a freshly-generated ES256 keypair with the JWK
// metadata the OP needs to resolve and verify assertions signed under
// it. CA-PKJWT tests build one per scenario so the private key never
// leaves the test goroutine and the public JWK lands on the registered
// client through [testkit.ClientFixture.JWKs].
type pkjwtKeypair struct {
	priv *ecdsa.PrivateKey
	kid  string
	alg  josev4.SignatureAlgorithm
}

// newPKJWTKeypair generates a fresh ES256 keypair for a CA-PKJWT test.
// It uses crypto/rand and crypto/ecdsa directly because the testkit's
// [Provider.SignedJWT] helper signs with the OP's key, which is the
// wrong end of the trust relationship for client_assertion (the *client*
// signs, the OP verifies).
func newPKJWTKeypair(t *testing.T, kid string) *pkjwtKeypair {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	return &pkjwtKeypair{priv: priv, kid: kid, alg: josev4.ES256}
}

// PublicJWKSet returns the JSON-encoded JWK Set the test should hand to
// [testkit.ClientFixture.JWKs]. Only the public key is exported.
func (p *pkjwtKeypair) PublicJWKSet(t *testing.T) json.RawMessage {
	t.Helper()
	jwk := josev4.JSONWebKey{
		Key:       p.priv.Public(),
		KeyID:     p.kid,
		Algorithm: string(p.alg),
		Use:       "sig",
	}
	set := josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{jwk}}
	raw, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}
	return raw
}

// signedClientAssertion serialises claims as a compact JWS using key
// (private) and the supplied alg / kid. Tests use it to drive both the
// happy path (kp.priv signs, public JWK is registered) and the unhappy
// paths (drop a claim, sign with the wrong key, set an unsupported alg).
//
// The kid header is set unconditionally so CA-PKJWT-06 can override it
// to "no-such-kid" without changing the helper's signature.
func signedClientAssertion(t *testing.T, kp *pkjwtKeypair, claims map[string]any) string {
	t.Helper()
	return signedClientAssertionWithKID(t, kp, kp.kid, claims)
}

// signedClientAssertionWithKID is signedClientAssertion with an
// explicit "kid" override. CA-PKJWT-06 uses it to drive the
// "kid points at no key in the registered JWKS" path.
func signedClientAssertionWithKID(t *testing.T, kp *pkjwtKeypair, kid string, claims map[string]any) string {
	t.Helper()
	signer, err := josev4.NewSigner(
		josev4.SigningKey{
			Algorithm: kp.alg,
			Key: josev4.JSONWebKey{
				Key:       kp.priv,
				KeyID:     kid,
				Algorithm: string(kp.alg),
				Use:       "sig",
			},
		},
		(&josev4.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	out, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize: %v", err)
	}
	return out
}

// signedHS256Assertion serialises claims as an HS256 JWS using a
// caller-supplied symmetric secret. CA-PKJWT-01 / CA-PKJWT-11 use it to
// verify the OP rejects shared-secret JWTs even when the attacker
// successfully signs the assertion: the OP's JOSE allow-list refuses
// HS256 at parse time and never reaches a key-resolution stage.
func signedHS256Assertion(t *testing.T, secret []byte, kid string, claims map[string]any) string {
	t.Helper()
	signer, err := josev4.NewSigner(
		josev4.SigningKey{
			Algorithm: josev4.HS256,
			Key: josev4.JSONWebKey{
				Key:       secret,
				KeyID:     kid,
				Algorithm: string(josev4.HS256),
				Use:       "sig",
			},
		},
		(&josev4.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatalf("NewSigner(HS256): %v", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("Sign(HS256): %v", err)
	}
	out, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize(HS256): %v", err)
	}
	return out
}

// pkjwtAudiences returns the audience values the OP advertises for
// private_key_jwt assertions: the absolute token endpoint URL (the
// OIDC Core §9 default) and the issuer URL (the FAPI 2.0 §5.2.2 form
// the verifier accepts via AuxAudiences). The token URL is built
// from tk.Issuer (NOT tk.Server.URL) because op.absoluteEndpointURL
// joins issuer + mount prefix + endpoint to mirror the discovery
// document. tk.Server.URL is the loopback host the httptest server
// bound to, which the OP never names in any audience claim.
func pkjwtAudiences(tk *testkit.Provider) (tokenURL, issuer string) {
	return tk.Issuer + "/oidc/token", tk.Issuer
}

// pkjwtClaims builds the standard claim set every CA-PKJWT test starts
// from. Tests mutate the returned map (drop a key, swap a value) before
// signing.
func pkjwtClaims(clientID, audience string, now time.Time) map[string]any {
	return map[string]any{
		"iss": clientID,
		"sub": clientID,
		"aud": audience,
		"jti": clientID + "-" + now.UTC().Format("20060102T150405.000000000"),
		"iat": now.Unix(),
		"exp": now.Add(2 * time.Minute).Unix(),
	}
}

// fixedClock is a non-advancing [op.Clock] for CA-PKJWT-08. The struct
// is local because the file already declares a different clock helper
// type elsewhere; keep them apart so neither test grows accidental
// shared state.
type pkjwtFixedClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *pkjwtFixedClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// registerPKJWTClient seeds a confidential client whose
// token_endpoint_auth_method is private_key_jwt and whose JWKs is the
// public half of kp. The signing flow then becomes "test signs with
// kp.priv → OP resolves public via store.Client.JWKs → verify".
func registerPKJWTClient(t *testing.T, tk *testkit.Provider, id string, kp *pkjwtKeypair) {
	t.Helper()
	//nolint:gosec // G101 false positive: "private_key_jwt" is the OIDC auth-method name, not a credential.
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      id,
		TokenEndpointAuthMethod: "private_key_jwt",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		JWKs:                    kp.PublicJWKSet(t),
	})
}

// postPKJWTAssertion POSTs a /token request whose only credentials are
// client_assertion / client_assertion_type. grant_type/code default to
// the "fake authorization_code" shape every CA-PKJWT test uses to
// distinguish "auth passed" (invalid_grant) from "auth failed"
// (invalid_client).
func postPKJWTAssertion(t *testing.T, tk *testkit.Provider, assertion string, extra url.Values) caTokenResponse {
	t.Helper()
	form := url.Values{
		"grant_type":            {"authorization_code"},
		"code":                  {"never-issued"},
		"redirect_uri":          {"https://rp.testkit.invalid/callback"},
		"client_assertion":      {assertion},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
	}
	for k, vs := range extra {
		form[k] = vs
	}
	return postTokenForm(t, tk, form, nil)
}

// requireInvalidClient fails the test unless resp shows the canonical
// "client authentication failed" wire shape: 401 + error=invalid_client.
// The description is checked to NOT echo the implementation detail
// extra (e.g. "no matching key", "iss mismatch") so CA-PKJWT does not
// regress the security-driven generic wording the secret methods use.
func requireInvalidClient(t *testing.T, resp caTokenResponse, leakSubstrings ...string) {
	t.Helper()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 body=%v", resp.StatusCode, resp.Body)
	}
	if got, _ := resp.Body["error"].(string); got != "invalid_client" {
		t.Fatalf("error=%q want invalid_client (body=%v)", got, resp.Body)
	}
	desc, _ := resp.Body["error_description"].(string)
	for _, leak := range leakSubstrings {
		if leak == "" {
			continue
		}
		if strings.Contains(strings.ToLower(desc), strings.ToLower(leak)) {
			t.Errorf("error_description=%q must not echo %q", desc, leak)
		}
	}
}

// requireAuthPassedFakeCode fails the test unless resp shows "client
// auth verified, but the supplied authorization_code is not real": 400
// + error=invalid_grant. CA-PKJWT-01 / -04 / -05 / -07 / -09 (the
// happy-path subtests) use this assertion to confirm authentication
// succeeded without driving a full code/PKCE flow.
func requireAuthPassedFakeCode(t *testing.T, resp caTokenResponse) {
	t.Helper()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 (invalid_grant) body=%v", resp.StatusCode, resp.Body)
	}
	if got, _ := resp.Body["error"].(string); got != "invalid_grant" {
		t.Fatalf("error=%q want invalid_grant (body=%v)", got, resp.Body)
	}
}

// TestScenario_CA_COMMON_01_NoMechanismProvidedRejected drives /token
// with grant_type=authorization_code but neither an Authorization
// header nor body credentials. RFC 6749 §5.2 lists "no client
// authentication included" under invalid_client; the OP returns
// 401 invalid_client and routes the description through the generic
// "client authentication required" template so the response shape
// does not leak whether the request also lacked grant_type or code.
//
// Spec: RFC 6749 §5.2.
func TestScenario_CA_COMMON_01_NoMechanismProvidedRejected(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	resp := postTokenForm(t, tk, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"never-issued"},
		"redirect_uri": {"https://rp.testkit.invalid/callback"},
	}, nil)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 body=%v", resp.StatusCode, resp.Body)
	}
	if got, _ := resp.Body["error"].(string); got != "invalid_client" {
		t.Errorf("error=%q want invalid_client (body=%v)", got, resp.Body)
	}
	desc, _ := resp.Body["error_description"].(string)
	if !strings.Contains(strings.ToLower(desc), "client authentication") {
		t.Errorf("error_description=%q must name client authentication", desc)
	}
}

// TestScenario_CA_COMMON_02_UnknownClientIDRejected sends valid Basic
// credentials for a client_id the store does not know. RFC 6749 §5.2
// requires 401 invalid_client. The OP runs the dummy-verify timing
// shim before responding so the latency channel cannot reveal whether
// the client existed.
//
// Spec: RFC 6749 §5.2.
func TestScenario_CA_COMMON_02_UnknownClientIDRejected(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	resp := postTokenForm(t, tk, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"never-issued"},
		"redirect_uri": {"https://rp.testkit.invalid/callback"},
	}, func(r *http.Request) {
		r.SetBasicAuth("ca-common-02-unknown", "doesnotmatter")
	})

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 body=%v", resp.StatusCode, resp.Body)
	}
	if got, _ := resp.Body["error"].(string); got != "invalid_client" {
		t.Errorf("error=%q want invalid_client (body=%v)", got, resp.Body)
	}
}

// TestScenario_CA_COMMON_03_DoubleMechanismRejected presents both
// Authorization: Basic and a client_secret in the body. RFC 6749 §2.3
// forbids combining mechanisms; the OP returns 400 invalid_request so
// downstream auth code never runs.
//
// Spec: RFC 6749 §2.3.
func TestScenario_CA_COMMON_03_DoubleMechanismRejected(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	const (
		clientID = "ca-common-03"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "ca-common-03-secret"
	registerCASecretClient(t, tk, clientID, clientSecret, "client_secret_basic")

	resp := postTokenForm(t, tk, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"never-issued"},
		"redirect_uri":  {"https://rp.testkit.invalid/callback"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}, func(r *http.Request) {
		r.SetBasicAuth(clientID, clientSecret)
	})

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", resp.StatusCode, resp.Body)
	}
	if got, _ := resp.Body["error"].(string); got != "invalid_request" {
		t.Errorf("error=%q want invalid_request (body=%v)", got, resp.Body)
	}
}

// TestScenario_CA_COMMON_04_RegisteredMethodMismatchRejected drives a
// client registered with token_endpoint_auth_method=client_secret_post
// using HTTP Basic. The OP rejects with 401 invalid_client without
// disclosing in the description that the registered method differs;
// see internal/clientauth/verify.go methodAllowedForClient.
//
// Spec: RFC 6749 §2.3 / OIDC Core §9.
func TestScenario_CA_COMMON_04_RegisteredMethodMismatchRejected(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	const clientID = "ca-common-04"
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "ca-common-04-secret"
	registerCASecretClient(t, tk, clientID, clientSecret, "client_secret_post")

	resp := postTokenForm(t, tk, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"never-issued"},
		"redirect_uri": {"https://rp.testkit.invalid/callback"},
	}, func(r *http.Request) {
		r.SetBasicAuth(clientID, clientSecret)
	})

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 body=%v", resp.StatusCode, resp.Body)
	}
	if got, _ := resp.Body["error"].(string); got != "invalid_client" {
		t.Errorf("error=%q want invalid_client (body=%v)", got, resp.Body)
	}
}

// TestScenario_CA_COMMON_05_BodyClientIDMismatchRejected presents a
// Basic header for client A while the body sets client_id to B. The
// parser detects the disagreement at the channel-reconciliation step
// (clientauth/parse.go pickClientID) and returns ErrClientMismatch,
// which the HTTP layer collapses onto 401 invalid_client so the
// caller cannot tell which channel held the canonical id.
//
// Spec: RFC 6749 §2.3.1 / §5.2.
func TestScenario_CA_COMMON_05_BodyClientIDMismatchRejected(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	const clientID = "ca-common-05"
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "ca-common-05-secret"
	registerCASecretClient(t, tk, clientID, clientSecret, "client_secret_basic")

	resp := postTokenForm(t, tk, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"never-issued"},
		"redirect_uri": {"https://rp.testkit.invalid/callback"},
		"client_id":    {"ca-common-05-other"},
	}, func(r *http.Request) {
		r.SetBasicAuth(clientID, clientSecret)
	})

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 body=%v", resp.StatusCode, resp.Body)
	}
	if got, _ := resp.Body["error"].(string); got != "invalid_client" {
		t.Errorf("error=%q want invalid_client (body=%v)", got, resp.Body)
	}
}

// TestScenario_CA_COMMON_06_BasicChallengeOnlyOnBasicFailure sweeps
// three failure mechanisms — HTTP Basic, client_secret_post body, and
// private_key_jwt assertion — and asserts that only the Basic-mode
// failure carries a "Basic" WWW-Authenticate challenge. CA-ERR-01
// already locks the Basic / Post pair on the same handler; this row
// extends the property to the third mechanism v1.0 ships
// (private_key_jwt) so a future refactor that accidentally stamped the
// challenge on every invalid_client path is caught here.
//
// Spec: RFC 6749 §5.2.
func TestScenario_CA_COMMON_06_BasicChallengeOnlyOnBasicFailure(t *testing.T) {
	t.Parallel()

	t.Run("Basic", func(t *testing.T) {
		t.Parallel()
		tk := testkit.NewProvider(t)
		const clientID = "ca-common-06-basic"
		//nolint:gosec // test fixture: not a real credential.
		const clientSecret = "ca-common-06-basic-secret"
		registerCASecretClient(t, tk, clientID, clientSecret, "client_secret_basic")

		resp := postTokenForm(t, tk, url.Values{
			"grant_type":   {"authorization_code"},
			"code":         {"never-issued"},
			"redirect_uri": {"https://rp.testkit.invalid/callback"},
		}, func(r *http.Request) {
			r.SetBasicAuth(clientID, "wrong-secret")
		})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status=%d want 401 body=%v", resp.StatusCode, resp.Body)
		}
		if !strings.HasPrefix(strings.ToLower(resp.WWWAuth), "basic ") {
			t.Errorf("WWW-Authenticate=%q want Basic challenge after Basic-auth failure", resp.WWWAuth)
		}
	})

	t.Run("Post", func(t *testing.T) {
		t.Parallel()
		tk := testkit.NewProvider(t)
		const clientID = "ca-common-06-post"
		//nolint:gosec // test fixture: not a real credential.
		const clientSecret = "ca-common-06-post-secret"
		registerCASecretClient(t, tk, clientID, clientSecret, "client_secret_post")

		resp := postTokenForm(t, tk, url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {"never-issued"},
			"redirect_uri":  {"https://rp.testkit.invalid/callback"},
			"client_id":     {clientID},
			"client_secret": {"wrong-secret"},
		}, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status=%d want 401 body=%v", resp.StatusCode, resp.Body)
		}
		if resp.WWWAuth != "" {
			t.Errorf("WWW-Authenticate=%q want empty after form-based auth failure", resp.WWWAuth)
		}
	})

	t.Run("PrivateKeyJWT", func(t *testing.T) {
		t.Parallel()
		tk := testkit.NewProvider(t)
		const clientID = "ca-common-06-pkjwt"
		kp := newPKJWTKeypair(t, "kid-ca-common-06")
		registerPKJWTClient(t, tk, clientID, kp)

		// Sign with a foreign keypair so verification fails (the
		// client's registered JWKS does not contain this key).
		foreign := newPKJWTKeypair(t, "kid-ca-common-06")
		tokenURL, _ := pkjwtAudiences(tk)
		claims := pkjwtClaims(clientID, tokenURL, time.Now())
		assertion := signedClientAssertion(t, foreign, claims)

		resp := postPKJWTAssertion(t, tk, assertion, url.Values{"client_id": {clientID}})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status=%d want 401 body=%v", resp.StatusCode, resp.Body)
		}
		if got, _ := resp.Body["error"].(string); got != "invalid_client" {
			t.Fatalf("error=%q want invalid_client (body=%v)", got, resp.Body)
		}
		if resp.WWWAuth != "" {
			t.Errorf("WWW-Authenticate=%q want empty after private_key_jwt failure", resp.WWWAuth)
		}
	})
}

// TestScenario_CA_COMMON_07_ErrorResponsePreservesNoStore exercises a
// failing /token request and asserts that the error response carries
// the cache-control envelope OIDC Core §3.1.3.4 / RFC 6749 §5.1
// require on every token-endpoint response. A token-bearing failure
// envelope MUST NOT be cached by intermediaries; stampNoStore
// (internal/tokenendpoint/error.go) sets both Cache-Control: no-store
// and Pragma: no-cache, and this row pins both so the headers stay
// synchronised with the success path.
//
// Spec: OIDC Core §3.1.3.4 / RFC 6749 §5.1.
func TestScenario_CA_COMMON_07_ErrorResponsePreservesNoStore(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	resp := postTokenForm(t, tk, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"never-issued"},
		"redirect_uri": {"https://rp.testkit.invalid/callback"},
	}, func(r *http.Request) {
		r.SetBasicAuth("ca-common-07-unknown", "doesnotmatter")
	})

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 body=%v", resp.StatusCode, resp.Body)
	}
	if resp.CacheControl != "no-store" {
		t.Errorf("Cache-Control=%q want no-store", resp.CacheControl)
	}
	if resp.Pragma != "no-cache" {
		t.Errorf("Pragma=%q want no-cache", resp.Pragma)
	}
}

// TestScenario_CA_NONE_01_NoneClientAuthenticatesByClientID drives a
// full authorization_code → /token round-trip for a public client
// registered with token_endpoint_auth_method=none. The /token request
// carries client_id only (no Authorization header, no client_secret),
// so the OP authenticates the request as MethodNone and emits a
// 200 envelope with access_token + id_token.
//
// Spec: RFC 6749 §2.3.
func TestScenario_CA_NONE_01_NoneClientAuthenticatesByClientID(t *testing.T) {
	t.Parallel()

	const (
		clientID = "ca-none-01"
		callback = "https://rp.testkit.invalid/callback"
	)

	tk := testkit.NewProvider(t)
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:           clientID,
		RedirectURIs: []string{callback},
		PublicClient: true,
		Scopes:       []string{"openid", "profile", "email"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
	})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		PKCE:        pkce,
	})
	if flow.Error != "" {
		t.Fatalf("authorize error=%s desc=%s", flow.Error, flow.ErrorDesc)
	}
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}

	// ExchangeCode only sets Basic when both ClientID AND ClientSecret
	// are populated; the helper also doesn't echo ClientID into the
	// body, so we route the public-client identity through Extra to
	// drive the canonical "none" shape (body-only client_id, no
	// Authorization header, no client_secret).
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:        flow.Code,
		RedirectURI: callback,
		Verifier:    pkce.Verifier,
		Extra:       url.Values{"client_id": {rp.ID}},
	})
	if tok.StatusCode != http.StatusOK {
		t.Fatalf("/token status=%d body=%v, want 200", tok.StatusCode, tok.Raw)
	}
	if tok.AccessToken == "" {
		t.Errorf("access_token missing from /token envelope: %v", tok.Raw)
	}
	if tok.IDToken == "" {
		t.Errorf("id_token missing from /token envelope: %v", tok.Raw)
	}
	if tok.TokenType != "Bearer" {
		t.Errorf("token_type=%q want Bearer", tok.TokenType)
	}
}

// TestScenario_CA_NONE_02_NoneClientWithSecretRejected registers a
// public client (token_endpoint_auth_method=none) and presents a
// client_secret on /token. The OP runs methodAllowedForClient, which
// rejects every secret-bearing method on a public client, and returns
// 401 invalid_client with the generic "client authentication failed"
// shape rather than a "method mismatch" hint that would betray the
// registered method.
//
// Spec: RFC 6749 §2.3.
func TestScenario_CA_NONE_02_NoneClientWithSecretRejected(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	const clientID = "ca-none-02"
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:           clientID,
		RedirectURIs: []string{"https://rp.testkit.invalid/callback"},
		PublicClient: true,
		GrantTypes:   []string{"authorization_code", "refresh_token"},
	})

	resp := postTokenForm(t, tk, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"never-issued"},
		"redirect_uri": {"https://rp.testkit.invalid/callback"},
	}, func(r *http.Request) {
		// Use a fabricated secret; the registered method is none, so
		// the OP must reject before any cryptographic check runs.
		r.SetBasicAuth(clientID, "anything")
	})

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 body=%v", resp.StatusCode, resp.Body)
	}
	if got, _ := resp.Body["error"].(string); got != "invalid_client" {
		t.Errorf("error=%q want invalid_client (body=%v)", got, resp.Body)
	}
	desc, _ := resp.Body["error_description"].(string)
	if strings.Contains(strings.ToLower(desc), "method mismatch") {
		t.Errorf("error_description=%q must not leak 'method mismatch' detail", desc)
	}
}

// TestScenario_CA_NONE_03_NoneClientNotAllowedForConfidentialFlows
// registers a public client (token_endpoint_auth_method=none) whose
// GrantTypes nominally include client_credentials and asserts that a
// client_credentials request is rejected with 400 unauthorized_client
// (RFC 6749 §5.2: "the authenticated client is not authorized to use
// this authorization grant type"). The auth layer admits MethodNone
// for the public client; the grant authorizer
// (internal/grants/clientcred) then refuses on PublicClient=true,
// which is the structural counterpart to RFC 6749 §2.1's "public
// clients MUST NOT use grants reserved for confidential clients".
//
// Spec: RFC 6749 §2.1 / §5.2.
func TestScenario_CA_NONE_03_NoneClientNotAllowedForConfidentialFlows(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	const clientID = "ca-none-03"
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:           clientID,
		RedirectURIs: []string{"https://rp.testkit.invalid/callback"},
		PublicClient: true,
		GrantTypes:   []string{"authorization_code", "client_credentials"},
		Scopes:       []string{"openid", "api"},
	})

	resp := postTokenForm(t, tk, url.Values{
		"grant_type": {"client_credentials"},
		"client_id":  {clientID},
		"scope":      {"api"},
	}, nil)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", resp.StatusCode, resp.Body)
	}
	if got, _ := resp.Body["error"].(string); got != "unauthorized_client" {
		t.Errorf("error=%q want unauthorized_client (body=%v)", got, resp.Body)
	}
}

// TestScenario_CA_BASIC_01_WellFormedBasicHeaderAccepted drives a
// full code → /token round-trip for a confidential client registered
// with token_endpoint_auth_method=client_secret_basic. The /token
// request carries Authorization: Basic <base64(client_id:secret)>;
// the OP authenticates the request as MethodSecretBasic and returns
// a 200 envelope.
//
// Spec: RFC 6749 §2.3.1.
func TestScenario_CA_BASIC_01_WellFormedBasicHeaderAccepted(t *testing.T) {
	t.Parallel()

	const (
		clientID = "ca-basic-01"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "ca-basic-01-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t)
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
	})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		PKCE:        pkce,
	})
	if flow.Error != "" {
		t.Fatalf("authorize error=%s desc=%s", flow.Error, flow.ErrorDesc)
	}
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}

	// ExchangeCode sets Basic via req.SetBasicAuth when both ClientID
	// and ClientSecret are populated.
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     rp.ID,
		ClientSecret: clientSecret,
	})
	if tok.StatusCode != http.StatusOK {
		t.Fatalf("/token status=%d body=%v, want 200", tok.StatusCode, tok.Raw)
	}
	if tok.AccessToken == "" {
		t.Errorf("access_token missing: %v", tok.Raw)
	}
	if tok.IDToken == "" {
		t.Errorf("id_token missing: %v", tok.Raw)
	}
	if tok.TokenType != "Bearer" {
		t.Errorf("token_type=%q want Bearer", tok.TokenType)
	}
}

// TestScenario_CA_BASIC_02_BasicWithMatchingBodyClientID drives a
// /token request that carries Authorization: Basic AND a body
// client_id whose value equals the Basic header's user. The parser's
// pickClientID step (clientauth/parse.go) reconciles the two channels
// and accepts when they agree; the request then takes the
// MethodSecretBasic path and authentication succeeds. The wire signal
// for "auth passed" is "the response is NOT invalid_client" — we use
// the fake-code shape so a downstream invalid_grant lands instead of
// minting real tokens. The mismatching counterpart is CA-COMMON-05 /
// CA-BASIC-05.
//
// Spec: RFC 6749 §2.3.1.
func TestScenario_CA_BASIC_02_BasicWithMatchingBodyClientID(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	const clientID = "ca-basic-02"
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "ca-basic-02-secret"
	registerCASecretClient(t, tk, clientID, clientSecret, "client_secret_basic")

	resp := postTokenForm(t, tk, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"never-issued"},
		"redirect_uri": {"https://rp.testkit.invalid/callback"},
		"client_id":    {clientID},
	}, func(r *http.Request) {
		r.SetBasicAuth(clientID, clientSecret)
	})

	if got, _ := resp.Body["error"].(string); got == "invalid_client" {
		t.Fatalf("matching client_id values must authenticate; got invalid_client body=%v", resp.Body)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 invalid_grant (auth passed, code bogus); body=%v",
			resp.StatusCode, resp.Body)
	}
	if got, _ := resp.Body["error"].(string); got != "invalid_grant" {
		t.Errorf("error=%q want invalid_grant (auth passed); body=%v", got, resp.Body)
	}
}

// TestScenario_CA_BASIC_03_BasicAcceptedForPostRegisteredClient is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_BASIC_03_BasicAcceptedForPostRegisteredClient(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-BASIC-03 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_BASIC_04_AppendixBFormURLEncoding pins the Appendix B
// encoding rule on HTTP Basic credentials: client_id and client_secret
// MUST be application/x-www-form-urlencoded before being joined with
// ":" and base64-encoded. Credentials containing %, &, +, and space
// authenticate successfully under that encoding because the OP
// form-url-decodes each side after the base64 split. A registry value
// that contains a literal "+" arrives at the OP encoded as "%2B"; an
// untransformed "+" decodes to a space, so the wire shape and the
// stored shape differ unless the client encoded properly.
//
// Spec: RFC 6749 §2.3.1 / Appendix B.
func TestScenario_CA_BASIC_04_AppendixBFormURLEncoding(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		clientID string
		secret   string
	}{
		{
			name:     "SpaceInSecret",
			clientID: "ca-basic-04-space",
			secret:   "secret with space",
		},
		{
			name:     "AmpersandInSecret",
			clientID: "ca-basic-04-amp",
			secret:   "secret&with&amp",
		},
		{
			name:     "PercentInSecret",
			clientID: "ca-basic-04-pct",
			secret:   "secret%with%pct",
		},
		{
			name:     "PlusInSecret",
			clientID: "ca-basic-04-plus",
			secret:   "secret+with+plus",
		},
		//nolint:gosec // G101 false positive: dummy fixture secret consumed only by the in-process testkit.
		{
			name:     "SpaceAndPlusInClientID",
			clientID: "ca-basic 04+id",
			secret:   "ca-basic-04-secret",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tk := testkit.NewProvider(t)
			registerCASecretClient(t, tk, tc.clientID, tc.secret, "client_secret_basic")

			form := url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {"opaque-refresh-token-never-reached"},
			}
			// req.SetBasicAuth applies application/x-www-form-urlencoded
			// to neither side; manually encode per Appendix B so the OP
			// receives the canonical RFC 6749 §2.3.1 wire shape.
			encodedID := url.QueryEscape(tc.clientID)
			encodedSecret := url.QueryEscape(tc.secret)
			cred := encodedID + ":" + encodedSecret
			authValue := "Basic " + base64.StdEncoding.EncodeToString([]byte(cred))

			resp := postTokenForm(t, tk, form, func(req *http.Request) {
				req.Header.Set("Authorization", authValue)
			})

			// Authentication succeeds → the request reaches the
			// refresh-token resolution path, where the bogus token
			// fails with 400 invalid_grant. The wire signal that
			// authentication PASSED is "the response is NOT
			// invalid_client". An Appendix-B-broken decoder would
			// instead fail with 401 invalid_client because the
			// secret would not match.
			gotErr, _ := resp.Body["error"].(string)
			if gotErr == "invalid_client" {
				t.Fatalf("authentication failed with invalid_client (status=%d, body=%v); credentials of shape %q/%q must succeed under Appendix B form-url-decoding",
					resp.StatusCode, resp.Body, tc.clientID, tc.secret)
			}
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status=%d want 400 invalid_grant (auth passed, refresh token bogus); body=%v",
					resp.StatusCode, resp.Body)
			}
			if gotErr != "invalid_grant" {
				t.Errorf("error=%q want invalid_grant (auth passed); body=%v", gotErr, resp.Body)
			}
		})
	}
}

// TestScenario_CA_BASIC_05_BasicHeaderBodyClientIDMismatch presents
// HTTP Basic for the registered client and a different client_id in
// the body. The parser detects the disagreement at
// clientauth/parse.go pickClientID and returns ErrClientMismatch,
// which the HTTP layer collapses onto 401 invalid_client; the
// response intentionally does not name which channel held the
// canonical id. This is the Basic-only counterpart to CA-COMMON-05.
//
// Spec: RFC 6749 §2.3.1 / §5.2.
func TestScenario_CA_BASIC_05_BasicHeaderBodyClientIDMismatch(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	const clientID = "ca-basic-05"
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "ca-basic-05-secret"
	registerCASecretClient(t, tk, clientID, clientSecret, "client_secret_basic")

	resp := postTokenForm(t, tk, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"never-issued"},
		"redirect_uri": {"https://rp.testkit.invalid/callback"},
		"client_id":    {"ca-basic-05-other"},
	}, func(r *http.Request) {
		r.SetBasicAuth(clientID, clientSecret)
	})

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 body=%v", resp.StatusCode, resp.Body)
	}
	if got, _ := resp.Body["error"].(string); got != "invalid_client" {
		t.Errorf("error=%q want invalid_client (body=%v)", got, resp.Body)
	}
}

// TestScenario_CA_BASIC_06_ImproperlyEncodedBasicHeader sends an
// Authorization: Basic header whose payload is not valid base64. Go
// stdlib's r.BasicAuth() returns hasBasic=false in that case, so the
// parser sees no credentials at all → MethodNone → ErrNoCredentials,
// and the HTTP layer responds with 401 invalid_client carrying the
// generic "client authentication required" description. The wire
// shape is identical to "no Authorization header at all", which is
// the intended privacy property: a probe of malformed headers learns
// nothing about how the OP would have parsed a valid one.
//
// Spec: RFC 6749 §2.3.1 / §5.2 / Appendix B.
func TestScenario_CA_BASIC_06_ImproperlyEncodedBasicHeader(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	resp := postTokenForm(t, tk, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"never-issued"},
		"redirect_uri": {"https://rp.testkit.invalid/callback"},
	}, func(r *http.Request) {
		// "@@@" is not valid base64 — Go's r.BasicAuth() therefore
		// reports hasBasic=false, dropping the request onto the
		// MethodNone path.
		r.Header.Set("Authorization", "Basic @@@not-base64@@@")
	})

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 body=%v", resp.StatusCode, resp.Body)
	}
	if got, _ := resp.Body["error"].(string); got != "invalid_client" {
		t.Errorf("error=%q want invalid_client (body=%v)", got, resp.Body)
	}
	desc, _ := resp.Body["error_description"].(string)
	if !strings.Contains(strings.ToLower(desc), "client authentication") {
		t.Errorf("error_description=%q must name client authentication", desc)
	}
}

// TestScenario_CA_BASIC_07_NonBasicSchemeRejected sends an
// Authorization header whose scheme is not Basic (here, "Bearer
// xyz"). Go stdlib's r.BasicAuth() recognises only the Basic scheme
// and returns hasBasic=false otherwise, so the request lands on the
// MethodNone path → ErrNoCredentials → 401 invalid_client with the
// generic "client authentication required" description. The OP
// intentionally never echoes the offending scheme so a caller cannot
// enumerate accepted schemes via probing.
//
// Spec: RFC 6749 §2.3.1 / §5.2 / RFC 7235.
func TestScenario_CA_BASIC_07_NonBasicSchemeRejected(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	resp := postTokenForm(t, tk, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"never-issued"},
		"redirect_uri": {"https://rp.testkit.invalid/callback"},
	}, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer not-a-bearer-token")
	})

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 body=%v", resp.StatusCode, resp.Body)
	}
	if got, _ := resp.Body["error"].(string); got != "invalid_client" {
		t.Errorf("error=%q want invalid_client (body=%v)", got, resp.Body)
	}
	desc, _ := resp.Body["error_description"].(string)
	if strings.Contains(strings.ToLower(desc), "bearer") {
		t.Errorf("error_description=%q must not echo offending scheme", desc)
	}
}

// TestScenario_CA_BASIC_08_EmptySecretInBasicRejected sends a
// well-formed Basic header whose payload is "client_id:" (no secret
// after the colon). Go stdlib's r.BasicAuth() returns hasBasic=true
// with secret="", so the request takes the MethodSecretBasic path
// and verifySecret runs the configured length-constant compare
// against the empty input. The compare fails and the OP returns
// 401 invalid_client with the generic "client authentication failed"
// description — identical to the wrong-secret response shape, which
// is the intended timing / oracle property.
//
// Spec: RFC 6749 §2.3.1 / §5.2.
func TestScenario_CA_BASIC_08_EmptySecretInBasicRejected(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	const clientID = "ca-basic-08"
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "ca-basic-08-secret"
	registerCASecretClient(t, tk, clientID, clientSecret, "client_secret_basic")

	// Build "client_id:" payload manually rather than rely on
	// SetBasicAuth, so the test documents the empty-secret shape.
	payload := base64.StdEncoding.EncodeToString([]byte(clientID + ":"))
	resp := postTokenForm(t, tk, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"never-issued"},
		"redirect_uri": {"https://rp.testkit.invalid/callback"},
	}, func(r *http.Request) {
		r.Header.Set("Authorization", "Basic "+payload)
	})

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 body=%v", resp.StatusCode, resp.Body)
	}
	if got, _ := resp.Body["error"].(string); got != "invalid_client" {
		t.Errorf("error=%q want invalid_client (body=%v)", got, resp.Body)
	}
}

// TestScenario_CA_BASIC_09_BasicSecretMismatchInvalidClient presents
// a Basic header whose username matches the registered client but
// whose password is wrong. The verifier runs the length-constant
// SecretVerifier compare, which rejects, and the OP returns
// 401 invalid_client with the generic "client authentication failed"
// description. The wire shape is identical to "unknown client",
// "method mismatch", and "empty secret" responses; that uniformity
// is the oracle-resistance property the catalog row asserts.
//
// Spec: RFC 6749 §5.2.
func TestScenario_CA_BASIC_09_BasicSecretMismatchInvalidClient(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	const clientID = "ca-basic-09"
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "ca-basic-09-secret"
	registerCASecretClient(t, tk, clientID, clientSecret, "client_secret_basic")

	resp := postTokenForm(t, tk, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"never-issued"},
		"redirect_uri": {"https://rp.testkit.invalid/callback"},
	}, func(r *http.Request) {
		r.SetBasicAuth(clientID, "ca-basic-09-WRONG-secret")
	})

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 body=%v", resp.StatusCode, resp.Body)
	}
	if got, _ := resp.Body["error"].(string); got != "invalid_client" {
		t.Errorf("error=%q want invalid_client (body=%v)", got, resp.Body)
	}
	desc, _ := resp.Body["error_description"].(string)
	if strings.Contains(strings.ToLower(desc), "secret") {
		t.Errorf("error_description=%q must not name the secret as the failing component", desc)
	}
}

// TestScenario_CA_BASIC_10_BasicSecretExpired is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_BASIC_10_BasicSecretExpired(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-BASIC-10 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_POST_01_FormBodyCredentialsAccepted drives a full
// code → /token round-trip for a confidential client registered with
// token_endpoint_auth_method=client_secret_post. The /token request
// carries client_id and client_secret in the form body (no
// Authorization header); the OP authenticates as MethodSecretPost
// and returns a 200 envelope. The scenariokit ExchangeCode helper
// always sets Basic when both values are populated, so this test
// builds the /token request manually to drive the body-only path.
//
// Spec: RFC 6749 §2.3.1.
func TestScenario_CA_POST_01_FormBodyCredentialsAccepted(t *testing.T) {
	t.Parallel()

	const (
		clientID = "ca-post-01"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "ca-post-01-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t)
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_post",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
	})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		PKCE:        pkce,
	})
	if flow.Error != "" {
		t.Fatalf("authorize error=%s desc=%s", flow.Error, flow.ErrorDesc)
	}
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}

	// Build /token POST manually so client_id and client_secret land
	// in the body, exercising the MethodSecretPost path.
	resp := postTokenForm(t, tk, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {flow.Code},
		"redirect_uri":  {callback},
		"code_verifier": {pkce.Verifier},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}, nil)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/token status=%d body=%v, want 200", resp.StatusCode, resp.Body)
	}
	if got, _ := resp.Body["access_token"].(string); got == "" {
		t.Errorf("access_token missing from /token envelope: %v", resp.Body)
	}
	if got, _ := resp.Body["id_token"].(string); got == "" {
		t.Errorf("id_token missing from /token envelope: %v", resp.Body)
	}
	if got, _ := resp.Body["token_type"].(string); got != "Bearer" {
		t.Errorf("token_type=%q want Bearer", got)
	}
}

// TestScenario_CA_POST_02_ChunkedTransferEncodingAccepted submits a
// /token POST whose body uses Transfer-Encoding: chunked instead of a
// fixed Content-Length, exercising the RFC 7230 §4.1 streaming-body
// shape. The OP MUST NOT require Content-Length for token requests:
// http.Server's body parser handles both framings transparently and
// the handler reads through ParseForm, so the chunked path lands on
// the same code that processes the Content-Length variant. We wrap
// the request body in a ReadCloser whose Length is unknown so the
// stdlib http.Client emits Transfer-Encoding: chunked rather than
// Content-Length; the success signal is "auth passed → invalid_grant"
// for the bogus authorization_code, identical to the wire shape
// CA-BASIC-04 uses.
//
// Spec: RFC 7230 §4.1.
func TestScenario_CA_POST_02_ChunkedTransferEncodingAccepted(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	const clientID = "ca-post-02"
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "ca-post-02-secret"
	registerCASecretClient(t, tk, clientID, clientSecret, "client_secret_post")

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"never-issued"},
		"redirect_uri":  {"https://rp.testkit.invalid/callback"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}.Encode()

	// Wrapping the body in a struct that exposes only Read (not Len)
	// drops the request below http.Client's "known length" optimisation,
	// so the transport falls back to Transfer-Encoding: chunked.
	body := io.NopCloser(struct{ io.Reader }{strings.NewReader(form)})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/token", body)
	if err != nil {
		t.Fatalf("build /token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ContentLength = -1
	// Pin the framing the assertion claims: the transport otherwise
	// could elect to buffer the body and re-stamp Content-Length.
	req.TransferEncoding = []string{"chunked"}

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /token (chunked): %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /token body: %v", err)
	}
	envelope := map[string]any{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &envelope); err != nil {
			t.Fatalf("body is not JSON: %v (raw=%q)", err, string(raw))
		}
	}

	// "auth passed" wire shape: Content-Length-required deployments
	// would have rejected the request with 411 (or 400) before any
	// auth ran, surfacing as either a non-OAuth status or
	// invalid_request. invalid_grant is the proof that the chunked
	// body parsed AND auth verified.
	gotErr, _ := envelope["error"].(string)
	if gotErr == "invalid_client" {
		t.Fatalf("chunked POST failed client auth (status=%d body=%v); the OP MUST NOT require Content-Length",
			resp.StatusCode, envelope)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 invalid_grant (auth passed, code bogus); body=%v",
			resp.StatusCode, envelope)
	}
	if gotErr != "invalid_grant" {
		t.Errorf("error=%q want invalid_grant (auth passed); body=%v", gotErr, envelope)
	}
}

// TestScenario_CA_POST_03_PostSecretMismatchInvalidClient presents
// client_id and a mismatching client_secret in the body of /token
// for a client registered with client_secret_post. The verifier
// runs the length-constant SecretVerifier compare, which rejects,
// and the OP returns 401 invalid_client with the generic
// "client authentication failed" description. The wire shape is
// identical to CA-BASIC-09 so the choice of auth method does not
// become a discriminator.
//
// Spec: RFC 6749 §5.2.
func TestScenario_CA_POST_03_PostSecretMismatchInvalidClient(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	const clientID = "ca-post-03"
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "ca-post-03-secret"
	registerCASecretClient(t, tk, clientID, clientSecret, "client_secret_post")

	resp := postTokenForm(t, tk, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"never-issued"},
		"redirect_uri":  {"https://rp.testkit.invalid/callback"},
		"client_id":     {clientID},
		"client_secret": {"ca-post-03-WRONG-secret"},
	}, nil)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 body=%v", resp.StatusCode, resp.Body)
	}
	if got, _ := resp.Body["error"].(string); got != "invalid_client" {
		t.Errorf("error=%q want invalid_client (body=%v)", got, resp.Body)
	}
}

// TestScenario_CA_POST_04_EmptyPostSecretMethodMismatch sends
// client_id with an empty client_secret on /token for a client
// registered with client_secret_post. The parser treats an empty
// secret as "no body secret" (hasPostSecret = bodySecret != ""), so
// the request lands on MethodNone with the body client_id. The
// verifier then rejects because the client is registered
// confidential — methodAllowedForClient(None, non-public) is false —
// and the OP returns 401 invalid_client with the generic
// "client authentication failed" description rather than a
// method-mismatch hint.
//
// Spec: RFC 6749 §2.3.1 / §5.2.
func TestScenario_CA_POST_04_EmptyPostSecretMethodMismatch(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	const clientID = "ca-post-04"
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "ca-post-04-secret"
	registerCASecretClient(t, tk, clientID, clientSecret, "client_secret_post")

	resp := postTokenForm(t, tk, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"never-issued"},
		"redirect_uri":  {"https://rp.testkit.invalid/callback"},
		"client_id":     {clientID},
		"client_secret": {""},
	}, nil)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 body=%v", resp.StatusCode, resp.Body)
	}
	if got, _ := resp.Body["error"].(string); got != "invalid_client" {
		t.Errorf("error=%q want invalid_client (body=%v)", got, resp.Body)
	}
	desc, _ := resp.Body["error_description"].(string)
	if strings.Contains(strings.ToLower(desc), "method mismatch") {
		t.Errorf("error_description=%q must not leak 'method mismatch' detail", desc)
	}
}

// TestScenario_CA_POST_05_PostSecretExpired is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_POST_05_PostSecretExpired(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-POST-05 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_POST_06_PostFromBasicRegisteredClientStrictReject
// drives a client registered with
// token_endpoint_auth_method=client_secret_basic that submits its
// credentials in the form body instead of the Authorization header.
// methodAllowedForClient (internal/clientauth/verify.go) requires the
// presented method match the registered one, so MethodSecretPost is
// refused for a Basic-registered client; the OP collapses the
// rejection onto 401 invalid_client without naming the registered
// method. v1.0 does not expose a cross-method compatibility toggle,
// so the strict-default behaviour is the only mode this row pins.
//
// Spec: RFC 6749 §2.3.
func TestScenario_CA_POST_06_PostFromBasicRegisteredClientStrictReject(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	const clientID = "ca-post-06"
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "ca-post-06-secret"
	registerCASecretClient(t, tk, clientID, clientSecret, "client_secret_basic")

	resp := postTokenForm(t, tk, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"never-issued"},
		"redirect_uri":  {"https://rp.testkit.invalid/callback"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}, nil)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 body=%v", resp.StatusCode, resp.Body)
	}
	if got, _ := resp.Body["error"].(string); got != "invalid_client" {
		t.Errorf("error=%q want invalid_client (body=%v)", got, resp.Body)
	}
	desc, _ := resp.Body["error_description"].(string)
	if strings.Contains(strings.ToLower(desc), "method") {
		t.Errorf("error_description=%q must not name the registered method", desc)
	}
}

// TestScenario_CA_CSJWT_01_AssertionTypeRequired is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_CSJWT_01_AssertionTypeRequired(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-CSJWT-01 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_CSJWT_02_AssertionTypeWrongValueRejected is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_CSJWT_02_AssertionTypeWrongValueRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-CSJWT-02 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_CSJWT_03_MissingOrMalformedAssertionRejected is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_CSJWT_03_MissingOrMalformedAssertionRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-CSJWT-03 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_CSJWT_04_HMACSignedWithClientSecret is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_CSJWT_04_HMACSignedWithClientSecret(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-CSJWT-04 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_CSJWT_05_RequiredClaimsEnforced is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_CSJWT_05_RequiredClaimsEnforced(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-CSJWT-05 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_CSJWT_06_IssMustEqualClientID is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_CSJWT_06_IssMustEqualClientID(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-CSJWT-06 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_CSJWT_07_SubMustEqualClientID is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_CSJWT_07_SubMustEqualClientID(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-CSJWT-07 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_CSJWT_08_AudAcceptanceForms is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_CSJWT_08_AudAcceptanceForms(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-CSJWT-08 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_CSJWT_09_JtiSingleUseEnforced is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_CSJWT_09_JtiSingleUseEnforced(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-CSJWT-09 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_CSJWT_10_ExpiredAssertionRejected is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_CSJWT_10_ExpiredAssertionRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-CSJWT-10 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_CSJWT_11_ClockToleranceDefaultZero is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_CSJWT_11_ClockToleranceDefaultZero(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-CSJWT-11 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_CSJWT_12_BodyClientIDMismatchAssertion is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_CSJWT_12_BodyClientIDMismatchAssertion(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-CSJWT-12 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_CSJWT_13_AssertionWithBasicHeaderRejected is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_CSJWT_13_AssertionWithBasicHeaderRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-CSJWT-13 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_CSJWT_14_RegisteredAlgMismatchRejected is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_CSJWT_14_RegisteredAlgMismatchRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-CSJWT-14 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_CSJWT_15_DiscoveryAlgRestrictionEnforced is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_CSJWT_15_DiscoveryAlgRestrictionEnforced(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-CSJWT-15 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_CSJWT_16_ClientSecretExpiredForAssertion is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_CSJWT_16_ClientSecretExpiredForAssertion(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-CSJWT-16 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_CSJWT_17_NoneRegisteredCannotUseAssertion is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_CSJWT_17_NoneRegisteredCannotUseAssertion(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-CSJWT-17 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_CSJWT_18_HSResponseAlgRequiresSecret is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_CSJWT_18_HSResponseAlgRequiresSecret(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-CSJWT-18 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_PKJWT_01_AsymmetricAlgsAcceptedHSRejected covers two
// halves of one wire-shape contract: a properly-signed ES256 assertion
// authenticates the client (so /token only fails on the fake
// authorization_code → invalid_grant), while an HS256 assertion forged
// against a known shared secret is rejected at the JOSE allow-list
// (internal/jose/jose.go's allowedV4Algorithms returns RS256, PS256,
// ES256, EdDSA — HS256 is structurally absent). The HS256 rejection
// surfaces as 401 invalid_client with the generic
// "client authentication failed" description; the OP intentionally
// does NOT echo the offending alg to avoid leaking the allow-list shape
// to a probing attacker.
//
// Spec: RFC 7523 §3 / OIDC Core §9.
func TestScenario_CA_PKJWT_01_AsymmetricAlgsAcceptedHSRejected(t *testing.T) {
	t.Parallel()

	const clientID = "ca-pkjwt-01"
	tk := testkit.NewProvider(t)
	kp := newPKJWTKeypair(t, "ca-pkjwt-01-key")
	registerPKJWTClient(t, tk, clientID, kp)

	tokenURL, _ := pkjwtAudiences(tk)
	now := time.Now().UTC()

	t.Run("ES256_accepted", func(t *testing.T) {
		t.Parallel()
		assertion := signedClientAssertion(t, kp, pkjwtClaims(clientID, tokenURL, now))
		resp := postPKJWTAssertion(t, tk, assertion, nil)
		requireAuthPassedFakeCode(t, resp)
	})

	t.Run("HS256_rejected", func(t *testing.T) {
		t.Parallel()
		// Even when the attacker knows a shared secret the HS256
		// assertion never reaches the AssertionVerifier — the JOSE
		// parse stage rejects the alg before key resolution runs.
		// HS256 requires the symmetric key to be >=32 bytes (RFC 7518
		// §3.2 / go-jose enforcement); pad an attacker-controlled
		// value out to 64 bytes so the test exercises the alg-policy
		// gate, not go-jose's key-size precondition.
		secret := []byte(strings.Repeat("a", 64))
		assertion := signedHS256Assertion(t, secret, kp.kid,
			pkjwtClaims(clientID, tokenURL, now))
		resp := postPKJWTAssertion(t, tk, assertion, nil)
		requireInvalidClient(t, resp, "hs256", "alg", "algorithm")
	})
}

// TestScenario_CA_PKJWT_02_RequiredClaimsEnforced drops each of the
// five required claims (iss, sub, aud, jti, exp) in turn and confirms
// the OP rejects every variation with 401 invalid_client. The
// validateAssertionClaims path collapses every missing-claim case onto
// ErrAssertionMalformed so the wire description stays
// "client authentication failed"; the test asserts the response shape
// is uniform across all five subtests.
//
// Spec: RFC 7523 §3.
func TestScenario_CA_PKJWT_02_RequiredClaimsEnforced(t *testing.T) {
	t.Parallel()

	const clientID = "ca-pkjwt-02"
	tk := testkit.NewProvider(t)
	kp := newPKJWTKeypair(t, "ca-pkjwt-02-key")
	registerPKJWTClient(t, tk, clientID, kp)

	tokenURL, _ := pkjwtAudiences(tk)
	now := time.Now().UTC()

	for _, drop := range []string{"iss", "sub", "aud", "jti", "exp"} {
		t.Run("drop_"+drop, func(t *testing.T) {
			t.Parallel()
			claims := pkjwtClaims(clientID, tokenURL, now)
			delete(claims, drop)
			assertion := signedClientAssertion(t, kp, claims)
			resp := postPKJWTAssertion(t, tk, assertion, nil)
			requireInvalidClient(t, resp, drop, "missing", "required claim")
		})
	}
}

// TestScenario_CA_PKJWT_03_IssEqualsSubEqualsClientID asserts that the
// verifier rejects the assertion whenever iss or sub disagrees with the
// client_id resolved from the request. validateAssertionClaims pins
// "claims.Issuer != clientID || claims.Subject != clientID" as a hard
// reject (ErrAssertionMalformed), and the wire response is the generic
// 401 invalid_client shape.
//
// Spec: RFC 7523 §3.
func TestScenario_CA_PKJWT_03_IssEqualsSubEqualsClientID(t *testing.T) {
	t.Parallel()

	const clientID = "ca-pkjwt-03"
	tk := testkit.NewProvider(t)
	kp := newPKJWTKeypair(t, "ca-pkjwt-03-key")
	registerPKJWTClient(t, tk, clientID, kp)

	tokenURL, _ := pkjwtAudiences(tk)
	now := time.Now().UTC()

	t.Run("iss_mismatch", func(t *testing.T) {
		t.Parallel()
		claims := pkjwtClaims(clientID, tokenURL, now)
		claims["iss"] = "ca-pkjwt-03-other"
		// client_id is still resolved from the (now mismatching) iss
		// claim by the parser's unverified-extraction path; the
		// VerifyClient step then rejects because the resolved client
		// is unknown. Pin client_id explicitly so the request lands
		// on the registered client and the verifier's claim check
		// runs.
		assertion := signedClientAssertion(t, kp, claims)
		resp := postPKJWTAssertion(t, tk, assertion, url.Values{"client_id": {clientID}})
		requireInvalidClient(t, resp, "iss", "mismatch")
	})

	t.Run("sub_mismatch", func(t *testing.T) {
		t.Parallel()
		claims := pkjwtClaims(clientID, tokenURL, now)
		claims["sub"] = "ca-pkjwt-03-other"
		assertion := signedClientAssertion(t, kp, claims)
		resp := postPKJWTAssertion(t, tk, assertion, nil)
		requireInvalidClient(t, resp, "sub", "mismatch")
	})
}

// TestScenario_CA_PKJWT_04_AudAcceptanceForms drives three audience
// shapes the OP accepts — the absolute token endpoint URL (string),
// that URL inside an array, and the issuer URL (FAPI 2.0 §5.2.2). All
// three pass the verifier (auth succeeds → invalid_grant for the fake
// code). A fourth subtest asserts a pure issuer-only string also
// works because the OP wires both the token URL and the issuer into
// AuxAudiences.
//
// Spec: RFC 7523 §3 / OIDC Core §9 / FAPI 2.0 §5.2.2.
func TestScenario_CA_PKJWT_04_AudAcceptanceForms(t *testing.T) {
	t.Parallel()

	const clientID = "ca-pkjwt-04"
	tk := testkit.NewProvider(t)
	kp := newPKJWTKeypair(t, "ca-pkjwt-04-key")
	registerPKJWTClient(t, tk, clientID, kp)

	tokenURL, issuer := pkjwtAudiences(tk)
	now := time.Now().UTC()

	cases := []struct {
		name string
		aud  any
	}{
		{"token_url_string", tokenURL},
		{"token_url_array", []string{tokenURL}},
		{"issuer_string", issuer},
		{"issuer_array", []string{issuer}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			claims := pkjwtClaims(clientID, tokenURL, now)
			claims["aud"] = tc.aud
			// jti must be unique across subtests so the JTI store does
			// not record one and reject the next as a replay.
			claims["jti"] = "ca-pkjwt-04-" + tc.name
			assertion := signedClientAssertion(t, kp, claims)
			resp := postPKJWTAssertion(t, tk, assertion, nil)
			requireAuthPassedFakeCode(t, resp)
		})
	}
}

// TestScenario_CA_PKJWT_05_KeyResolvedFromJWKSWithRefetch covers the
// inline-JWKs path of the StoreJWKSResolver: a freshly registered key
// authenticates the client (auth passes → invalid_grant), and an
// assertion signed with a different keypair than the one registered
// is rejected with 401 invalid_client. JWKsURI fetching is documented
// as a follow-up at internal/clientauth/store_jwks.go and not
// exercised here.
//
// Spec: OIDC Core §10 / RFC 7517.
func TestScenario_CA_PKJWT_05_KeyResolvedFromJWKSWithRefetch(t *testing.T) {
	t.Parallel()

	const clientID = "ca-pkjwt-05"
	tk := testkit.NewProvider(t)
	kpA := newPKJWTKeypair(t, "ca-pkjwt-05-key-A")
	registerPKJWTClient(t, tk, clientID, kpA)

	tokenURL, _ := pkjwtAudiences(tk)
	now := time.Now().UTC()

	t.Run("registered_key_accepted", func(t *testing.T) {
		t.Parallel()
		assertion := signedClientAssertion(t, kpA, pkjwtClaims(clientID, tokenURL, now))
		resp := postPKJWTAssertion(t, tk, assertion, nil)
		requireAuthPassedFakeCode(t, resp)
	})

	t.Run("foreign_key_rejected", func(t *testing.T) {
		t.Parallel()
		kpB := newPKJWTKeypair(t, "ca-pkjwt-05-key-B")
		// Sign with B's private key but never register B; the
		// resolver returns A's JWKS, the signature verify fails for
		// every key, and the OP returns generic 401 invalid_client.
		claims := pkjwtClaims(clientID, tokenURL, now)
		claims["jti"] = "ca-pkjwt-05-foreign"
		assertion := signedClientAssertion(t, kpB, claims)
		resp := postPKJWTAssertion(t, tk, assertion, nil)
		requireInvalidClient(t, resp, "key mismatch", "signature", "no matching key")
	})
}

// TestScenario_CA_PKJWT_06_NoMatchingKidRejected drives the
// kid-resolution unhappy path. The OP does NOT use the JWS "kid"
// header to filter the candidate JWKS — verifySignature
// (internal/clientauth/assertion.go:153) iterates every key in the
// registered set and accepts the first one whose Verify succeeds. So
// "kid mismatch" only manifests when neither (a) the kid AND (b) the
// underlying key material map to a registered entry. The test drives
// that combined-mismatch case: the assertion is signed with an
// unregistered keypair AND stamped with a kid the registered JWKS
// does not list. No registered key verifies, and the OP collapses
// onto the generic 401 invalid_client shape; the description does
// not echo "no matching key" so a probe of kid values cannot
// enumerate the registered key set.
//
// Spec: RFC 7515 §4.1.4.
func TestScenario_CA_PKJWT_06_NoMatchingKidRejected(t *testing.T) {
	t.Parallel()

	const clientID = "ca-pkjwt-06"
	tk := testkit.NewProvider(t)
	registered := newPKJWTKeypair(t, "ca-pkjwt-06-registered")
	registerPKJWTClient(t, tk, clientID, registered)

	tokenURL, _ := pkjwtAudiences(tk)
	now := time.Now().UTC()

	claims := pkjwtClaims(clientID, tokenURL, now)
	// Forge with an unregistered keypair and a kid that does not
	// appear in the client's JWKS. Both layers of mismatch — kid AND
	// key material — must miss for the verifier to reject; signing
	// with the registered private key would succeed regardless of the
	// kid header.
	forged := newPKJWTKeypair(t, "ca-pkjwt-06-forged")
	assertion := signedClientAssertionWithKID(t, forged, "ca-pkjwt-06-no-such-kid", claims)
	resp := postPKJWTAssertion(t, tk, assertion, nil)
	requireInvalidClient(t, resp, "no matching key", "kid", "key id")
}

// TestScenario_CA_PKJWT_07_JtiSingleUseEnforced exercises RFC 7523 §3's
// replay defence: the first assertion authenticates (auth passes →
// invalid_grant for the fake code), and the second submission of the
// SAME compact JWS is rejected with 401 invalid_client. The JTI store
// holds the consumed identifier through the assertion's exp; the OP
// maps store.ErrAlreadyConsumed to ErrAssertionReplayed which the HTTP
// layer routes through the canonical "client authentication failed"
// template.
//
// Spec: RFC 7523 §3.
func TestScenario_CA_PKJWT_07_JtiSingleUseEnforced(t *testing.T) {
	t.Parallel()

	const clientID = "ca-pkjwt-07"
	tk := testkit.NewProvider(t)
	kp := newPKJWTKeypair(t, "ca-pkjwt-07-key")
	registerPKJWTClient(t, tk, clientID, kp)

	tokenURL, _ := pkjwtAudiences(tk)
	now := time.Now().UTC()
	assertion := signedClientAssertion(t, kp, pkjwtClaims(clientID, tokenURL, now))

	first := postPKJWTAssertion(t, tk, assertion, nil)
	requireAuthPassedFakeCode(t, first)

	second := postPKJWTAssertion(t, tk, assertion, nil)
	requireInvalidClient(t, second, "replay", "jti")
}

// TestScenario_CA_PKJWT_08_ClockToleranceDefaultZero pins the
// clock-skew window the OP applies to assertion iat / exp comparisons.
// PrivateKeyJWTVerifier.Leeway defaults to 60 seconds when zero is
// passed (assertion.go:118-120), so an assertion whose iat lands
// significantly outside that window — here 5 minutes in the future —
// is rejected. The test wires a fixed [op.Clock] so the comparison is
// deterministic; without it the verifier reads time.Now() and the
// "future" claim could pass on slow hosts.
//
// The catalog row originally said "default tolerance is zero". v0.x
// ships a 60-second default (mirrors the JAR / id_token verifier
// leeway). The catalog wording is rewritten alongside this binding so
// the documented behaviour matches the code.
//
// Spec: RFC 7523 §3 / RFC 7519 §4.1.4.
func TestScenario_CA_PKJWT_08_ClockToleranceDefaultZero(t *testing.T) {
	t.Parallel()

	const clientID = "ca-pkjwt-08"
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	clock := &pkjwtFixedClock{now: now}

	tk := testkit.NewProvider(t, testkit.WithClock(clock))
	kp := newPKJWTKeypair(t, "ca-pkjwt-08-key")
	registerPKJWTClient(t, tk, clientID, kp)

	tokenURL, _ := pkjwtAudiences(tk)

	// iat is 5 minutes ahead of the OP's clock — well past the
	// 60-second default leeway. The verifier rejects with
	// ErrAssertionMalformed which the HTTP layer maps to 401
	// invalid_client.
	claims := pkjwtClaims(clientID, tokenURL, now.Add(5*time.Minute))
	claims["jti"] = "ca-pkjwt-08-future-iat"
	assertion := signedClientAssertion(t, kp, claims)
	resp := postPKJWTAssertion(t, tk, assertion, nil)
	requireInvalidClient(t, resp, "iat", "future", "skew")
}

// TestScenario_CA_PKJWT_09_RegisteredAlgPinning is the per-client
// signing-alg pinning row. v0.x [store.Client] does NOT carry a
// per-client TokenEndpointAuthSigningAlg field (only
// RequestObjectSigningAlg exists), so pinning happens implicitly
// through the registered JWK Set: a client whose JWKS only carries an
// EC P-256 / ES256 key cannot authenticate with an RS256 signature
// because no registered key would verify. The test exercises that
// implicit binding by registering an ES256 JWKS and submitting an
// ES256 assertion (accepted) and a wrong-key (still ES256 but signed
// with a separate, non-registered keypair) assertion (rejected with
// 401 invalid_client).
//
// Per-client TokenEndpointAuthSigningAlg pinning will arrive when the
// store record is extended; this row's catalog wording is rewritten
// to describe the v0.x behaviour explicitly so the test does not
// regress.
//
// Spec: OIDC Core §9.
func TestScenario_CA_PKJWT_09_RegisteredAlgPinning(t *testing.T) {
	t.Parallel()

	const clientID = "ca-pkjwt-09"
	tk := testkit.NewProvider(t)
	kp := newPKJWTKeypair(t, "ca-pkjwt-09-key")
	registerPKJWTClient(t, tk, clientID, kp)

	tokenURL, _ := pkjwtAudiences(tk)
	now := time.Now().UTC()

	t.Run("registered_alg_accepted", func(t *testing.T) {
		t.Parallel()
		assertion := signedClientAssertion(t, kp, pkjwtClaims(clientID, tokenURL, now))
		resp := postPKJWTAssertion(t, tk, assertion, nil)
		requireAuthPassedFakeCode(t, resp)
	})

	t.Run("foreign_es256_key_rejected", func(t *testing.T) {
		t.Parallel()
		// A second ES256 keypair the OP has never seen — the alg
		// matches the registered JWK's alg, but no registered key
		// verifies the signature.
		other := newPKJWTKeypair(t, "ca-pkjwt-09-other")
		claims := pkjwtClaims(clientID, tokenURL, now)
		claims["jti"] = "ca-pkjwt-09-foreign"
		assertion := signedClientAssertion(t, other, claims)
		resp := postPKJWTAssertion(t, tk, assertion, nil)
		requireInvalidClient(t, resp, "alg", "signing alg")
	})
}

// TestScenario_CA_PKJWT_10_DiscoveryAlgRestrictionEnforced asserts the
// OP-wide allow-list applied at JOSE parse time. The discovery
// document advertises token_endpoint_auth_signing_alg_values_supported
// = ["RS256", "PS256", "ES256", "EdDSA"]; the parser at
// internal/jose/jose.go uses the same list. An assertion outside the
// list (HS256 — the canonical "shared-secret" alg the OP refuses to
// honour) is rejected at parse time with the generic 401
// invalid_client wire shape. CA-PKJWT-01 already covers the HS256
// path; this row pins the discovery / parser symmetry — i.e. that the
// list advertised on /.well-known/openid-configuration is the same
// list the verifier enforces.
//
// Spec: OIDC Discovery §3.
func TestScenario_CA_PKJWT_10_DiscoveryAlgRestrictionEnforced(t *testing.T) {
	t.Parallel()

	const clientID = "ca-pkjwt-10"
	tk := testkit.NewProvider(t)
	kp := newPKJWTKeypair(t, "ca-pkjwt-10-key")
	registerPKJWTClient(t, tk, clientID, kp)

	// Pull the published list out of the discovery doc and confirm it
	// matches the documented set; the test would silently regress if
	// the OP started advertising HS-* in the future.
	disc := getDiscoveryJSON(t, tk.Server.URL+"/.well-known/openid-configuration")
	algs := disc["token_endpoint_auth_signing_alg_values_supported"]
	algList, _ := algs.([]any)
	if len(algList) == 0 {
		t.Fatalf("discovery missing token_endpoint_auth_signing_alg_values_supported: %v", disc)
	}
	for _, raw := range algList {
		alg, _ := raw.(string)
		if strings.HasPrefix(alg, "HS") {
			t.Fatalf("discovery advertises shared-secret alg %q; CA-PKJWT-10 contract violated", alg)
		}
	}

	tokenURL, _ := pkjwtAudiences(tk)
	now := time.Now().UTC()
	// HS256 requires a >=32-byte symmetric key per RFC 7518 §3.2 and
	// go-jose enforces it; the secret is irrelevant because the OP's
	// JOSE parse stage rejects HS256 before any key resolution runs.
	secret := []byte(strings.Repeat("a", 64))
	assertion := signedHS256Assertion(t, secret, kp.kid,
		pkjwtClaims(clientID, tokenURL, now))
	resp := postPKJWTAssertion(t, tk, assertion, nil)
	requireInvalidClient(t, resp, "hs256", "alg")
}

// TestScenario_CA_PKJWT_11_OctKeyRejectedForPrivateKeyJWT confirms the
// kty=oct safety property: even when a client registers a JWKS
// containing a symmetric (oct) key and forges an HS256 assertion using
// that key's material, the OP refuses to authenticate because the JOSE
// allow-list rejects HS* before any key resolution runs. This is the
// same wire shape as CA-PKJWT-01's HS256 subtest, but the registration
// step is the property the row pins: the OP MUST NOT special-case
// "client registered an oct key" to broaden the alg allow-list.
//
// Spec: RFC 7518 §6.4.
func TestScenario_CA_PKJWT_11_OctKeyRejectedForPrivateKeyJWT(t *testing.T) {
	t.Parallel()

	const clientID = "ca-pkjwt-11"
	tk := testkit.NewProvider(t)

	// Register a client whose JWKS is a symmetric key only. The
	// resolver returns it; the JOSE parse layer still refuses HS256
	// because alg is gated on the OP-wide allow-list. The shared
	// secret is 64 bytes so go-jose's HS256 key-size precondition
	// (>=32 bytes per RFC 7518 §3.2) does not mask the alg-policy
	// reject we are pinning here.
	sharedSecret := strings.Repeat("a", 64)
	octJWKS := json.RawMessage(`{"keys":[{"kty":"oct","kid":"ca-pkjwt-11-oct","use":"sig","alg":"HS256","k":"` +
		base64.RawURLEncoding.EncodeToString([]byte(sharedSecret)) + `"}]}`)
	//nolint:gosec // G101 false positive: "private_key_jwt" is the OIDC auth-method name, not a credential.
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		TokenEndpointAuthMethod: "private_key_jwt",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		JWKs:                    octJWKS,
	})

	tokenURL, _ := pkjwtAudiences(tk)
	now := time.Now().UTC()
	assertion := signedHS256Assertion(t, []byte(sharedSecret), "ca-pkjwt-11-oct",
		pkjwtClaims(clientID, tokenURL, now))
	resp := postPKJWTAssertion(t, tk, assertion, nil)
	requireInvalidClient(t, resp, "hs256", "oct", "symmetric")
}

// getDiscoveryJSON reads /.well-known/openid-configuration from the
// testkit's HTTPS server and returns the parsed JSON. CA-PKJWT-10 uses
// it to confirm the OP does not advertise shared-secret algs.
func getDiscoveryJSON(t *testing.T, u string) map[string]any {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, u, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("discovery GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("discovery read: %v", err)
	}
	out := map[string]any{}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("discovery unmarshal: %v (raw=%q)", err, string(body))
	}
	return out
}

// TestScenario_CA_MTLS_PKI_01_ProxyCertificateAuthorisedAccepted is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_MTLS_PKI_01_ProxyCertificateAuthorisedAccepted(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-MTLS-PKI-01 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_MTLS_PKI_02_ExactlyOneSubjectMetadataAllowed is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_MTLS_PKI_02_ExactlyOneSubjectMetadataAllowed(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-MTLS-PKI-02 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_MTLS_PKI_03_RegisteredSubjectExactMatchRequired is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_MTLS_PKI_03_RegisteredSubjectExactMatchRequired(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-MTLS-PKI-03 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_MTLS_PKI_04_NoCertificateForwardedRejected is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_MTLS_PKI_04_NoCertificateForwardedRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-MTLS-PKI-04 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_MTLS_PKI_05_ProxyVerifyFailureRejected is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_MTLS_PKI_05_ProxyVerifyFailureRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-MTLS-PKI-05 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_MTLS_PKI_06_SubjectDNCanonicalised is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_MTLS_PKI_06_SubjectDNCanonicalised(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-MTLS-PKI-06 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_MTLS_PKI_07_SANDNSCaseAndIDNRules is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_MTLS_PKI_07_SANDNSCaseAndIDNRules(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-MTLS-PKI-07 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_MTLS_PKI_08_SANURIExactMatch is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_MTLS_PKI_08_SANURIExactMatch(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-MTLS-PKI-08 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_MTLS_PKI_09_SANIPNormalisation is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_MTLS_PKI_09_SANIPNormalisation(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-MTLS-PKI-09 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_MTLS_PKI_10_SANEmailRFC822CaseRules is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_MTLS_PKI_10_SANEmailRFC822CaseRules(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-MTLS-PKI-10 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_MTLS_PKI_11_EmbedderCertificateHooksDelegated is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_MTLS_PKI_11_EmbedderCertificateHooksDelegated(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-MTLS-PKI-11 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_MTLS_PKI_12_DiscoveryAdvertisesMTLSAliases is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_MTLS_PKI_12_DiscoveryAdvertisesMTLSAliases(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-MTLS-PKI-12 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_MTLS_SS_01_ThumbprintMatchesRegisteredJWK is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_MTLS_SS_01_ThumbprintMatchesRegisteredJWK(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-MTLS-SS-01 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_MTLS_SS_02_StaleJWKSURIRefetched is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_MTLS_SS_02_StaleJWKSURIRefetched(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-MTLS-SS-02 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_MTLS_SS_03_RSAECEd25519CertificatesAccepted is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_MTLS_SS_03_RSAECEd25519CertificatesAccepted(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-MTLS-SS-03 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_MTLS_SS_04_NoMatchingThumbprintRejected is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_MTLS_SS_04_NoMatchingThumbprintRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-MTLS-SS-04 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_MTLS_SS_05_NoCertificateAvailableRejected is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_MTLS_SS_05_NoCertificateAvailableRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-MTLS-SS-05 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_MTLS_SS_06_TLSSubjectMetadataNotAllowed is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_MTLS_SS_06_TLSSubjectMetadataNotAllowed(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-MTLS-SS-06 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_ATT_01_BothAttestationAndPoPHeadersRequired is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_ATT_01_BothAttestationAndPoPHeadersRequired(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-ATT-01 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_ATT_02_AttestationTypHeadersEnforced is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_ATT_02_AttestationTypHeadersEnforced(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-ATT-02 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_ATT_03_AttestationRequiredClaims is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_ATT_03_AttestationRequiredClaims(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-ATT-03 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_ATT_04_PoPRequiredClaims is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_ATT_04_PoPRequiredClaims(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-ATT-04 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_ATT_05_PoPAudArrayShapeAndIssuer is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_ATT_05_PoPAudArrayShapeAndIssuer(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-ATT-05 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_ATT_06_ChallengeEndpointEmitsHMACToken is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_ATT_06_ChallengeEndpointEmitsHMACToken(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-ATT-06 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_ATT_07_MissingChallengeReturnsUseAttestationChallenge is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_ATT_07_MissingChallengeReturnsUseAttestationChallenge(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-ATT-07 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_ATT_08_PoPJtiSingleUseEnforced is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_ATT_08_PoPJtiSingleUseEnforced(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-ATT-08 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_ATT_09_AttesterKeyHookDelegated is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_ATT_09_AttesterKeyHookDelegated(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-ATT-09 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_ATT_10_AttestationPolicyHookDelegated is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_ATT_10_AttestationPolicyHookDelegated(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-ATT-10 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_ATT_11_CnfJwkBindsAttestationToPoP is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_ATT_11_CnfJwkBindsAttestationToPoP(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-ATT-11 (see catalog out_of_scope_reason)")
}

// caFetchDiscovery issues a GET against the OP's well-known discovery
// endpoint and returns the decoded JSON document. The CA-DISC suite uses
// it to assert which client authentication methods and signing algs the
// OP advertises under various feature combinations. The helper is local
// to client_auth_test.go to keep the CA-* file self-contained; the
// DIS-* suite has its own equivalent at test/scenarios/discovery_test.go.
func caFetchDiscovery(t *testing.T, tk *testkit.Provider) map[string]any {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		tk.Server.URL+"/.well-known/openid-configuration", http.NoBody)
	if err != nil {
		t.Fatalf("build discovery request: %v", err)
	}
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery status=%d want 200", resp.StatusCode)
	}
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode discovery body: %v", err)
	}
	return doc
}

// caDiscoveryStrings extracts a JSON-array-of-strings field from a
// discovery document. It returns ok=false when the field is missing so
// the caller can distinguish "field absent" from "field present but
// empty"; the wire shape difference matters for fields like
// token_endpoint_auth_signing_alg_values_supported that the OP omits
// rather than serialises as [].
func caDiscoveryStrings(doc map[string]any, key string) (out []string, ok bool) {
	raw, present := doc[key]
	if !present {
		return nil, false
	}
	arr, isArr := raw.([]any)
	if !isArr {
		return nil, false
	}
	out = make([]string, 0, len(arr))
	for _, v := range arr {
		if s, isStr := v.(string); isStr {
			out = append(out, s)
		}
	}
	return out, true
}

// TestScenario_CA_DISC_01_OnlyEnabledMethodsAdvertised verifies that the
// default discovery document advertises exactly the client authentication
// methods the OP actually supports at /token: client_secret_basic,
// client_secret_post, and private_key_jwt. client_secret_jwt is
// intentionally NEVER advertised — the OP does not implement it
// (docs/plans/002-product-design.md line 2159) — and attestation-based
// methods are absent for the same reason.
//
// Spec: OIDC Discovery §3.
func TestScenario_CA_DISC_01_OnlyEnabledMethodsAdvertised(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	doc := caFetchDiscovery(t, tk)

	methods, ok := caDiscoveryStrings(doc, "token_endpoint_auth_methods_supported")
	if !ok {
		t.Fatalf("discovery doc missing token_endpoint_auth_methods_supported")
	}
	want := map[string]bool{
		"client_secret_basic": true,
		"client_secret_post":  true,
		"private_key_jwt":     true,
	}
	got := make(map[string]bool, len(methods))
	for _, m := range methods {
		got[m] = true
	}
	for m := range want {
		if !got[m] {
			t.Errorf("token_endpoint_auth_methods_supported=%v missing %q", methods, m)
		}
	}
	for m := range got {
		if !want[m] {
			t.Errorf("token_endpoint_auth_methods_supported=%v advertises unexpected %q", methods, m)
		}
	}
	// CSJWT is non-goal (docs/plans/002-product-design.md line 2159);
	// it must never appear in the wire advertisement.
	if got["client_secret_jwt"] {
		t.Errorf("token_endpoint_auth_methods_supported=%v MUST NOT advertise client_secret_jwt (out-of-scope)", methods)
	}
	// Attestation-based client auth is non-goal for the same reason
	// (CA-ATT family is OOS); the registry name from the IETF draft is
	// "attest_jwt_client_auth", and it MUST NOT leak onto the wire.
	if got["attest_jwt_client_auth"] {
		t.Errorf("token_endpoint_auth_methods_supported=%v MUST NOT advertise attest_jwt_client_auth (out-of-scope)", methods)
	}
}

// TestScenario_CA_DISC_02_SigningAlgValuesPublishedConditionally drives
// the default OP and asserts that
// token_endpoint_auth_signing_alg_values_supported is published with a
// non-empty list. The OP advertises private_key_jwt by default, which
// satisfies the "an assertion-bearing method is enabled" precondition
// from OIDC Discovery §3 / FAPI 2.0 §5.4. client_secret_jwt is
// out-of-scope (docs/plans/002-product-design.md line 2159), so the
// trigger is private_key_jwt only.
//
// Spec: OIDC Discovery §3 / FAPI 2.0 §5.4.
func TestScenario_CA_DISC_02_SigningAlgValuesPublishedConditionally(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	doc := caFetchDiscovery(t, tk)

	algs, ok := caDiscoveryStrings(doc, "token_endpoint_auth_signing_alg_values_supported")
	if !ok {
		t.Fatalf("discovery doc missing token_endpoint_auth_signing_alg_values_supported (private_key_jwt is enabled by default)")
	}
	if len(algs) == 0 {
		t.Errorf("token_endpoint_auth_signing_alg_values_supported=[] want non-empty")
	}
}

// TestScenario_CA_DISC_04_PrivateKeyJWTPublishesAsymmetricOnly asserts
// that token_endpoint_auth_signing_alg_values_supported lists only
// asymmetric JWS algs (RS*, PS*, ES*, EdDSA) and never HMAC ones. The
// HMAC algs would belong to client_secret_jwt, which is out-of-scope per
// docs/plans/002-product-design.md line 2159; advertising them would
// imply a verifier the OP does not ship.
//
// Spec: OIDC Core §9 / RFC 7518 §3.
func TestScenario_CA_DISC_04_PrivateKeyJWTPublishesAsymmetricOnly(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	doc := caFetchDiscovery(t, tk)

	algs, ok := caDiscoveryStrings(doc, "token_endpoint_auth_signing_alg_values_supported")
	if !ok {
		t.Fatalf("discovery doc missing token_endpoint_auth_signing_alg_values_supported")
	}
	if len(algs) == 0 {
		t.Fatalf("token_endpoint_auth_signing_alg_values_supported=[] want non-empty")
	}
	for _, alg := range algs {
		// HMAC algs (HS256/HS384/HS512) belong to client_secret_jwt,
		// which is OOS; they MUST NOT appear here. The check is on the
		// "HS" prefix because that covers every HMAC variant the JOSE
		// registry ships.
		if strings.HasPrefix(alg, "HS") {
			t.Errorf("token_endpoint_auth_signing_alg_values_supported=%v advertises HMAC alg %q (client_secret_jwt is out-of-scope)", algs, alg)
		}
		// Defensive check on the "none" alg: it is always rejected at
		// the JOSE allow-list, but if it ever leaked into discovery a
		// downstream client would have a footgun.
		if alg == "none" {
			t.Errorf("token_endpoint_auth_signing_alg_values_supported=%v advertises 'none' alg", algs)
		}
		// Every remaining entry must match one of the asymmetric
		// families the OP actually accepts. The condition is positive
		// (only allow known prefixes) so a future addition that adds an
		// unknown alg is caught.
		switch {
		case strings.HasPrefix(alg, "RS"):
		case strings.HasPrefix(alg, "PS"):
		case strings.HasPrefix(alg, "ES"):
		case alg == "EdDSA":
		default:
			t.Errorf("token_endpoint_auth_signing_alg_values_supported=%v contains unrecognised alg %q (want RS*/PS*/ES*/EdDSA only)", algs, alg)
		}
	}
}

// TestScenario_CA_DISC_06_RevocationIntrospectionMethodsParity verifies
// that revocation_endpoint_auth_methods_supported and
// introspection_endpoint_auth_methods_supported are in lock-step with
// token_endpoint_auth_methods_supported when the matching feature is
// enabled. RFC 8414 §2 advertises the three lists separately so
// deployments may, in principle, accept different methods at each;
// v1.0 reuses the same client-auth machinery at all three endpoints, so
// the lists must be identical (set equality).
//
// Spec: RFC 7009 §4.1 / RFC 7662 §2 / RFC 8414 §2.
func TestScenario_CA_DISC_06_RevocationIntrospectionMethodsParity(t *testing.T) {
	t.Parallel()

	// Revoke is enabled by default (op.WithFeature(feature.Revoke) is
	// implicit on the testkit baseline); Introspect is opt-in so we add
	// it here. Both endpoints must advertise their auth-method list with
	// the same membership as the token endpoint.
	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithFeature(feature.Introspect),
		op.WithFeature(feature.Revoke),
	))
	doc := caFetchDiscovery(t, tk)

	tokenMethods, ok := caDiscoveryStrings(doc, "token_endpoint_auth_methods_supported")
	if !ok {
		t.Fatalf("discovery doc missing token_endpoint_auth_methods_supported")
	}
	introspectMethods, ok := caDiscoveryStrings(doc, "introspection_endpoint_auth_methods_supported")
	if !ok {
		t.Fatalf("discovery doc missing introspection_endpoint_auth_methods_supported (Introspect feature is enabled)")
	}
	revokeMethods, ok := caDiscoveryStrings(doc, "revocation_endpoint_auth_methods_supported")
	if !ok {
		t.Fatalf("discovery doc missing revocation_endpoint_auth_methods_supported (Revoke feature is enabled)")
	}

	// Set equality: convert each list to a string-set and compare. The
	// builder copies the token-endpoint list verbatim so order should
	// match too, but the contract is membership rather than ordering.
	asSet := func(in []string) map[string]struct{} {
		out := make(map[string]struct{}, len(in))
		for _, v := range in {
			out[v] = struct{}{}
		}
		return out
	}
	tokenSet := asSet(tokenMethods)
	introspectSet := asSet(introspectMethods)
	revokeSet := asSet(revokeMethods)

	if len(tokenSet) != len(introspectSet) {
		t.Errorf("introspection_endpoint_auth_methods_supported=%v has different cardinality than token_endpoint_auth_methods_supported=%v",
			introspectMethods, tokenMethods)
	}
	for m := range tokenSet {
		if _, ok := introspectSet[m]; !ok {
			t.Errorf("introspection_endpoint_auth_methods_supported=%v missing %q from token list %v",
				introspectMethods, m, tokenMethods)
		}
		if _, ok := revokeSet[m]; !ok {
			t.Errorf("revocation_endpoint_auth_methods_supported=%v missing %q from token list %v",
				revokeMethods, m, tokenMethods)
		}
	}
	if len(tokenSet) != len(revokeSet) {
		t.Errorf("revocation_endpoint_auth_methods_supported=%v has different cardinality than token_endpoint_auth_methods_supported=%v",
			revokeMethods, tokenMethods)
	}
}

// TestScenario_CA_DISC_07_MTLSEndpointAliasesGated verifies the
// feature-gated emission of mtls_endpoint_aliases (RFC 8705 §5):
// without MTLS the field is structurally absent; with MTLS but no
// embedder-supplied alias map the field stays absent (the canonical
// *_endpoint values are reachable over mTLS at a single hostname);
// with MTLS plus an alias map the field carries exactly the
// embedder-supplied URLs. The wire shape never invents alias entries
// the embedder did not declare, so a deployment that fronts a single
// hostname keeps the field omitted.
//
// Spec: RFC 8705 §5.
func TestScenario_CA_DISC_07_MTLSEndpointAliasesGated(t *testing.T) {
	t.Parallel()

	t.Run("DefaultOpHasNoMTLSAliases", func(t *testing.T) {
		t.Parallel()
		tk := testkit.NewProvider(t)
		doc := caFetchDiscovery(t, tk)
		if _, ok := doc["mtls_endpoint_aliases"]; ok {
			t.Errorf("mtls_endpoint_aliases must be absent when MTLS is disabled; got %v",
				doc["mtls_endpoint_aliases"])
		}
	})

	t.Run("MTLSEnabledWithoutEmbedderAliasesStaysAbsent", func(t *testing.T) {
		t.Parallel()
		tk := testkit.NewProvider(t,
			testkit.WithOptions(op.WithFeature(feature.MTLS)),
		)
		doc := caFetchDiscovery(t, tk)
		if _, ok := doc["mtls_endpoint_aliases"]; ok {
			t.Errorf("mtls_endpoint_aliases must be absent when no aliases were supplied; got %v",
				doc["mtls_endpoint_aliases"])
		}
		if got, _ := doc["tls_client_certificate_bound_access_tokens"].(bool); !got {
			t.Errorf("tls_client_certificate_bound_access_tokens=false want true (MTLS enabled)")
		}
	})

	t.Run("MTLSEnabledWithAliasesEmits", func(t *testing.T) {
		t.Parallel()
		//nolint:gosec // G101 false positive: RFC 8705 §5 metadata key names, not credentials.
		aliases := map[string]string{
			"token_endpoint":         "https://mtls.op.testkit.invalid/oidc/token",
			"introspection_endpoint": "https://mtls.op.testkit.invalid/oidc/introspect",
			"revocation_endpoint":    "https://mtls.op.testkit.invalid/oidc/revoke",
			"userinfo_endpoint":      "https://mtls.op.testkit.invalid/oidc/userinfo",
			"registration_endpoint":  "https://mtls.op.testkit.invalid/oidc/register",
		}
		tk := testkit.NewProvider(t,
			testkit.WithOptions(
				op.WithFeature(feature.MTLS),
				op.WithDiscoveryMetadata(op.DiscoveryMetadata{
					MTLSEndpointAliases: aliases,
				}),
			),
		)
		doc := caFetchDiscovery(t, tk)
		raw, ok := doc["mtls_endpoint_aliases"]
		if !ok {
			t.Fatalf("mtls_endpoint_aliases missing from discovery; doc=%v", doc)
		}
		got, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("mtls_endpoint_aliases is %T, want map[string]any", raw)
		}
		if len(got) != len(aliases) {
			t.Errorf("mtls_endpoint_aliases has %d entries, want %d (got=%v)",
				len(got), len(aliases), got)
		}
		for k, want := range aliases {
			gotVal, present := got[k]
			if !present {
				t.Errorf("mtls_endpoint_aliases missing key %q (got=%v)", k, got)
				continue
			}
			if gotStr, _ := gotVal.(string); gotStr != want {
				t.Errorf("mtls_endpoint_aliases[%q]=%v want %q", k, gotVal, want)
			}
		}
	})

	t.Run("AliasesWithoutMTLSStayAbsent", func(t *testing.T) {
		t.Parallel()
		// The option carries aliases but MTLS is off; the discovery
		// builder structurally drops the map so the field never lands
		// on the wire. This keeps the option safe to leave in place
		// across feature toggles without an extra branch in embedder
		// configuration.
		tk := testkit.NewProvider(t,
			testkit.WithOptions(
				op.WithDiscoveryMetadata(op.DiscoveryMetadata{
					//nolint:gosec // G101 false positive: RFC 8705 §5 metadata key name, not a credential.
					MTLSEndpointAliases: map[string]string{
						"token_endpoint": "https://mtls.op.testkit.invalid/oidc/token",
					},
				}),
			),
		)
		doc := caFetchDiscovery(t, tk)
		if _, ok := doc["mtls_endpoint_aliases"]; ok {
			t.Errorf("mtls_endpoint_aliases must be absent when MTLS feature is disabled; got %v",
				doc["mtls_endpoint_aliases"])
		}
	})
}

// TestScenario_CA_ERR_01_InvalidClient401WithConditionalChallenge drives
// the "invalid_client" path through both Basic and form-based
// (client_secret_post) authentication and asserts that the
// WWW-Authenticate challenge appears only when the failed mechanism was
// Basic. The OP's writeInvalidClient (internal/tokenendpoint/error.go)
// gates the Basic challenge on the usedBasic flag from
// internal/tokenendpoint/handler.go, which is true iff the request
// carried an Authorization header — RFC 6749 §5.2 mandates this exact
// shape so RP libraries that follow the Basic-auth state machine retry
// intelligently while form-based clients are not nudged toward Basic.
//
// Spec: RFC 6749 §5.2 / RFC 7235 §4.1.
func TestScenario_CA_ERR_01_InvalidClient401WithConditionalChallenge(t *testing.T) {
	t.Parallel()

	t.Run("Basic failure carries WWW-Authenticate", func(t *testing.T) {
		t.Parallel()

		tk := testkit.NewProvider(t)
		const clientID = "ca-err-01-basic"
		//nolint:gosec // test fixture: not a real credential.
		const clientSecret = "ca-err-01-basic-secret"
		registerCASecretClient(t, tk, clientID, clientSecret, "client_secret_basic")

		resp := postTokenForm(t, tk, url.Values{
			"grant_type":   {"authorization_code"},
			"code":         {"never-issued"},
			"redirect_uri": {"https://rp.testkit.invalid/callback"},
		}, func(r *http.Request) {
			r.SetBasicAuth(clientID, "wrong-secret")
		})

		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status=%d want 401 body=%v", resp.StatusCode, resp.Body)
		}
		if got, _ := resp.Body["error"].(string); got != "invalid_client" {
			t.Errorf("error=%q want invalid_client (body=%v)", got, resp.Body)
		}
		// RFC 7235 §4.1: the challenge starts with the auth-scheme.
		// Match a "Basic " prefix (case-insensitive on the scheme to
		// stay robust against future header writers) so the realm
		// parameter does not break the assertion.
		if !strings.HasPrefix(strings.ToLower(resp.WWWAuth), "basic ") {
			t.Errorf("WWW-Authenticate=%q want Basic challenge after Basic-auth failure", resp.WWWAuth)
		}
	})

	t.Run("Post failure has no Basic challenge", func(t *testing.T) {
		t.Parallel()

		tk := testkit.NewProvider(t)
		const clientID = "ca-err-01-post"
		//nolint:gosec // test fixture: not a real credential.
		const clientSecret = "ca-err-01-post-secret"
		registerCASecretClient(t, tk, clientID, clientSecret, "client_secret_post")

		resp := postTokenForm(t, tk, url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {"never-issued"},
			"redirect_uri":  {"https://rp.testkit.invalid/callback"},
			"client_id":     {clientID},
			"client_secret": {"wrong-secret"},
		}, nil)

		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status=%d want 401 body=%v", resp.StatusCode, resp.Body)
		}
		if got, _ := resp.Body["error"].(string); got != "invalid_client" {
			t.Errorf("error=%q want invalid_client (body=%v)", got, resp.Body)
		}
		// Form-based authentication failure MUST NOT carry a Basic
		// challenge; doing so would nudge the client toward a
		// mechanism the OP did not actually invite.
		if resp.WWWAuth != "" {
			t.Errorf("WWW-Authenticate=%q want empty after form-based auth failure", resp.WWWAuth)
		}
	})
}

// TestScenario_CA_ERR_02_ErrorDescriptionDoesNotLeakDetail sweeps
// several invalid_client failure shapes (unknown client, wrong secret,
// method mismatch, no credentials) and asserts that the
// error_description carries only the generic public template; OP-
// internal sentinel names, file paths, error wrappers, secret-storage
// internals, and method-mismatch hints MUST stay off the wire. The
// audit stream (CA-ERR-05) is the surface SOC tooling reads for the
// disambiguating detail.
//
// Spec: RFC 6749 §5.2.
func TestScenario_CA_ERR_02_ErrorDescriptionDoesNotLeakDetail(t *testing.T) {
	t.Parallel()

	// Strings that must NOT appear in any client-auth error_description.
	// The list is intentionally over-broad: a future refactor that
	// inlines an internal sentinel name into the description should be
	// caught here even if the wording changes.
	const (
		// Internal sentinel / wrapper names.
		leakErrCredentials = "errcredentialsinvalid"
		leakErrMethod      = "errmethodmismatch"
		// Internal package paths.
		leakInternalPath = "internal/"
		leakClientauth   = "clientauth"
		// Storage internals.
		leakHash     = "hash"
		leakArgon2   = "argon2"
		leakSecret   = "secret"
		leakStore    = "store"
		leakNotFound = "not found"
		// Method-mismatch detail (would betray which method the client is
		// registered with).
		leakMethodMismatch = "method mismatch"
		// Stack trace shape.
		leakStack = ".go:"
	)
	leaks := []string{
		leakErrCredentials, leakErrMethod, leakInternalPath, leakClientauth,
		leakHash, leakArgon2, leakSecret, leakStore, leakNotFound,
		leakMethodMismatch, leakStack,
	}

	cases := []struct {
		name     string
		setup    func(t *testing.T, tk *testkit.Provider)
		decorate func(r *http.Request)
		body     url.Values
	}{
		{
			name: "UnknownClient",
			body: url.Values{
				"grant_type":   {"authorization_code"},
				"code":         {"never-issued"},
				"redirect_uri": {"https://rp.testkit.invalid/callback"},
			},
			decorate: func(r *http.Request) {
				r.SetBasicAuth("ca-err-02-unknown", "any")
			},
		},
		{
			name: "WrongSecret",
			setup: func(t *testing.T, tk *testkit.Provider) {
				registerCASecretClient(t, tk, "ca-err-02-known",
					"ca-err-02-known-secret", "client_secret_basic")
			},
			body: url.Values{
				"grant_type":   {"authorization_code"},
				"code":         {"never-issued"},
				"redirect_uri": {"https://rp.testkit.invalid/callback"},
			},
			decorate: func(r *http.Request) {
				r.SetBasicAuth("ca-err-02-known", "wrong-secret")
			},
		},
		{
			name: "MethodMismatch",
			setup: func(t *testing.T, tk *testkit.Provider) {
				registerCASecretClient(t, tk, "ca-err-02-postclient",
					"ca-err-02-postclient-secret", "client_secret_post")
			},
			body: url.Values{
				"grant_type":   {"authorization_code"},
				"code":         {"never-issued"},
				"redirect_uri": {"https://rp.testkit.invalid/callback"},
			},
			decorate: func(r *http.Request) {
				r.SetBasicAuth("ca-err-02-postclient", "ca-err-02-postclient-secret")
			},
		},
		{
			name: "NoCredentials",
			body: url.Values{
				"grant_type":   {"authorization_code"},
				"code":         {"never-issued"},
				"redirect_uri": {"https://rp.testkit.invalid/callback"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tk := testkit.NewProvider(t)
			if tc.setup != nil {
				tc.setup(t, tk)
			}
			resp := postTokenForm(t, tk, tc.body, tc.decorate)

			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status=%d want 401 body=%v", resp.StatusCode, resp.Body)
			}
			desc, _ := resp.Body["error_description"].(string)
			// The template must remain short — pin a generous upper
			// bound so a future template change that inlined a stack
			// trace or internal note would trip the assertion. 200
			// chars covers any reasonable human-readable sentence.
			if len(desc) > 200 {
				t.Errorf("error_description length=%d want <=200 (full=%q)", len(desc), desc)
			}
			lower := strings.ToLower(desc)
			for _, leak := range leaks {
				if strings.Contains(lower, leak) {
					t.Errorf("error_description=%q must not contain internal-state hint %q", desc, leak)
				}
			}
		})
	}
}

// TestScenario_CA_ERR_03_TimingEqualisedAcrossFailurePaths locks the
// shape-equivalence defence against client-auth timing oracles. v1.0's
// handler routes both "unknown client_id" and "wrong secret" through
// clientauth.ErrCredentialsInvalid (lookupClient maps store.ErrNotFound
// onto the same sentinel) so the wire response is byte-equivalent: same
// status code, same RFC 6749 §5.2 envelope, same WWW-Authenticate
// challenge. The structural defence (shared path + Argon2id constant-
// time KDF) makes wall-clock timing assertions redundant; we lock the
// observable property instead.
//
// Spec: RFC 6749 §10.4 / RFC 6749 §5.2.
func TestScenario_CA_ERR_03_TimingEqualisedAcrossFailurePaths(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	const knownID = "ca-err-03-known"
	//nolint:gosec // test fixture: not a real credential.
	const knownSecret = "ca-err-03-known-secret"
	registerCASecretClient(t, tk, knownID, knownSecret, "client_secret_basic")

	// Unknown client: id never registered, any secret.
	unknown := postTokenForm(t, tk, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"never-issued"},
		"redirect_uri": {"https://rp.testkit.invalid/callback"},
	}, func(r *http.Request) {
		r.SetBasicAuth("ca-err-03-never-registered", "any-guess")
	})

	// Wrong secret: registered client, wrong secret.
	wrong := postTokenForm(t, tk, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"never-issued"},
		"redirect_uri": {"https://rp.testkit.invalid/callback"},
	}, func(r *http.Request) {
		r.SetBasicAuth(knownID, "wrong-secret")
	})

	if unknown.StatusCode != http.StatusUnauthorized || wrong.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: unknown=%d wrong=%d, want both 401", unknown.StatusCode, wrong.StatusCode)
	}
	if unknown.StatusCode != wrong.StatusCode {
		t.Errorf("status differs across failure modes: unknown=%d wrong=%d", unknown.StatusCode, wrong.StatusCode)
	}
	uErr, _ := unknown.Body["error"].(string)
	wErr, _ := wrong.Body["error"].(string)
	if uErr != "invalid_client" || wErr != "invalid_client" {
		t.Fatalf("error: unknown=%q wrong=%q, want both invalid_client", uErr, wErr)
	}
	if uErr != wErr {
		t.Errorf("error code differs: unknown=%q wrong=%q", uErr, wErr)
	}
	uDesc, _ := unknown.Body["error_description"].(string)
	wDesc, _ := wrong.Body["error_description"].(string)
	if uDesc != wDesc {
		t.Errorf("error_description differs across failure modes:\n  unknown=%q\n  wrong  =%q", uDesc, wDesc)
	}
	// WWW-Authenticate challenge MUST be byte-identical: a probing
	// client cannot tell unknown_client from wrong_secret apart by
	// header diff. The realm parameter and any other parameters are
	// part of the assertion.
	if unknown.WWWAuth != wrong.WWWAuth {
		t.Errorf("WWW-Authenticate differs:\n  unknown=%q\n  wrong  =%q", unknown.WWWAuth, wrong.WWWAuth)
	}
	if !strings.HasPrefix(strings.ToLower(unknown.WWWAuth), "basic ") {
		t.Errorf("WWW-Authenticate=%q want Basic challenge after Basic-auth failure", unknown.WWWAuth)
	}
}

// TestScenario_CA_ERR_04_AuthFlowRateLimitOPScoped is OOS — see catalog out_of_scope_reason.
func TestScenario_CA_ERR_04_AuthFlowRateLimitOPScoped(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CA-ERR-04 (see catalog out_of_scope_reason)")
}

// TestScenario_CA_ERR_05_ClientAuthnFailureAuditEvent pins the
// post-failure audit signal: every pre-issuance client authentication
// failure at /token raises a "client_authn.failure" audit event
// carrying the auth method (when known), a short reason code, and the
// failing client_id (when known). The wire response stays at the
// canonical RFC 6749 §5.2 invalid_client envelope, so the audit stream
// is the only place SOC tooling can spot probing patterns the wire
// response deliberately hides.
//
// Spec: RFC 6749 §5.2; structured-event practice from RFC 8417
// (Security Event Token).
func TestScenario_CA_ERR_05_ClientAuthnFailureAuditEvent(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		clientID     string // empty means do not register a client
		registerOnly bool
		decorate     func(req *http.Request)
		wantClientID string
		wantMethod   string
		wantReason   string
	}{
		{
			name:         "BadSecret",
			clientID:     "rp-ca-err-05-bad-secret",
			registerOnly: true,
			decorate: func(req *http.Request) {
				req.SetBasicAuth("rp-ca-err-05-bad-secret", "wrong-secret")
			},
			wantClientID: "rp-ca-err-05-bad-secret",
			wantMethod:   "client_secret_basic",
			wantReason:   "invalid_client_credentials",
		},
		{
			name:     "UnknownClient",
			clientID: "",
			decorate: func(req *http.Request) {
				req.SetBasicAuth("rp-ca-err-05-not-registered", "any-secret")
			},
			wantClientID: "rp-ca-err-05-not-registered",
			wantMethod:   "client_secret_basic",
			// lookupClient maps store.ErrNotFound onto
			// clientauth.ErrCredentialsInvalid to keep the wire
			// response indistinguishable from "wrong secret".
			wantReason: "invalid_client_credentials",
		},
		{
			name:         "NoCredentials",
			clientID:     "",
			decorate:     nil,
			wantClientID: "",
			wantMethod:   "",
			wantReason:   "no_credentials",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			capture := newScenarioAuditCapture()
			tk := testkit.NewProvider(t,
				testkit.WithOptions(op.WithAuditLogger(capture.logger())),
			)
			if tc.registerOnly {
				registerCASecretClient(t, tk, tc.clientID,
					"rp-ca-err-05-correct-secret", "client_secret_basic")
			}

			form := url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {"opaque-refresh-token-never-reached"},
			}
			resp := postTokenForm(t, tk, form, tc.decorate)
			if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status=%d want 400 or 401, body=%v", resp.StatusCode, resp.Body)
			}
			if got, _ := resp.Body["error"].(string); got == "" {
				t.Fatalf("error field missing on failure response: %v", resp.Body)
			}

			events := capture.findEvents(string(op.AuditClientAuthnFailure))
			if len(events) != 1 {
				t.Fatalf("got %d client_authn.failure events, want exactly 1; capture=%s",
					len(events), capture.dump())
			}
			rec := events[0]
			gotID, _ := rec["client_id"].(string)
			if gotID != tc.wantClientID {
				t.Errorf("client_id=%q want %q", gotID, tc.wantClientID)
			}
			extras, _ := rec["extras"].(map[string]any)
			if extras == nil {
				t.Fatalf("extras missing on client_authn.failure: %v", rec)
			}
			if got, _ := extras["reason"].(string); got != tc.wantReason {
				t.Errorf("extras.reason=%q want %q", got, tc.wantReason)
			}
			if tc.wantMethod == "" {
				if _, present := extras["method"]; present {
					t.Errorf("extras.method present (=%v) but credentials were unparseable; want absent",
						extras["method"])
				}
			} else if got, _ := extras["method"].(string); got != tc.wantMethod {
				t.Errorf("extras.method=%q want %q", got, tc.wantMethod)
			}
		})
	}
}
