package authorizeendpoint_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
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
)

// jarHarness wires a testkit Provider with the JAR feature enabled and
// registers a single client whose JWKs the harness controls. Tests
// reuse the harness across the rows below.
type jarHarness struct {
	tk          *testkit.Provider
	rpID        string
	redirectURI string
	httpClient  *http.Client
	clock       fakeClock
	priv        *ecdsa.PrivateKey
	kid         string
}

func newJARHarness(t *testing.T, mutate func(*store.Client)) *jarHarness {
	t.Helper()
	clock := fakeClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	tk := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(op.WithFeature(feature.JAR)),
	)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	const kid = "rp-jar-1"
	jwks := jarBuildJWKS(t, &priv.PublicKey, kid)
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:           "rp-jar",
		PublicClient: true,
		RedirectURIs: []string{"https://rp.testkit.invalid/callback"},
		Scopes:       []string{"openid", "profile", "email"},
	})
	// Patch the registered client with the inline JWKs (and apply any
	// caller-supplied mutation) so the JAR verifier finds keys without
	// reaching the network.
	updated := *rp
	updated.JWKs = jwks
	if mutate != nil {
		mutate(&updated)
	}
	if err := tk.Store.UpdateClient(context.Background(), &updated); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	httpClient := tk.HTTPClient(jar)
	return &jarHarness{
		tk:          tk,
		rpID:        rp.ID,
		redirectURI: rp.RedirectURIs[0],
		httpClient:  httpClient,
		clock:       clock,
		priv:        priv,
		kid:         kid,
	}
}

// jarBuildJWKS returns a serialised JWKS containing pub.
func jarBuildJWKS(t *testing.T, pub *ecdsa.PublicKey, kid string) []byte {
	t.Helper()
	keys := josev4.JSONWebKeySet{
		Keys: []josev4.JSONWebKey{{
			Key:       pub,
			KeyID:     kid,
			Algorithm: string(josev4.ES256),
			Use:       "sig",
		}},
	}
	out, err := json.Marshal(keys)
	if err != nil {
		t.Fatalf("Marshal jwks: %v", err)
	}
	return out
}

// jarSign returns a compact ES256 JWS over claims using the harness key.
func (h *jarHarness) jarSign(t *testing.T, claims map[string]any) string {
	t.Helper()
	sk := josev4.SigningKey{
		Algorithm: josev4.ES256,
		Key: josev4.JSONWebKey{
			Key:       h.priv,
			KeyID:     h.kid,
			Algorithm: string(josev4.ES256),
			Use:       "sig",
		},
	}
	signer, err := josev4.NewSigner(sk, (&josev4.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	out, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return out
}

// happyJARClaims returns a request-object claim bag that satisfies the
// verifier when paired with the harness's clock and registered RP. The
// fixture mints a fresh "jti" per call so successive request objects
// in the same test do not collide on the consumed-jti gate (RFC 9101
// §10.8).
func (h *jarHarness) happyJARClaims() map[string]any {
	return map[string]any{
		"iss":                   h.rpID,
		"aud":                   h.tk.Issuer,
		"exp":                   h.clock.now.Add(5 * time.Minute).Unix(),
		"iat":                   h.clock.now.Unix(),
		"jti":                   freshJARJTI(),
		"client_id":             h.rpID,
		"response_type":         "code",
		"redirect_uri":          h.redirectURI,
		"scope":                 "openid profile email",
		"state":                 "state-abc",
		"nonce":                 "n-0S6_WzA2Mj",
		"code_challenge":        e2eChallenge(),
		"code_challenge_method": "S256",
	}
}

// freshJARJTI mints a 128-bit random JWT identifier suitable for a
// single end-to-end request object. crypto/rand is used directly so a
// single test never produces colliding values across successive
// request objects in the same fixture.
func freshJARJTI() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return "jti-" + hex.EncodeToString(b[:])
}

// jarGet issues GET /authorize?client_id=...&request=<JWT> and returns
// the response. Redirects are not followed.
func (h *jarHarness) jarGet(t *testing.T, jwtStr string) *http.Response {
	t.Helper()
	values := url.Values{"client_id": {h.rpID}, "request": {jwtStr}}
	target := h.tk.Server.URL + "/oidc/auth?" + values.Encode()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := h.httpClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	return resp
}

func TestEndToEnd_JAR_AcceptsSignedRequest(t *testing.T) {
	t.Parallel()
	h := newJARHarness(t, nil)
	signed := h.jarSign(t, h.happyJARClaims())
	resp := h.jarGet(t, signed)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, string(dump))
	}
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	if !strings.HasPrefix(loc.Path, "/oidc/interaction/") {
		t.Fatalf("expected interaction redirect; got %s", loc.String())
	}
}

func TestEndToEnd_JAR_RejectsAlgNone(t *testing.T) {
	t.Parallel()
	h := newJARHarness(t, nil)
	// Hand-craft a base64 "alg=none" JWT. The verifier rejects this
	// at the alg-allow-list gate.
	const noneJWT = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJycC1qYXIifQ."
	resp := h.jarGet(t, noneJWT)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	body := decodeMap(t, resp)
	if body["error"] == "" {
		t.Errorf("error empty: %v", body)
	}
}

func TestEndToEnd_JAR_RejectsClientIDMismatch(t *testing.T) {
	t.Parallel()
	h := newJARHarness(t, nil)
	claims := h.happyJARClaims()
	claims["client_id"] = "someone-else"
	signed := h.jarSign(t, claims)
	resp := h.jarGet(t, signed)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	body := decodeMap(t, resp)
	if body["error"] != "invalid_request" {
		t.Errorf("error=%v want invalid_request", body["error"])
	}
}

func TestEndToEnd_JAR_RejectsAudMismatch(t *testing.T) {
	t.Parallel()
	h := newJARHarness(t, nil)
	claims := h.happyJARClaims()
	claims["aud"] = "https://different-op.example.com"
	signed := h.jarSign(t, claims)
	resp := h.jarGet(t, signed)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	body := decodeMap(t, resp)
	if body["error"] != "invalid_request_object" {
		t.Errorf("error=%v want invalid_request_object", body["error"])
	}
}

func TestEndToEnd_JAR_RejectsExpired(t *testing.T) {
	t.Parallel()
	h := newJARHarness(t, nil)
	claims := h.happyJARClaims()
	claims["exp"] = h.clock.now.Add(-time.Minute).Unix()
	claims["iat"] = h.clock.now.Add(-2 * time.Minute).Unix()
	signed := h.jarSign(t, claims)
	resp := h.jarGet(t, signed)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	body := decodeMap(t, resp)
	if body["error"] != "invalid_request_object" {
		t.Errorf("error=%v want invalid_request_object", body["error"])
	}
}

func TestEndToEnd_JAR_RejectsBothRequestAndRequestURI(t *testing.T) {
	t.Parallel()
	h := newJARHarness(t, nil)
	signed := h.jarSign(t, h.happyJARClaims())
	values := url.Values{
		"client_id":   {h.rpID},
		"request":     {signed},
		"request_uri": {"https://rp.testkit.invalid/req"},
	}
	target := h.tk.Server.URL + "/oidc/auth?" + values.Encode()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := h.httpClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	body := decodeMap(t, resp)
	if body["error"] != "invalid_request" {
		t.Errorf("error=%v want invalid_request", body["error"])
	}
}

func TestEndToEnd_JAR_FeatureDisabledRejectsRequest(t *testing.T) {
	t.Parallel()
	// No WithFeature(feature.JAR): the testkit provider lacks the verifier.
	clock := fakeClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	tk := testkit.NewProvider(t, testkit.WithClock(clock))
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:           "rp-no-jar",
		PublicClient: true,
		RedirectURIs: []string{"https://rp.testkit.invalid/callback"},
		Scopes:       []string{"openid"},
	})
	values := url.Values{
		"client_id": {rp.ID},
		"request":   {"eyJhbGciOiJFUzI1NiJ9.body.sig"},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		tk.Server.URL+"/oidc/auth?"+values.Encode(), http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	body := decodeMap(t, resp)
	if body["error"] != "invalid_request" {
		t.Errorf("error=%v want invalid_request", body["error"])
	}
}

func TestEndToEnd_JAR_RequestURIMustBePreregistered(t *testing.T) {
	t.Parallel()
	// Register no RequestURIs on the client; any non-PAR request_uri
	// must fall through to the JAR consumer and be rejected.
	h := newJARHarness(t, nil)
	values := url.Values{
		"client_id":   {h.rpID},
		"request_uri": {"https://attacker.example/req"},
	}
	resp := h.jarDoGet(t, h.tk.Server.URL+"/oidc/auth?"+values.Encode())
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	body := decodeMap(t, resp)
	if body["error"] != "invalid_request_uri" {
		t.Errorf("error=%v want invalid_request_uri", body["error"])
	}
}

// jarDoGet issues GET against target through the harness HTTP client
// without following redirects.
func (h *jarHarness) jarDoGet(t *testing.T, target string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := h.httpClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	return resp
}

func TestEndToEnd_JAR_RequestURIServedAndConsumed(t *testing.T) {
	t.Parallel()
	// Stand up a small file server that returns the signed request
	// object; register its URL on the client; assert /authorize
	// follows the URL and accepts the signed claims.
	h := newJARHarness(t, nil)
	signed := h.jarSign(t, h.happyJARClaims())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
		_, _ = w.Write([]byte(signed))
	}))
	defer srv.Close()
	// Re-register the client with the server URL allowlisted. The
	// fetch deny-list rejects 127.0.0.1, so this test confirms the
	// allow-private path is wired AND that the URI must be in the
	// allowlist — but httptest binds to loopback so the SSRF check
	// fires first and the test asserts that path instead. (A future
	// op.WithAllowPrivateNetworkJAR option would let this case
	// exercise the success path against httptest; for now we land on
	// the deny.)
	updated, err := h.tk.Store.GetClient(context.Background(), h.rpID)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	updated.RequestURIs = []string{srv.URL + "/req"}
	if err := h.tk.Store.UpdateClient(context.Background(), updated); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	values := url.Values{
		"client_id":   {h.rpID},
		"request_uri": {srv.URL + "/req"},
	}
	resp := h.jarDoGet(t, h.tk.Server.URL+"/oidc/auth?"+values.Encode())
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 (loopback deny)", resp.StatusCode)
	}
	body := decodeMap(t, resp)
	if body["error"] != "invalid_request_uri" {
		t.Errorf("error=%v want invalid_request_uri", body["error"])
	}
}

// TestEndToEnd_JAR_DiscoveryAdvertisesMetadata confirms the OP advertises
// the JAR-related metadata fields when the feature is enabled.
func TestEndToEnd_JAR_DiscoveryAdvertisesMetadata(t *testing.T) {
	t.Parallel()
	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithFeature(feature.JAR)))
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		tk.Server.URL+"/.well-known/openid-configuration", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	doc := decodeMap(t, resp)
	if got, _ := doc["request_parameter_supported"].(bool); !got {
		t.Errorf("request_parameter_supported=%v", doc["request_parameter_supported"])
	}
	if got, _ := doc["request_uri_parameter_supported"].(bool); !got {
		t.Errorf("request_uri_parameter_supported=%v", doc["request_uri_parameter_supported"])
	}
	if got, _ := doc["require_request_uri_registration"].(bool); !got {
		t.Errorf("require_request_uri_registration=%v", doc["require_request_uri_registration"])
	}
	algs, _ := doc["request_object_signing_alg_values_supported"].([]any)
	if len(algs) == 0 {
		t.Errorf("request_object_signing_alg_values_supported empty: %v", doc["request_object_signing_alg_values_supported"])
	}
}
