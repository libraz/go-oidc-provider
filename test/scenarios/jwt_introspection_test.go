package scenarios_test

// Catalog: test/scenarios/catalog/jwt_introspection.yaml (JINT-NNN)
// Spec:
//   - RFC 9701 — JWT Response for OAuth 2.0 Token Introspection
//   - RFC 7662 — OAuth 2.0 Token Introspection (prerequisite)
//   - RFC 7515 / 7516 / 7518 — JWS / JWE / JWA
//   - RFC 8414 §2 — `introspection_signing_alg_values_supported`
//   - OIDC Core 1.0 §10

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
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

// jintJWTAccept is the RFC 9701 §4 wire content-type a client sets to
// request the JWT introspection envelope. Pulled into a constant so
// each test reads the negotiation step without re-quoting the literal.
const jintJWTAccept = "application/token-introspection+jwt"

// jintIssueAccessToken drives the full code → /token round-trip for a
// confidential client and returns the access token plus the active OP.
// Helper is local to this file because no other feature in the scenario
// suite needs an "issue an access token then introspect it" pair; if a
// second feature picks up the same pattern this should move to
// scenariokit.
func jintIssueAccessToken(t *testing.T, tk *testkit.Provider, clientID, clientSecret, callback string) (rp *store.Client, accessToken string) {
	t.Helper()

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	registered := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
	})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    registered.ID,
		RedirectURI: callback,
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     registered.ID,
		ClientSecret: clientSecret,
	})
	if tok.StatusCode != http.StatusOK || tok.AccessToken == "" {
		t.Fatalf("/token status=%d body=%v want 200 with access_token", tok.StatusCode, tok.Raw)
	}
	return registered, tok.AccessToken
}

// jintIntrospect issues a single /introspect request with the supplied
// Accept header (omit by passing the empty string) and returns the
// raw response. The body is NOT read; the caller decides whether to
// parse JSON or a JWS, and is responsible for closing the body.
func jintIntrospect(t *testing.T, tk *testkit.Provider, clientID, clientSecret, accessToken, accept string) *http.Response {
	t.Helper()

	form := url.Values{"token": {accessToken}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/introspect", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build /introspect request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	req.SetBasicAuth(clientID, clientSecret)

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /introspect: %v", err)
	}
	return resp
}

// jintParseJWT verifies the RFC 9701 §4 JWS body against the testkit's
// active public signing key and returns the decoded claim bundle. The
// helper fails the test on any structural / cryptographic fault.
func jintParseJWT(t *testing.T, tk *testkit.Provider, raw string) map[string]any {
	t.Helper()

	parsed, err := jwt.ParseSigned(raw, []josev4.SignatureAlgorithm{josev4.ES256})
	if err != nil {
		t.Fatalf("ParseSigned: %v (raw=%q)", err, raw)
	}
	pub, ok := tk.SigningKey.Signer.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("testkit signer public key is not *ecdsa.PublicKey: %T", tk.SigningKey.Signer.Public())
	}
	out := map[string]any{}
	if err := parsed.Claims(pub, &out); err != nil {
		t.Fatalf("Claims verify: %v", err)
	}
	return out
}

// jintDecodeHeader decodes the JWS protected header from a compact
// serialisation. go-jose v4's typed header API keys ExtraHeaders by a
// private constant, so this hand-decode keeps the assertion on plain
// strings.
func jintDecodeHeader(t *testing.T, raw string) map[string]any {
	t.Helper()

	dot := strings.IndexByte(raw, '.')
	if dot <= 0 {
		t.Fatalf("compact JWS missing first segment: %q", raw)
	}
	hdrBytes, err := base64.RawURLEncoding.DecodeString(raw[:dot])
	if err != nil {
		t.Fatalf("decode header segment: %v", err)
	}
	hdr := map[string]any{}
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		t.Fatalf("unmarshal header: %v (raw=%q)", err, hdrBytes)
	}
	return hdr
}

// TestScenario_JINT_003_DefaultJSONWhenAcceptOmitted checks the RFC
// 7662 §2.2 default: when an introspection request omits Accept, the
// OP MUST keep the legacy JSON content-type. The JWT envelope is
// negotiated only on an explicit Accept ask under the v1.0 posture.
//
// Spec: RFC 7662 §2.2 / RFC 9701 §5.
func TestScenario_JINT_003_DefaultJSONWhenAcceptOmitted(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-jint-003"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-jint-003-secret"

	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithFeature(feature.Introspect)))
	rp, at := jintIssueAccessToken(t, tk, clientID, clientSecret, callback)

	resp := jintIntrospect(t, tk, rp.ID, clientSecret, at, "")
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, raw)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type=%q want application/json (default JSON path)", got)
	}
	var env map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if active, _ := env["active"].(bool); !active {
		t.Fatalf("active=%v want true; body=%v", env["active"], env)
	}
}

// TestScenario_JINT_004_JWTBodyForMatchingAcceptHeader checks the RFC
// 9701 §4 negotiation: the same client repeating the introspection
// with Accept: application/token-introspection+jwt receives the JWT
// envelope plus the matching wire content-type.
//
// Spec: RFC 9701 §4.
func TestScenario_JINT_004_JWTBodyForMatchingAcceptHeader(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-jint-004"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-jint-004-secret"

	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithFeature(feature.Introspect)))
	rp, at := jintIssueAccessToken(t, tk, clientID, clientSecret, callback)

	resp := jintIntrospect(t, tk, rp.ID, clientSecret, at, jintJWTAccept)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, raw)
	}
	if got := resp.Header.Get("Content-Type"); got != jintJWTAccept {
		t.Fatalf("Content-Type=%q want %q", got, jintJWTAccept)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	raw := strings.TrimSpace(string(body))
	if strings.Count(raw, ".") != 2 {
		t.Fatalf("body is not a compact JWS (need 2 dots): %q", raw)
	}
	// Verify it actually parses against the OP's signer.
	_ = jintParseJWT(t, tk, raw)
}

// TestScenario_JINT_005_JWTEnvelopeClaimsPresent checks the RFC 9701
// §5 envelope: iss=provider issuer, aud=client_id, iat as a JSON
// number, and a token_introspection claim that nests the JSON
// introspection document (active=true plus client_id, scope, sub,
// iss, iat, exp, token_type, aud).
//
// Spec: RFC 9701 §5.
func TestScenario_JINT_005_JWTEnvelopeClaimsPresent(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-jint-005"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-jint-005-secret"

	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithFeature(feature.Introspect)))
	rp, at := jintIssueAccessToken(t, tk, clientID, clientSecret, callback)

	resp := jintIntrospect(t, tk, rp.ID, clientSecret, at, jintJWTAccept)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, raw)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	raw := strings.TrimSpace(string(body))
	claims := jintParseJWT(t, tk, raw)

	if got, _ := claims["iss"].(string); got != tk.Issuer {
		t.Errorf("iss=%v want %q", claims["iss"], tk.Issuer)
	}
	if got, _ := claims["aud"].(string); got != rp.ID {
		t.Errorf("aud=%v want %q", claims["aud"], rp.ID)
	}
	if _, ok := claims["iat"].(float64); !ok {
		t.Errorf("iat must be a JSON number, got %T", claims["iat"])
	}

	nested, ok := claims["token_introspection"].(map[string]any)
	if !ok {
		t.Fatalf("token_introspection claim missing or not an object: %T (%v)", claims["token_introspection"], claims["token_introspection"])
	}
	if active, _ := nested["active"].(bool); !active {
		t.Errorf("token_introspection.active=%v want true", nested["active"])
	}
	if got, _ := nested["client_id"].(string); got != rp.ID {
		t.Errorf("token_introspection.client_id=%v want %q", nested["client_id"], rp.ID)
	}
	if got, _ := nested["sub"].(string); got != scenariokit.DefaultSubject {
		t.Errorf("token_introspection.sub=%v want %q", nested["sub"], scenariokit.DefaultSubject)
	}
	if got, _ := nested["iss"].(string); got != tk.Issuer {
		t.Errorf("token_introspection.iss=%v want %q", nested["iss"], tk.Issuer)
	}
	if got, _ := nested["token_type"].(string); got != "Bearer" {
		t.Errorf("token_introspection.token_type=%v want Bearer", nested["token_type"])
	}
	if _, ok := nested["iat"].(float64); !ok {
		t.Errorf("token_introspection.iat must be a JSON number, got %T", nested["iat"])
	}
	if _, ok := nested["exp"].(float64); !ok {
		t.Errorf("token_introspection.exp must be a JSON number, got %T", nested["exp"])
	}
}

// TestScenario_JINT_006_JWTHeaderTypeIsTokenIntrospection checks the
// RFC 9701 §5 header binding: the JWS protected header MUST set
// typ=token-introspection+jwt so a JWT pulled out of context still
// self-describes as an introspection envelope.
//
// Spec: RFC 9701 §5.
func TestScenario_JINT_006_JWTHeaderTypeIsTokenIntrospection(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-jint-006"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-jint-006-secret"

	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithFeature(feature.Introspect)))
	rp, at := jintIssueAccessToken(t, tk, clientID, clientSecret, callback)

	resp := jintIntrospect(t, tk, rp.ID, clientSecret, at, jintJWTAccept)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	raw := strings.TrimSpace(string(body))
	hdr := jintDecodeHeader(t, raw)
	if got, _ := hdr["typ"].(string); got != "token-introspection+jwt" {
		t.Fatalf("typ=%v want token-introspection+jwt", hdr["typ"])
	}
}

// TestScenario_JINT_007_JWTIatProgressesWithClock checks the RFC 9701
// §5 freshness binding: repeating the introspection after the
// injected clock advances by N seconds MUST advance the JWT iat claim
// by N seconds. The OP reads the clock at sign time, so each response
// carries a fresh iat regardless of the underlying token's age.
//
// Spec: RFC 9701 §5.
func TestScenario_JINT_007_JWTIatProgressesWithClock(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-jint-007"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-jint-007-secret"

	clock := newAdvanceableClock(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	tk := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(
			op.WithFeature(feature.Introspect),
			op.WithAccessTokenTTL(1*time.Hour),
		),
	)
	rp, at := jintIssueAccessToken(t, tk, clientID, clientSecret, callback)

	first := jintIntrospect(t, tk, rp.ID, clientSecret, at, jintJWTAccept)
	body1, err := io.ReadAll(first.Body)
	_ = first.Body.Close()
	if err != nil {
		t.Fatalf("read first body: %v", err)
	}
	claims1 := jintParseJWT(t, tk, strings.TrimSpace(string(body1)))
	iat1, ok := claims1["iat"].(float64)
	if !ok {
		t.Fatalf("first response: iat is not a JSON number: %T", claims1["iat"])
	}

	const advance = 30 * time.Second
	clock.Advance(advance)

	second := jintIntrospect(t, tk, rp.ID, clientSecret, at, jintJWTAccept)
	body2, err := io.ReadAll(second.Body)
	_ = second.Body.Close()
	if err != nil {
		t.Fatalf("read second body: %v", err)
	}
	claims2 := jintParseJWT(t, tk, strings.TrimSpace(string(body2)))
	iat2, ok := claims2["iat"].(float64)
	if !ok {
		t.Fatalf("second response: iat is not a JSON number: %T", claims2["iat"])
	}

	got := int64(iat2) - int64(iat1)
	want := int64(advance.Seconds())
	if got != want {
		t.Fatalf("iat delta=%d want %d (iat1=%d iat2=%d)", got, want, int64(iat1), int64(iat2))
	}
}

// TestScenario_JINT_008_ActiveFalseShapeForJWTResponse checks that a
// JWT-asking introspection of an unknown token still returns 200 plus
// a signed envelope whose token_introspection claim is exactly
// {"active": false}. The envelope iss / aud / iat MUST still be
// populated so the relying party can verify the signature and bind
// the response to itself; only the inner introspection document
// collapses to the inactive shape (no sub, scope, exp, etc.).
//
// Spec: RFC 9701 §5 / RFC 7662 §2.2 (single inactive envelope).
func TestScenario_JINT_008_ActiveFalseShapeForJWTResponse(t *testing.T) {
	t.Parallel()

	const clientID = "rp-jint-008"
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-jint-008-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithFeature(feature.Introspect)))
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		Scopes:                  []string{"openid"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	resp := jintIntrospect(t, tk, rp.ID, clientSecret, "this-token-was-never-issued-by-the-op", jintJWTAccept)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, raw)
	}
	if got := resp.Header.Get("Content-Type"); got != jintJWTAccept {
		t.Fatalf("Content-Type=%q want %q", got, jintJWTAccept)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	raw := strings.TrimSpace(string(body))
	claims := jintParseJWT(t, tk, raw)

	if got, _ := claims["iss"].(string); got != tk.Issuer {
		t.Errorf("iss=%v want %q", claims["iss"], tk.Issuer)
	}
	if got, _ := claims["aud"].(string); got != rp.ID {
		t.Errorf("aud=%v want %q", claims["aud"], rp.ID)
	}
	if _, ok := claims["iat"].(float64); !ok {
		t.Errorf("iat must be a JSON number, got %T", claims["iat"])
	}

	nested, ok := claims["token_introspection"].(map[string]any)
	if !ok {
		t.Fatalf("token_introspection claim missing or not an object: %T", claims["token_introspection"])
	}
	if active, _ := nested["active"].(bool); active {
		t.Fatalf("token_introspection.active=true for unknown token; nested=%v", nested)
	}
	for _, leak := range []string{"sub", "client_id", "scope", "iat", "exp", "iss", "token_type", "aud", "jti"} {
		if _, present := nested[leak]; present {
			t.Errorf("inactive token_introspection leaked %q: %v", leak, nested)
		}
	}
}
