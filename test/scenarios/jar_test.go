package scenarios_test

// Catalog: test/scenarios/catalog/jar.yaml (JAR-NNN)
// Spec:
//   - RFC 9101 — JWT-Secured Authorization Request (JAR)
//   - OpenID Connect Core 1.0 §6
//   - OpenID Connect Discovery 1.0 §3
//   - RFC 8628 §3.1 — Device Authorization Endpoint

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
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
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// jarFixedClock pins the OP's notion of "now" so JAR claim windows
// (iat / exp / nbf) behave deterministically across runs. Mid-day UTC
// keeps the ±60s skew window well clear of day boundaries.
type jarFixedClock struct{ t time.Time }

func (c jarFixedClock) Now() time.Time { return c.t }

// jarAnchor is the canonical "now" the JAR scenarios pin the OP clock
// to. The 5-minute exp / 60s skew defaults compose cleanly around this
// anchor without bumping into JTI store edge cases.
var jarAnchor = time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

// jarFixture bundles a JAR-enabled testkit Provider with a
// confidential client whose JWKs the harness controls. JAR scenarios
// reuse the harness across the rows below.
type jarFixture struct {
	tk          *testkit.Provider
	clientID    string
	redirectURI string
	priv        *ecdsa.PrivateKey
	kid         string
	clock       jarFixedClock
}

// newJARFixture constructs a fresh JAR-enabled provider and registers
// a public client with an inline ES256 JWKS. Public client keeps the
// /authorize wire form free of HTTP Basic so the tests focus on the
// JAR pipeline. Tests that need to drive a different alg / key call
// the publish helpers below to mutate the registered client.
func newJARFixture(t *testing.T) *jarFixture {
	t.Helper()
	clock := jarFixedClock{t: jarAnchor}
	tk := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(op.WithFeature(feature.JAR)),
	)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	const kid = "rp-jar-kid"
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
	const clientID = "rp-jar"
	const redirect = "https://rp.testkit.invalid/callback"
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:           clientID,
		PublicClient: true,
		RedirectURIs: []string{redirect},
		Scopes:       []string{"openid", "profile", "email"},
	})
	updated := *rp
	updated.JWKs = jwksRaw
	if err := tk.Store.UpdateClient(context.Background(), &updated); err != nil {
		t.Fatalf("UpdateClient(JWKs): %v", err)
	}
	return &jarFixture{
		tk:          tk,
		clientID:    clientID,
		redirectURI: redirect,
		priv:        priv,
		kid:         kid,
		clock:       clock,
	}
}

// pinAlg sets the registered client's RequestObjectSigningAlg so the
// JAR verifier rejects request objects signed with any other alg.
// Mirrors par_test.go's parJARFixture.pinAlg helper.
func (f *jarFixture) pinAlg(t *testing.T, alg string) {
	t.Helper()
	rp, err := f.tk.Store.GetClient(context.Background(), f.clientID)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	updated := *rp
	updated.RequestObjectSigningAlg = alg
	if err := f.tk.Store.UpdateClient(context.Background(), &updated); err != nil {
		t.Fatalf("UpdateClient(alg pin): %v", err)
	}
}

// publishPS256Key adds a freshly-generated PS256 key to the client's
// published JWKS (alongside the existing ES256 key) and returns the
// new private key. The dual JWKS lets a test sign with PS256 while
// the verifier still resolves the kid; a per-client alg pin can then
// drive the rejection.
func (f *jarFixture) publishPS256Key(t *testing.T, psKID string) *rsa.PrivateKey {
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
	rp, err := f.tk.Store.GetClient(context.Background(), f.clientID)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	updated := *rp
	updated.JWKs = jwksRaw
	if err := f.tk.Store.UpdateClient(context.Background(), &updated); err != nil {
		t.Fatalf("UpdateClient(JWKS dual): %v", err)
	}
	return rsaPriv
}

// happyClaims returns the standard request-object claim set every JAR
// scenario starts from. Tests mutate the returned map (drop a claim,
// override response_type, etc.) before signing. Each call mints a
// fresh jti so successive request objects in the same test do not
// collide on the consumed-jti gate (RFC 9101 §10.8).
func (f *jarFixture) happyClaims() map[string]any {
	now := f.clock.t
	return map[string]any{
		"iss":                   f.clientID,
		"aud":                   f.tk.Issuer,
		"exp":                   now.Add(2 * time.Minute).Unix(),
		"iat":                   now.Unix(),
		"nbf":                   now.Unix(),
		"jti":                   freshJARScenarioJTI(),
		"client_id":             f.clientID,
		"response_type":         "code",
		"redirect_uri":          f.redirectURI,
		"scope":                 "openid profile email",
		"state":                 "jar-state",
		"nonce":                 "jar-nonce",
		"code_challenge":        jarPKCEChallenge,
		"code_challenge_method": "S256",
	}
}

// freshJARScenarioJTI mints a 128-bit random JWT identifier suitable
// for a single end-to-end request object. crypto/rand is used directly
// so a single test never produces colliding values across successive
// request objects.
func freshJARScenarioJTI() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return "jar-jti-" + hex.EncodeToString(b[:])
}

// jarPKCEChallenge / jarPKCEVerifier are a pre-computed S256 PKCE
// pair the JAR scenarios reuse. The challenge is the SHA-256 of the
// verifier expressed as base64url-no-pad, so the value satisfies the
// authorize parser's PKCE format check. Tests that drive the happy
// path through /authorize do not exchange the code, so the verifier
// is unused beyond satisfying the format gate.
const (
	jarPKCEChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	jarPKCEVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)

// signES256 serialises claims as a compact ES256 JWS using the
// fixture's keypair / kid.
func (f *jarFixture) signES256(t *testing.T, claims map[string]any) string {
	t.Helper()
	return signWithJOSE(t, josev4.SigningKey{
		Algorithm: josev4.ES256,
		Key: josev4.JSONWebKey{
			Key:       f.priv,
			KeyID:     f.kid,
			Algorithm: string(josev4.ES256),
			Use:       "sig",
		},
	}, claims)
}

// signPS256 serialises claims as a compact PS256 JWS using the
// supplied keypair / kid.
func (f *jarFixture) signPS256(t *testing.T, priv *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	return signWithJOSE(t, josev4.SigningKey{
		Algorithm: josev4.PS256,
		Key: josev4.JSONWebKey{
			Key:       priv,
			KeyID:     kid,
			Algorithm: string(josev4.PS256),
			Use:       "sig",
		},
	}, claims)
}

// signWithJOSE is the shared signer-construction path. Centralising
// it keeps every per-alg helper at a single ES256/PS256/etc dispatch.
func signWithJOSE(t *testing.T, key josev4.SigningKey, claims map[string]any) string {
	t.Helper()
	signer, err := josev4.NewSigner(key, (&josev4.SignerOptions{}).WithType("oauth-authz-req+jwt"))
	if err != nil {
		t.Fatalf("NewSigner(%s): %v", key.Algorithm, err)
	}
	out, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("Serialize(%s): %v", key.Algorithm, err)
	}
	return out
}

// authorizeGet issues GET /oidc/auth with the supplied wire values
// and returns the raw response. The transport does not follow
// redirects so tests can inspect the immediate Location / status.
func (f *jarFixture) authorizeGet(t *testing.T, values url.Values) *http.Response {
	t.Helper()
	target := f.tk.Server.URL + "/oidc/auth?" + values.Encode()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest /authorize: %v", err)
	}
	resp, err := f.tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("Do /authorize: %v", err)
	}
	return resp
}

// jarDecodeJSON parses resp.Body as a JSON object map. Mirrors the
// helpers in par_test.go so the JAR scenarios stay self-contained.
func jarDecodeJSON(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	out := map[string]any{}
	if len(raw) == 0 {
		return out
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("Unmarshal %s: %v", raw, err)
	}
	return out
}

// expectJARError asserts a 400 response with the supplied error code
// on resp. The body is consumed so the caller does not need to defer
// Close itself.
func expectJARError(t *testing.T, resp *http.Response, wantCode string) map[string]any {
	t.Helper()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 (%s)", resp.StatusCode, wantCode)
	}
	body := jarDecodeJSON(t, resp)
	if got, _ := body["error"].(string); got != wantCode {
		t.Errorf("error=%q want %q (body=%v)", got, wantCode, body)
	}
	return body
}

// expectInteractionRedirect asserts resp is a 302 to /oidc/interaction
// (the canonical /authorize success path). Used by the happy-path JAR
// scenarios so the test fails loudly if the verifier rejected.
func expectInteractionRedirect(t *testing.T, resp *http.Response) *url.URL {
	t.Helper()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 302 (body=%s)", resp.StatusCode, string(body))
	}
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	if !strings.HasPrefix(loc.Path, "/oidc/interaction/") {
		t.Fatalf("Location.Path=%q want /oidc/interaction/...", loc.Path)
	}
	return loc
}

// TestScenario_JAR_001_DiscoveryRequestParameterSupported confirms
// that with [feature.JAR] enabled (and no FAPI 2.0 Message Signing
// profile asserting require_signed_request_object), the discovery
// document advertises request_parameter_supported=true and does NOT
// include the require_signed_request_object signal.
//
// Spec: RFC 9101 §10.5 / OIDC Discovery §3.
func TestScenario_JAR_001_DiscoveryRequestParameterSupported(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithFeature(feature.JAR)))
	target := tk.Server.URL + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	doc := jarDecodeJSON(t, resp)
	if got, _ := doc["request_parameter_supported"].(bool); !got {
		t.Errorf("request_parameter_supported=%v want true", doc["request_parameter_supported"])
	}
	if _, ok := doc["require_signed_request_object"]; ok {
		t.Errorf("require_signed_request_object should be absent without Message Signing profile (doc=%v)", doc)
	}
}

// TestScenario_JAR_002_DiscoveryRequireSignedRequestObject is OOS — see catalog out_of_scope_reason.
func TestScenario_JAR_002_DiscoveryRequireSignedRequestObject(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: JAR-002 (see catalog out_of_scope_reason)")
}

// TestScenario_JAR_003_RequestObjectOverridesOuterParams confirms RFC 9101
// §6.1 / OIDC Core §6.1: every authorization parameter inside the signed
// request object overrides the wire-level value of the same name. The
// test pins the contract by passing an attacker-controlled redirect_uri
// on the wire alongside a registered redirect_uri in the JWT — if the
// JWT did NOT win, the verifier would reject the unregistered URI; the
// fact that the OP redirects to /oidc/interaction proves the JWT
// override fired.
//
// v1.0 does not ship a /device_authorization endpoint (no
// feature.DeviceFlow), so the catalog row's "and the device
// authorization endpoint" clause has no v1.0 surface; this binding
// covers the /authorize half, which is the only endpoint where JAR is
// honoured today.
//
// Spec: RFC 9101 §5 / OIDC Core §6.1.
func TestScenario_JAR_003_RequestObjectOverridesOuterParams(t *testing.T) {
	t.Parallel()

	f := newJARFixture(t)
	claims := f.happyClaims()
	signed := f.signES256(t, claims)
	values := url.Values{
		"client_id": {f.clientID},
		// Outer redirect_uri is unregistered: if it survived the merge,
		// the authorize parser would reject with invalid_request before
		// reaching /oidc/interaction.
		"redirect_uri":  {"https://attacker.example/cb"},
		"response_type": {"code"},
		"request":       {signed},
	}
	resp := f.authorizeGet(t, values)
	defer func() { _ = resp.Body.Close() }()
	expectInteractionRedirect(t, resp)
}

// TestScenario_JAR_004_NumericClaimsCoercedToString confirms numeric
// request-object claims (canonical example: max_age) are coerced to
// strings before downstream processing — the JAR merger lowers
// numeric JSON values onto the wire url.Values shape so the authorize
// parser sees a single string-keyed representation.
//
// The test drives the happy path through to /oidc/interaction; if the
// coercion failed (e.g. the merger left max_age as a typed JSON
// number that the authorize parser cannot consume), the request would
// be rejected before the interaction redirect.
//
// Spec: OIDC Core §6.1 / RFC 9101 §6.1.
func TestScenario_JAR_004_NumericClaimsCoercedToString(t *testing.T) {
	t.Parallel()

	f := newJARFixture(t)
	claims := f.happyClaims()
	claims["max_age"] = 60 // numeric JSON number; the merger MUST coerce.
	signed := f.signES256(t, claims)
	resp := f.authorizeGet(t, url.Values{
		"client_id": {f.clientID},
		"request":   {signed},
	})
	defer func() { _ = resp.Body.Close() }()
	expectInteractionRedirect(t, resp)
}

// TestScenario_JAR_005_DuplicateScopeArrayRejected is OOS — see catalog out_of_scope_reason.
func TestScenario_JAR_005_DuplicateScopeArrayRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: JAR-005 (see catalog out_of_scope_reason)")
}

// TestScenario_JAR_006_ClaimsAsStringPassthrough is OOS — see catalog out_of_scope_reason.
func TestScenario_JAR_006_ClaimsAsStringPassthrough(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: JAR-006 (see catalog out_of_scope_reason)")
}

// TestScenario_JAR_007_ClaimsAsObjectReserialised confirms a "claims"
// parameter delivered as a JSON object in the request object is
// accepted and re-serialised back to a canonical JSON string before
// being handed to the authorize parser. The merger's mergeJSONClaims
// allow-list covers "claims" / "authorization_details"; both arrive
// inside the JWT as decoded shapes and are re-encoded so the
// downstream parser sees the bytes it would have on a plain wire.
//
// Spec: OIDC Core §5.5 / §6.1.
func TestScenario_JAR_007_ClaimsAsObjectReserialised(t *testing.T) {
	t.Parallel()

	f := newJARFixture(t)
	claims := f.happyClaims()
	claims["claims"] = map[string]any{
		"id_token": map[string]any{
			"email": map[string]any{"essential": true},
		},
	}
	signed := f.signES256(t, claims)
	resp := f.authorizeGet(t, url.Values{
		"client_id": {f.clientID},
		"request":   {signed},
	})
	defer func() { _ = resp.Body.Close() }()
	expectInteractionRedirect(t, resp)
}

// TestScenario_JAR_008_ClockSkewToleranceAccepted confirms that a
// request object whose iat is slightly in the future but within the
// configured clock-skew tolerance is accepted. The verifier defaults
// to a 60-second future-skew window; the test moves iat 30 seconds
// forward and asserts the /authorize redirect to /oidc/interaction
// succeeds.
//
// Spec: RFC 9101 §10.8 / RFC 7519 §4.1.6.
func TestScenario_JAR_008_ClockSkewToleranceAccepted(t *testing.T) {
	t.Parallel()

	f := newJARFixture(t)
	claims := f.happyClaims()
	now := f.clock.t
	claims["iat"] = now.Add(30 * time.Second).Unix()
	claims["nbf"] = now.Add(30 * time.Second).Unix()
	signed := f.signES256(t, claims)
	resp := f.authorizeGet(t, url.Values{
		"client_id": {f.clientID},
		"request":   {signed},
	})
	defer func() { _ = resp.Body.Close() }()
	expectInteractionRedirect(t, resp)
}

// TestScenario_JAR_009_HS256AcceptedForRegisteredClient is OOS — see catalog out_of_scope_reason.
func TestScenario_JAR_009_HS256AcceptedForRegisteredClient(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: JAR-009 (see catalog out_of_scope_reason)")
}

// TestScenario_JAR_010_ExpiredSecretRejected is OUT-OF-SCOPE for v1.0.
// The catalog row asserts that an HS256-signed request object whose
// backing client secret has expired is rejected with
// invalid_request_object. v1.0's project-wide JOSE allow-list refuses
// every HMAC algorithm at parse time (internal/jose Algorithm.IsAllowed
// rejects HS256 / HS384 / HS512); a request object signed under HS256
// fails before the verifier can read the symmetric secret, so the
// "expired secret" sub-state cannot be reached on the wire.
//
// Standing directive: HS256 is the discontinued JAR alg; the unused
// expired-secret branch carries no remaining security surface in v1.0.
//
// Spec: RFC 9101 §6.1 / OIDC Core §6.3.
func TestScenario_JAR_010_ExpiredSecretRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: JAR-010 (see catalog out_of_scope_reason)")
}

// TestScenario_JAR_011_NestedRequestParameterForbidden confirms RFC 9101
// §10.4 / §6.1: a request object that nests a "request" claim inside
// its payload is rejected. The verifier's assertNoNestedRequest gate
// surfaces ErrNestedRequest, which writeJAREnvelopeError maps to
// invalid_request_object.
//
// Spec: RFC 9101 §10.4 / OIDC Core §6.1.
func TestScenario_JAR_011_NestedRequestParameterForbidden(t *testing.T) {
	t.Parallel()

	f := newJARFixture(t)
	claims := f.happyClaims()
	claims["request"] = "eyJhbGciOiJFUzI1NiJ9.body.sig"
	signed := f.signES256(t, claims)
	resp := f.authorizeGet(t, url.Values{
		"client_id": {f.clientID},
		"request":   {signed},
	})
	defer func() { _ = resp.Body.Close() }()
	expectJARError(t, resp, "invalid_request_object")
}

// TestScenario_JAR_012_NestedRequestUriForbidden confirms RFC 9101
// §10.4: a request object that nests a "request_uri" claim is
// rejected with invalid_request_object. The check is symmetric to
// JAR-011 but covers the alternative nesting vector.
//
// Spec: RFC 9101 §10.4.
func TestScenario_JAR_012_NestedRequestUriForbidden(t *testing.T) {
	t.Parallel()

	f := newJARFixture(t)
	claims := f.happyClaims()
	claims["request_uri"] = "https://rp.testkit.invalid/req"
	signed := f.signES256(t, claims)
	resp := f.authorizeGet(t, url.Values{
		"client_id": {f.clientID},
		"request":   {signed},
	})
	defer func() { _ = resp.Body.Close() }()
	expectJARError(t, resp, "invalid_request_object")
}

// TestScenario_JAR_013_ResponseModeFragmentHonoured is OOS — see catalog out_of_scope_reason.
func TestScenario_JAR_013_ResponseModeFragmentHonoured(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: JAR-013 (see catalog out_of_scope_reason)")
}

// TestScenario_JAR_014_UnsupportedResponseModeRejected confirms a
// request object that carries a response_mode the OP does not support
// is rejected with unsupported_response_mode. v1.0's authorize
// validator admits {"", "query", "form_post"} plus the four JARM
// modes; any other value (here, "fragment", which v1.0 does NOT ship
// because response_type=code is the only advertised type) is rejected.
//
// The error envelope shape is the legacy redirect-mode error envelope
// because the request reached the authorize endpoint as code-flow:
// the OP redirects to the registered redirect_uri with
// error=unsupported_response_mode in the query.
//
// Spec: RFC 6749 §3.1.2 / OIDC Core §6.1.
func TestScenario_JAR_014_UnsupportedResponseModeRejected(t *testing.T) {
	t.Parallel()

	f := newJARFixture(t)
	claims := f.happyClaims()
	claims["response_mode"] = "fragment"
	signed := f.signES256(t, claims)
	resp := f.authorizeGet(t, url.Values{
		"client_id": {f.clientID},
		"request":   {signed},
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d want 302 (legacy redirect-mode error)", resp.StatusCode)
	}
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	if got := loc.Query().Get("error"); got != "unsupported_response_mode" {
		t.Errorf("error=%q want unsupported_response_mode (loc=%s)", got, loc.String())
	}
}

// TestScenario_JAR_015_ResponseTypeMismatchRejected is OUT-OF-SCOPE
// for v1.0. The catalog row asserts that an outer response_type that
// disagrees with the JWT response_type is rejected with
// invalid_request_object ("response_type mismatch"). v1.0's contract
// (internal/jar Merge + RFC 9101 §6.1) is the JWT silently overrides
// the outer wire value: there is no "mismatch" gate, just a silent
// merge precedence. PAR-021 already exercises the override-wins
// contract with a different response_type pairing; reproducing the
// override here would assert a non-existent gate.
//
// The unsupported_response_type path (e.g. "id_token") is covered by
// the response_type=code-only validator at parse time, not by JAR.
//
// Spec: RFC 9101 §5 / OIDC Core §6.1.
func TestScenario_JAR_015_ResponseTypeMismatchRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: JAR-015 (see catalog out_of_scope_reason)")
}

// TestScenario_JAR_016_StatePreservedOnError is OOS — see catalog out_of_scope_reason.
func TestScenario_JAR_016_StatePreservedOnError(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: JAR-016 (see catalog out_of_scope_reason)")
}

// TestScenario_JAR_017_ClientIDMismatchRejected is OUT-OF-SCOPE for
// v1.0. The catalog row asserts that an outer client_id that
// disagrees with the JWT client_id is rejected with
// invalid_request_object at "either the authorization or device
// authorization endpoint". Two v1.0 deltas:
//
//  1. v1.0 emits "invalid_request" (not invalid_request_object) for
//     the wire-vs-JWT client_id mismatch. The taxonomy choice lives
//     in writeJAREnvelopeError: the mismatch is treated as a wire
//     consistency violation rather than a request-object format
//     failure. PAR-023 already binds this contract on the /par side;
//     the /authorize side shares the same code path, so the
//     wire-level behaviour is identical.
//  2. v1.0 does not ship a /device_authorization endpoint
//     (no feature.DeviceFlow), so the row's device-endpoint half has
//     no surface to bind.
//
// Spec: RFC 9101 §5.
func TestScenario_JAR_017_ClientIDMismatchRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: JAR-017 (see catalog out_of_scope_reason)")
}

// TestScenario_JAR_018_MalformedJWTRejected confirms RFC 9101 §6.1 /
// RFC 7519 §7.2: a "request" parameter that is not a syntactically
// valid compact-serialised JWS is rejected with invalid_request_object.
// The verifier's Parse step surfaces ErrParse, which maps to the
// canonical "request object is malformed" envelope.
//
// Spec: RFC 9101 §6.1 / RFC 7519 §7.2.
func TestScenario_JAR_018_MalformedJWTRejected(t *testing.T) {
	t.Parallel()

	f := newJARFixture(t)
	resp := f.authorizeGet(t, url.Values{
		"client_id": {f.clientID},
		"request":   {"definitely.notsigned.jwt"},
	})
	defer func() { _ = resp.Body.Close() }()
	expectJARError(t, resp, "invalid_request_object")
}

// TestScenario_JAR_019_PreregisteredAlgEnforced confirms RFC 9101 §6.1
// / OIDC Core §6.3: when a client publishes
// request_object_signing_alg=ES256 and pushes a Request Object signed
// under PS256, the OP rejects with invalid_request_object even
// though PS256 is on the OP's project-wide allow-list. The pin lives
// on store.Client.RequestObjectSigningAlg; the verifier rejects the
// alg-mismatch before signature verification.
//
// (Mirrors PAR-022 on the /par surface; the /authorize gate shares
// the same verifier, so the same code path is exercised.)
//
// Spec: RFC 9101 §6.1 / OIDC Core §6.3.
func TestScenario_JAR_019_PreregisteredAlgEnforced(t *testing.T) {
	t.Parallel()

	f := newJARFixture(t)
	f.pinAlg(t, "ES256")
	const psKID = "rp-jar-ps-kid"
	psPriv := f.publishPS256Key(t, psKID)
	signed := f.signPS256(t, psPriv, psKID, f.happyClaims())
	resp := f.authorizeGet(t, url.Values{
		"client_id": {f.clientID},
		"request":   {signed},
	})
	defer func() { _ = resp.Body.Close() }()
	expectJARError(t, resp, "invalid_request_object")
}

// TestScenario_JAR_020_UnsupportedAlgRejected confirms RFC 9101 §10.1:
// a request object whose JWS "alg" header advertises a value outside
// the OP's configured allow-list is rejected with
// invalid_request_object. v1.0 ships an asymmetric-only allow-list
// (RS256 / PS256 / ES256 / EdDSA); "alg":"none" is the canonical
// downgrade attempt RFC 7519 §6 / RFC 8725 §2.1 warn against, and
// internal/jose ParseSigned rejects it before any signature work.
//
// The hand-crafted unsigned token is base64url("alg=none") + empty
// body + empty signature so the parser reaches the alg gate without
// stumbling on a header decode error first.
//
// Spec: RFC 9101 §10.1 / RFC 8725 §2.1.
func TestScenario_JAR_020_UnsupportedAlgRejected(t *testing.T) {
	t.Parallel()

	f := newJARFixture(t)
	const noneJWT = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJycC1qYXIifQ."
	resp := f.authorizeGet(t, url.Values{
		"client_id": {f.clientID},
		"request":   {noneJWT},
	})
	defer func() { _ = resp.Body.Close() }()
	expectJARError(t, resp, "invalid_request_object")
}

// TestScenario_JAR_021_SignatureVerificationFails confirms RFC 9101
// §6.1 / RFC 7515 §5.2: a request object signed with a key that does
// not match the published JWKS is rejected with
// invalid_request_object. The test signs with a fresh ES256 key
// while the published JWKS still references the fixture's original
// key (same kid on the JWS header drives a hit in the keyset, but
// the signature does not verify against the registered public key).
//
// Spec: RFC 9101 §6.1 / RFC 7515 §5.2.
func TestScenario_JAR_021_SignatureVerificationFails(t *testing.T) {
	t.Parallel()

	f := newJARFixture(t)
	// Sign with a different ES256 keypair under the same kid the
	// fixture published. The verifier's pickKey resolves the entry,
	// but JWS.Verify against the public side fails — the
	// ErrSigInvalid sentinel maps to invalid_request_object.
	otherPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	signed := signWithJOSE(t, josev4.SigningKey{
		Algorithm: josev4.ES256,
		Key: josev4.JSONWebKey{
			Key:       otherPriv,
			KeyID:     f.kid,
			Algorithm: string(josev4.ES256),
			Use:       "sig",
		},
	}, f.happyClaims())
	resp := f.authorizeGet(t, url.Values{
		"client_id": {f.clientID},
		"request":   {signed},
	})
	defer func() { _ = resp.Body.Close() }()
	expectJARError(t, resp, "invalid_request_object")
}

// TestScenario_JAR_022_RegistrationClaimForbidden is OOS — see catalog out_of_scope_reason.
func TestScenario_JAR_022_RegistrationClaimForbidden(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: JAR-022 (see catalog out_of_scope_reason)")
}

// TestScenario_JAR_023_UnknownMembersIgnored confirms that a request
// object carrying claims the OP does not recognise is accepted and
// the unknown members are silently ignored (RFC 9101 §6.1 leaves
// unknown members "non-actionable"). The merger projects every
// non-allow-listed claim onto the wire form via stringifyClaim; the
// authorize parser then drops anything outside its own known-keys
// set, so the redirect to /oidc/interaction proves the unknown member
// did not derail the request.
//
// Spec: RFC 9101 §6.1 / OIDC Core §6.1.
func TestScenario_JAR_023_UnknownMembersIgnored(t *testing.T) {
	t.Parallel()

	f := newJARFixture(t)
	claims := f.happyClaims()
	claims["x_vendor_extension"] = "ignored-by-spec"
	signed := f.signES256(t, claims)
	resp := f.authorizeGet(t, url.Values{
		"client_id": {f.clientID},
		"request":   {signed},
	})
	defer func() { _ = resp.Body.Close() }()
	expectInteractionRedirect(t, resp)
}

// Suppress "unused" lint on the PKCE verifier constant: scenarios
// here drive /authorize → /oidc/interaction (no /token redemption),
// so jarPKCEVerifier is documented above next to its challenge but
// not exercised on the wire. A future code-redemption JAR scenario
// would consume it.
var _ = jarPKCEVerifier
