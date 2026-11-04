package scenarios_test

// Catalog: test/scenarios/catalog/fapi.yaml (FAPI-NNN, FAPI-V1-NNN, FAPI-V2-NNN)
// Spec:
//   - FAPI 1.0 Part 2 (Advanced) — Final
//   - FAPI 2.0 Security Profile — Final
//   - FAPI 2.0 Message Signing
//   - RFC 9101 — JAR / Request Object
//   - RFC 9126 — PAR
//   - RFC 6749 §3.2.1, §10
//   - RFC 9700 — OAuth 2.0 Security Best Current Practice
//   - RFC 8707 — Resource Indicators
//   - OIDC Core 1.0 §3.2 (hybrid), §15.5 (sender-constrained tokens)

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/internal/grants/refresh"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/profile"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

// fapiClock pins the OP's notion of "now" so JAR claim windows
// (iat / exp / nbf) and the FAPI MaxLifetime (60s) cap behave
// deterministically across runs. Mid-day UTC keeps the ±60s skew
// window well clear of day boundaries.
type fapiClock struct{ t time.Time }

func (c fapiClock) Now() time.Time { return c.t }

// fapiAnchor is the canonical "now" the FAPI scenarios pin the OP
// clock to. Sits comfortably inside reasonable epoch ranges so any
// claim-second arithmetic stays within int64 head-room.
var fapiAnchor = time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

// fapiFixture bundles a FAPI 2.0 Baseline-enabled provider with a
// confidential private_key_jwt client published with an inline
// ES256 JWKS. The fixture exposes the keypair so scenarios can sign
// both client_assertion JWTs and Request Object JWTs with the same
// material.
//
// FAPI 2.0 Baseline auto-enables PAR + JAR via the profile wiring,
// so every wire-form authorize MUST be pushed via /par first. DPoP
// is added to satisfy the disjunctive sender-constrained-token
// requirement (FAPI 2.0 §3.1.4 mandates DPoP OR mTLS); the bound
// scenarios never reach /token so the DPoP proof is not exercised
// here.
type fapiFixture struct {
	tk          *testkit.Provider
	clientID    string
	redirectURI string
	priv        *ecdsa.PrivateKey
	kid         string
	clock       fapiClock
}

// newFAPIFixture constructs a fresh FAPI 2.0 Baseline-enabled
// provider and registers a confidential private_key_jwt client.
// FAPI 2.0 §3.1.3 forbids public clients and shared-secret auth;
// private_key_jwt is the in-process choice. mTLS would need a
// gateway and is not exercised here.
func newFAPIFixture(t *testing.T) *fapiFixture {
	t.Helper()
	return newPrivateKeyJWTFixture(t, op.WithProfile(profile.FAPI2Baseline), op.WithFeature(feature.DPoP))
}

// newPrivateKeyJWTFixture is [newFAPIFixture] with the provider options
// supplied by the caller, so a scenario can contrast the FAPI 2.0
// posture with a provider that declares no profile.
func newPrivateKeyJWTFixture(t *testing.T, opts ...op.Option) *fapiFixture {
	t.Helper()
	clock := fapiClock{t: fapiAnchor}
	tk := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(opts...),
	)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	const kid = "rp-fapi-kid"
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
	const clientID = "rp-fapi"
	const redirect = "https://rp.testkit.invalid/callback"
	//nolint:gosec // G101: test fixture, not a real credential.
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		RedirectURIs:            []string{redirect},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "private_key_jwt",
		JWKs:                    jwksRaw,
	})
	return &fapiFixture{
		tk:          tk,
		clientID:    clientID,
		redirectURI: redirect,
		priv:        priv,
		kid:         kid,
		clock:       clock,
	}
}

// happyRequestObjectClaims returns the canonical FAPI 2.0 Request
// Object claim set every Request-Object scenario starts from. Tests
// mutate the returned map (drop a claim, push exp out of window)
// before signing. The exp window is held to 5 minutes which sits
// comfortably under the FAPI 2.0 Message Signing §5.6 60-minute
// MaxLifetime cap (wired in op_builders.go); rows that need to exceed
// the cap explicitly override exp (e.g. to 70 minutes).
func (f *fapiFixture) happyRequestObjectClaims() map[string]any {
	now := f.clock.t
	return map[string]any{
		"iss":                   f.clientID,
		"aud":                   f.tk.Issuer,
		"exp":                   now.Add(5 * time.Minute).Unix(),
		"iat":                   now.Unix(),
		"nbf":                   now.Unix(),
		"jti":                   freshFAPIJTI("ro"),
		"client_id":             f.clientID,
		"response_type":         "code",
		"redirect_uri":          f.redirectURI,
		"scope":                 "openid profile email",
		"state":                 "fapi-state",
		"nonce":                 "fapi-nonce",
		"code_challenge":        fapiPKCEChallenge,
		"code_challenge_method": "S256",
	}
}

// fapiPKCEChallenge is a pre-computed S256 challenge satisfying the
// authorize parser's PKCE format check. The bound scenarios do not
// exchange the code, so only the challenge is needed; the matching
// verifier ("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") is
// recorded here for the audit trail but not referenced.
const fapiPKCEChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

// signES256 serialises claims as a compact ES256 JWS using the
// fixture's keypair / kid.
func (f *fapiFixture) signES256(t *testing.T, claims map[string]any) string {
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
		(&josev4.SignerOptions{}).WithType("oauth-authz-req+jwt"),
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

// clientAssertion builds and signs a private_key_jwt assertion for
// the fixture's client. The audience is the OP's issuer as a single
// string, the one shape FAPI 2.0 Security Profile §5.3.2.1 admits.
func (f *fapiFixture) clientAssertion(t *testing.T) string {
	t.Helper()
	return f.clientAssertionFor(t, f.tk.Issuer)
}

// clientAssertionFor is [fapiFixture.clientAssertion] with the "aud"
// claim supplied by the caller: a string or a string slice.
func (f *fapiFixture) clientAssertionFor(t *testing.T, aud any) string {
	t.Helper()
	now := f.clock.t
	return f.signES256(t, map[string]any{
		"iss": f.clientID,
		"sub": f.clientID,
		"aud": aud,
		"jti": freshFAPIJTI("ca"),
		"iat": now.Unix(),
		"exp": now.Add(2 * time.Minute).Unix(),
	})
}

// freshFAPIJTI returns a unique jti string for the current test run.
// The FAPI 2.0 wiring rejects jti-less Request Objects (RFC 9101
// §10.8), so every signed envelope needs a distinct value.
func freshFAPIJTI(prefix string) string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		panic(err)
	}
	// Hex render keeps the value in the unreserved character set so
	// the value rides safely on either header or body.
	const hex = "0123456789abcdef"
	out := make([]byte, len(prefix)+1+2*len(buf))
	copy(out, prefix)
	out[len(prefix)] = '-'
	for i, b := range buf {
		out[len(prefix)+1+2*i] = hex[b>>4]
		out[len(prefix)+1+2*i+1] = hex[b&0x0f]
	}
	return string(out)
}

// parPost POSTs form to /oidc/par with the fixture's client_assertion
// stamped on automatically and returns the raw response. The
// transport does not follow redirects (PAR responds 201 / 400 / 401,
// never 302).
func (f *fapiFixture) parPost(t *testing.T, form url.Values) *http.Response {
	t.Helper()
	return f.parPostWithAssertion(t, form, f.clientAssertion(t))
}

// parPostWithAssertion is [fapiFixture.parPost] with the caller's
// client_assertion.
func (f *fapiFixture) parPostWithAssertion(t *testing.T, form url.Values, assertion string) *http.Response {
	t.Helper()
	if form == nil {
		form = url.Values{}
	}
	form.Set("client_assertion", assertion)
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	target := f.tk.Server.URL + "/oidc/par"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		target, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest /par: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := f.tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("Do /par: %v", err)
	}
	return resp
}

// fapiHappyForm returns a canonical /par form body satisfying every
// FAPI 2.0 baseline gate. Tests that exercise a rejection path call
// this and then mutate / drop a single field so the failure isolates
// to the change under test.
func (f *fapiFixture) fapiHappyForm() url.Values {
	return url.Values{
		"client_id":             {f.clientID},
		"response_type":         {"code"},
		"redirect_uri":          {f.redirectURI},
		"scope":                 {"openid profile email"},
		"state":                 {"fapi-state"},
		"nonce":                 {"fapi-nonce"},
		"code_challenge":        {fapiPKCEChallenge},
		"code_challenge_method": {"S256"},
	}
}

// fapiExpectError asserts resp is a 400 with the supplied error code
// and returns the decoded body for any further inspection.
func fapiExpectError(t *testing.T, resp *http.Response, wantCode string) map[string]any {
	t.Helper()
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 400 (%s); body=%s", resp.StatusCode, wantCode, string(body))
	}
	body := scenariokit.DecodeJSON(t, resp)
	if got, _ := body["error"].(string); got != wantCode {
		t.Errorf("error=%q want %q (body=%v)", got, wantCode, body)
	}
	return body
}

// TestScenario_FAPI_001_UserInfoRejectsQueryAccessToken is OOS — see catalog out_of_scope_reason.
func TestScenario_FAPI_001_UserInfoRejectsQueryAccessToken(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: FAPI-001 (see catalog out_of_scope_reason)")
}

// TestScenario_FAPI_002_AuthorizationRejectsBadResponseMode is OOS — see catalog out_of_scope_reason.
func TestScenario_FAPI_002_AuthorizationRejectsBadResponseMode(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: FAPI-002 (see catalog out_of_scope_reason)")
}

// TestScenario_FAPI_V1_010_HybridAcceptsNoPKCEWithIDToken is OOS — see catalog out_of_scope_reason.
func TestScenario_FAPI_V1_010_HybridAcceptsNoPKCEWithIDToken(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: FAPI-V1-010 (see catalog out_of_scope_reason)")
}

// TestScenario_FAPI_V1_011_PARRequiresPKCE is OOS — see catalog out_of_scope_reason.
func TestScenario_FAPI_V1_011_PARRequiresPKCE(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: FAPI-V1-011 (see catalog out_of_scope_reason)")
}

// TestScenario_FAPI_V1_012_CodeOnlyRequiresJARM is OOS — see catalog out_of_scope_reason.
func TestScenario_FAPI_V1_012_CodeOnlyRequiresJARM(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: FAPI-V1-012 (see catalog out_of_scope_reason)")
}

// TestScenario_FAPI_V1_013_JARRequestRequiresJARM is OOS — see catalog out_of_scope_reason.
func TestScenario_FAPI_V1_013_JARRequestRequiresJARM(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: FAPI-V1-013 (see catalog out_of_scope_reason)")
}

// TestScenario_FAPI_V1_014_RequestObjectRequiresExp is OOS — see catalog out_of_scope_reason.
func TestScenario_FAPI_V1_014_RequestObjectRequiresExp(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: FAPI-V1-014 (see catalog out_of_scope_reason)")
}

// TestScenario_FAPI_V1_015_RequestObjectRequiresNbf is OOS — see catalog out_of_scope_reason.
func TestScenario_FAPI_V1_015_RequestObjectRequiresNbf(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: FAPI-V1-015 (see catalog out_of_scope_reason)")
}

// TestScenario_FAPI_V1_016_RequestObjectExpNbfWindow is OOS — see catalog out_of_scope_reason.
func TestScenario_FAPI_V1_016_RequestObjectExpNbfWindow(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: FAPI-V1-016 (see catalog out_of_scope_reason)")
}

// TestScenario_FAPI_V1_017_HybridSignedRequestProducesIDToken is OOS — see catalog out_of_scope_reason.
func TestScenario_FAPI_V1_017_HybridSignedRequestProducesIDToken(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: FAPI-V1-017 (see catalog out_of_scope_reason)")
}

// TestScenario_FAPI_V2_020_CodeFlowRequiresPKCE pins the FAPI 2.0
// §5.3.2.1 PKCE-mandatory rule. Under FAPI 2.0 Baseline every
// authorization request reaches the OP via PAR; a /par push that
// drops code_challenge MUST be rejected with 400 invalid_request
// before any /authorize hop.
//
// The error_description is the v1.0 wire-form "code_challenge is
// required" — the catalog's upstream-style "Authorization Server policy
// requires PKCE" text is non-spec residue, but the error code and
// the rejection point are identical.
//
// Spec: FAPI 2.0 §5.3.2.1 / RFC 7636.
func TestScenario_FAPI_V2_020_CodeFlowRequiresPKCE(t *testing.T) {
	t.Parallel()

	f := newFAPIFixture(t)
	form := f.fapiHappyForm()
	form.Del("code_challenge")
	form.Del("code_challenge_method")
	resp := f.parPost(t, form)
	defer func() { _ = resp.Body.Close() }()

	body := fapiExpectError(t, resp, "invalid_request")
	desc, _ := body["error_description"].(string)
	if !strings.Contains(desc, "code_challenge") {
		t.Errorf("error_description=%q does not mention code_challenge", desc)
	}
}

// TestScenario_FAPI_V2_021_PrivateKeyJWTAudIsIssuer pins FAPI 2.0
// Security Profile §5.3.2.1: under the profile a client assertion
// authenticates only when its "aud" is the issuer as a single string.
// An array — even one holding only the issuer — and the token or PAR
// endpoint URL answer 401 invalid_client. A provider without the
// profile keeps accepting every one of those shapes.
//
// Spec: FAPI 2.0 Security Profile §5.3.2.1 / RFC 7523 §3.
func TestScenario_FAPI_V2_021_PrivateKeyJWTAudIsIssuer(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		aud     func(f *fapiFixture) any
		fapiOK  bool
		plainOK bool
	}{
		{"issuer string", func(f *fapiFixture) any { return f.tk.Issuer }, true, true},
		{"issuer array", func(f *fapiFixture) any { return []string{f.tk.Issuer} }, false, true},
		{"token endpoint URL", func(f *fapiFixture) any { return f.tk.Issuer + "/oidc/token" }, false, true},
		{"PAR endpoint URL", func(f *fapiFixture) any { return f.tk.Issuer + "/oidc/par" }, false, true},
		{"array with issuer and token endpoint", func(f *fapiFixture) any {
			return []string{f.tk.Issuer, f.tk.Issuer + "/oidc/token"}
		}, false, true},
	}
	run := func(t *testing.T, f *fapiFixture, aud any, wantOK bool) {
		t.Helper()
		resp := f.parPostWithAssertion(t, f.fapiHappyForm(), f.clientAssertionFor(t, aud))
		defer func() { _ = resp.Body.Close() }()
		if wantOK {
			if resp.StatusCode != http.StatusCreated {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("aud=%v: status=%d want 201; body=%s", aud, resp.StatusCode, body)
			}
			return
		}
		if resp.StatusCode != http.StatusUnauthorized {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("aud=%v: status=%d want 401; body=%s", aud, resp.StatusCode, body)
		}
		if got, _ := scenariokit.DecodeJSON(t, resp)["error"].(string); got != "invalid_client" {
			t.Errorf("aud=%v: error=%q want invalid_client", aud, got)
		}
	}
	for _, tc := range cases {
		t.Run("fapi2-baseline/"+tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFAPIFixture(t)
			run(t, f, tc.aud(f), tc.fapiOK)
		})
		t.Run("no-profile/"+tc.name, func(t *testing.T) {
			t.Parallel()
			f := newPrivateKeyJWTFixture(t, op.WithFeature(feature.PAR))
			run(t, f, tc.aud(f), tc.plainOK)
		})
	}
}

// TestScenario_FAPI_V2_022_RedirectURIAlwaysRequired pins the FAPI
// 2.0 §5.3.1.2 redirect_uri-required rule. v1.0 has no
// AllowOmittingSingleRegisteredRedirectUri knob to begin with —
// redirect_uri is universally required regardless of profile — but
// the wire shape catalog asserts is identical: a missing redirect_uri
// at /par MUST yield 400 invalid_request (rendered, no redirect
// target since the OP has no trusted URI to send the RP to).
//
// Spec: FAPI 2.0 §5.3.1.2 / RFC 6749 §3.1.2.
func TestScenario_FAPI_V2_022_RedirectURIAlwaysRequired(t *testing.T) {
	t.Parallel()

	f := newFAPIFixture(t)
	form := f.fapiHappyForm()
	form.Del("redirect_uri")
	resp := f.parPost(t, form)
	defer func() { _ = resp.Body.Close() }()

	body := fapiExpectError(t, resp, "invalid_request")
	desc, _ := body["error_description"].(string)
	if !strings.Contains(desc, "redirect_uri") {
		t.Errorf("error_description=%q does not mention redirect_uri", desc)
	}
}

// TestScenario_FAPI_V2_023_RequestObjectRequiresExpAndNbf pins the
// FAPI 2.0 §5.3.2.1 / RFC 9101 §6.1 rule that a signed Request
// Object MUST carry both exp and nbf. The fixture's profile flips
// JAR's RequireNbf knob on (op_builders.go); pushing a Request
// Object missing either claim through /par surfaces
// invalid_request_object.
//
// Spec: FAPI 2.0 §5.3.2.1 / RFC 9101 §6.1.
func TestScenario_FAPI_V2_023_RequestObjectRequiresExpAndNbf(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		drop string
	}{
		{name: "missing exp", drop: "exp"},
		{name: "missing nbf", drop: "nbf"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFAPIFixture(t)
			claims := f.happyRequestObjectClaims()
			delete(claims, tc.drop)
			signed := f.signES256(t, claims)
			form := url.Values{
				"client_id": {f.clientID},
				"request":   {signed},
			}
			resp := f.parPost(t, form)
			defer func() { _ = resp.Body.Close() }()
			fapiExpectError(t, resp, "invalid_request_object")
		})
	}
}

// TestScenario_FAPI_V2_024_RequestObjectExpNbfWindow pins the FAPI
// 2.0 §5.3.2.1 / Message Signing §5.6 cap on the request object's
// lifetime relative to "now". The library wires JAR's MaxLifetime to
// 60 minutes under any FAPI 2.0 profile (op_builders.go); an exp 70
// minutes ahead exceeds the cap and the JAR.assertExp gate surfaces
// ErrExpired with the "exp lies more than ... in the future" detail,
// mapped to invalid_request_object by writeJARError. The 70-minute
// target matches the OFCS conformance "ensure-request-object-with-
// exp-over-60-fails" probe so the rejection surface stays
// unambiguous.
//
// Spec: FAPI 2.0 §5.3.2.1 / FAPI 2.0 Message Signing §5.6.
func TestScenario_FAPI_V2_024_RequestObjectExpNbfWindow(t *testing.T) {
	t.Parallel()

	f := newFAPIFixture(t)
	claims := f.happyRequestObjectClaims()
	// 70 minutes > 60-minute cap → rejected by the FAPI MaxLifetime gate.
	claims["exp"] = f.clock.t.Add(70 * time.Minute).Unix()
	signed := f.signES256(t, claims)
	form := url.Values{
		"client_id": {f.clientID},
		"request":   {signed},
	}
	resp := f.parPost(t, form)
	defer func() { _ = resp.Body.Close() }()
	fapiExpectError(t, resp, "invalid_request_object")
}

// TestScenario_FAPI_V2_025_CodePKCEProducesQueryRedirect pins the
// FAPI 2.0 §5.3.1 success path: a valid Request Object carrying
// response_type=code with PKCE, pushed via /par, returns a 201 with
// a request_uri whose URN matches RFC 9126 §2.2. The test asserts
// the wire shape of the PAR success — a successful PAR push is the
// pre-condition for the eventual /authorize?request_uri redirect
// that FAPI 2.0 keeps on the query (NOT the fragment, NOT JARM by
// default; JARM is only enabled by the Message Signing profile).
//
// Spec: FAPI 2.0 §5.3.1 / RFC 9101 §5 / RFC 9126 §2.2.
func TestScenario_FAPI_V2_025_CodePKCEProducesQueryRedirect(t *testing.T) {
	t.Parallel()

	f := newFAPIFixture(t)
	claims := f.happyRequestObjectClaims()
	signed := f.signES256(t, claims)
	form := url.Values{
		"client_id": {f.clientID},
		"request":   {signed},
	}
	resp := f.parPost(t, form)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 201 (body=%s)", resp.StatusCode, string(body))
	}
	body := scenariokit.DecodeJSON(t, resp)
	uri, _ := body["request_uri"].(string)
	if !strings.HasPrefix(uri, "urn:ietf:params:oauth:request_uri:") {
		t.Errorf("request_uri=%q does not match RFC 9126 §2.2 prefix", uri)
	}
	expires, _ := body["expires_in"].(float64)
	if expires <= 0 {
		t.Errorf("expires_in=%v want >0", body["expires_in"])
	}
}

// TestScenario_FAPI_030_PolicyEnforcedRegardlessOfMetadata is OOS — see catalog out_of_scope_reason.
func TestScenario_FAPI_030_PolicyEnforcedRegardlessOfMetadata(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: FAPI-030 (see catalog out_of_scope_reason)")
}

// TestScenario_FAPI_031_DetachedSignatureCarriesSHashCHash is OOS — see catalog out_of_scope_reason.
func TestScenario_FAPI_031_DetachedSignatureCarriesSHashCHash(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: FAPI-031 (see catalog out_of_scope_reason)")
}

// TestScenario_FAPI_V2_026_RefreshTokenNotRotated pins FAPI 2.0
// Security Profile §5.3.2.1: under the profile a refresh_token grant
// answers with a fresh access token and no refresh_token, the presented
// refresh token stays redeemable, and retiring the grant still ends it.
//
// Spec: FAPI 2.0 Security Profile §5.3.2.1 / RFC 6749 §6.
func TestScenario_FAPI_V2_026_RefreshTokenNotRotated(t *testing.T) {
	t.Parallel()

	f := newFAPIFixture(t)
	const (
		subject = "fapi-refresh-subject"
		grantID = "fapi-refresh-grant"
	)
	scenariokit.SeedSubject(t, f.tk, subject)
	issuer, err := refresh.NewIssuer(refresh.IssuerConfig{
		Store: f.tk.Store.RefreshTokens(),
		Clock: f.clock,
		TTL:   time.Hour,
	})
	if err != nil {
		t.Fatalf("refresh.NewIssuer: %v", err)
	}
	refreshToken, err := issuer.Issue(context.Background(), refresh.IssueInput{
		ClientID: f.clientID,
		Subject:  subject,
		GrantID:  grantID,
		Scope:    []string{"openid", "profile"},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	key := newDPoPKey(t)

	redeem := func(t *testing.T) (int, map[string]any) {
		t.Helper()
		form := url.Values{
			"grant_type":            {"refresh_token"},
			"refresh_token":         {refreshToken},
			"client_id":             {f.clientID},
			"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
			"client_assertion":      {f.clientAssertion(t)},
		}
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
			f.tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatalf("NewRequest /token: %v", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("DPoP", makeDPoPProof(t, key, dpopProofOpts{
			htu: f.tk.Issuer + "/oidc/token",
			iat: f.clock.t,
			jti: freshFAPIJTI("dpop"),
		}))
		resp, err := f.tk.HTTPClient(nil).Do(req)
		if err != nil {
			t.Fatalf("Do /token: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode, scenariokit.DecodeJSON(t, resp)
	}

	for i := range 2 {
		status, body := redeem(t)
		if status != http.StatusOK {
			t.Fatalf("refresh %d: status=%d body=%v", i, status, body)
		}
		if at, _ := body["access_token"].(string); at == "" {
			t.Errorf("refresh %d: access_token missing: %v", i, body)
		}
		if _, ok := body["refresh_token"]; ok {
			t.Errorf("refresh %d: response carried refresh_token %v; the profile does not rotate", i, body["refresh_token"])
		}
	}
	rec, err := f.tk.Store.RefreshTokens().Find(context.Background(), refreshToken)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if rec.ConsumedAt != nil {
		t.Errorf("presented refresh token consumed at %v; it must stay redeemable", rec.ConsumedAt)
	}

	if err := f.tk.Store.RefreshTokens().RevokeByGrant(context.Background(), grantID); err != nil {
		t.Fatalf("RevokeByGrant: %v", err)
	}
	status, body := redeem(t)
	if status != http.StatusBadRequest {
		t.Fatalf("after grant revocation: status=%d body=%v, want 400", status, body)
	}
	if got, _ := body["error"].(string); got != "invalid_grant" {
		t.Errorf("after grant revocation: error=%q want invalid_grant", got)
	}
}
