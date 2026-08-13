package scenarios_test

// Catalog: test/scenarios/catalog/dpop.yaml (DPOP-NNN)
// Spec:
//   - RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP)
//   - RFC 6749 — OAuth 2.0 Authorization Framework
//   - RFC 6750 — OAuth 2.0 Bearer Token Usage
//   - OIDC Core 1.0
//   - RFC 9126 — Pushed Authorization Requests
//   - RFC 8628 — Device Authorization Grant
//   - OpenID CIBA Core 1.0

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
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

// dpopFixedClock pins the OP's notion of "now" for the DPoP scenarios so
// proof iat values are deterministic. testkit.WithClock + the dpop
// verifier's iat window (60s) collapse onto a single anchor; tests that
// drive expiry / freshness scenarios offset their proof iat from this
// value.
type dpopFixedClock struct{ t time.Time }

func (c dpopFixedClock) Now() time.Time { return c.t }

// dpopAnchor is the canonical "now" value DPoP scenarios pin the OP
// clock to. Mid-day UTC keeps ±60s offsets well clear of day boundaries.
var dpopAnchor = time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

// dpopKey bundles a freshly-generated ECDSA P-256 signer with its
// JOSE-formatted public JWK and the SHA-256 thumbprint downstream code
// stamps onto cnf.jkt. The struct is the rough analogue of the
// internal/dpop test-package's dpopProofKey, ported to the public
// scenariokit-friendly surface.
type dpopKey struct {
	priv crypto.Signer
	jwk  josev4.JSONWebKey
	jkt  string
}

// newDPoPKey returns a fresh ECDSA P-256 keypair plus the JWK / thumbprint
// projection RFC 9449 §4.2 mandates on every proof header.
func newDPoPKey(t *testing.T) dpopKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	jwk := josev4.JSONWebKey{Key: &priv.PublicKey, Algorithm: string(josev4.ES256), Use: "sig"}
	jkt, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	return dpopKey{
		priv: priv,
		jwk:  jwk,
		jkt:  base64.RawURLEncoding.EncodeToString(jkt),
	}
}

// dpopProofOpts carries the per-call proof-shape inputs that scenarios
// vary. Defaults mirror RFC 9449 §4.2 / §4.3 happy-path values; any field
// the caller does not set falls back to a spec-conforming default
// computed inside [makeDPoPProof].
type dpopProofOpts struct {
	method  string    // HTTP method; default "POST".
	htu     string    // canonical request URL; required.
	iat     time.Time // proof iat; defaults to dpopAnchor.
	jti     string    // jti; defaults to a deterministic per-call value.
	ath     string    // optional ath claim (resource-server flows).
	nonce   string    // optional nonce claim.
	typ     string    // JOSE typ header; defaults to "dpop+jwt".
	omitJTI bool      // when true the jti claim is omitted entirely.
}

// makeDPoPProof builds a compact-serialised JWS that the OP's verifier
// admits when opts are spec-conforming, and that drives a target
// negative path when the caller mutates a single field.
func makeDPoPProof(t *testing.T, key dpopKey, opts dpopProofOpts) string {
	t.Helper()
	method := opts.method
	if method == "" {
		method = http.MethodPost
	}
	iat := opts.iat
	if iat.IsZero() {
		iat = dpopAnchor
	}
	jti := opts.jti
	if jti == "" {
		jti = "jti-" + iat.Format("150405.000000000")
	}
	typ := opts.typ
	if typ == "" {
		typ = "dpop+jwt"
	}
	signerOpts := (&josev4.SignerOptions{}).
		WithType(josev4.ContentType(typ)).
		WithHeader("jwk", key.jwk)
	signer, err := josev4.NewSigner(
		josev4.SigningKey{Algorithm: josev4.ES256, Key: key.priv},
		signerOpts,
	)
	if err != nil {
		t.Fatalf("makeDPoPProof: NewSigner: %v", err)
	}
	claims := map[string]any{
		"htm": method,
		"htu": opts.htu,
		"iat": iat.Unix(),
	}
	if !opts.omitJTI {
		claims["jti"] = jti
	}
	if opts.ath != "" {
		claims["ath"] = opts.ath
	}
	if opts.nonce != "" {
		claims["nonce"] = opts.nonce
	}
	tok, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("makeDPoPProof: Serialize: %v", err)
	}
	return tok
}

// makeDPoPProofRawClaims signs a proof from a caller-supplied claim map
// instead of [dpopProofOpts]. It exists for the claim-type scenarios:
// [dpopProofOpts] models every claim as a Go string, so a proof whose
// jti is a number or an object — the shape RFC 9449 §4.2 forbids — can
// only be built by handing the serialiser the raw map.
func makeDPoPProofRawClaims(t *testing.T, key dpopKey, claims map[string]any) string {
	t.Helper()
	signerOpts := (&josev4.SignerOptions{}).
		WithType(josev4.ContentType("dpop+jwt")).
		WithHeader("jwk", key.jwk)
	signer, err := josev4.NewSigner(
		josev4.SigningKey{Algorithm: josev4.ES256, Key: key.priv},
		signerOpts,
	)
	if err != nil {
		t.Fatalf("makeDPoPProofRawClaims: NewSigner: %v", err)
	}
	tok, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("makeDPoPProofRawClaims: Serialize: %v", err)
	}
	return tok
}

// dpopFixture bundles a DPoP-enabled testkit Provider with a registered
// confidential client suitable for /token redemptions. The fixture pins
// testkit.WithClock to dpopAnchor so proof iat values are deterministic
// across the suite.
type dpopFixture struct {
	tk       *testkit.Provider
	clock    dpopFixedClock
	clientID string
	secret   string
	redirect string
}

// newDPoPFixture builds a DPoP-enabled provider with a confidential
// client registered for the authorization_code + refresh_token grant.
// extraOpts is appended last so callers can layer on PAR / other
// features without reimplementing the boilerplate.
func newDPoPFixture(t *testing.T, extraOpts ...op.Option) *dpopFixture {
	t.Helper()
	clock := dpopFixedClock{t: dpopAnchor}
	opts := make([]op.Option, 0, 1+len(extraOpts))
	opts = append(opts, op.WithFeature(feature.DPoP))
	opts = append(opts, extraOpts...)
	tk := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(opts...),
	)
	const secret = "rp-dpop-secret" //nolint:gosec // not a credential — opaque test fixture secret.
	hash, err := op.HashClientSecret(secret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	const clientID = "rp-dpop"
	const redirect = "https://rp.testkit.invalid/callback"
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{redirect},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	return &dpopFixture{
		tk:       tk,
		clock:    clock,
		clientID: clientID,
		secret:   secret,
		redirect: redirect,
	}
}

// tokenURL is the canonical /token endpoint URL for the fixture's OP.
func (f *dpopFixture) tokenURL() string { return f.tk.Server.URL + "/oidc/token" }

// runFlow drives /authorize → consent → callback and returns the
// authorization code together with the PKCE verifier scenariokit minted
// inline. Callers exchange the code at /token with their preferred
// DPoP proof shape.
func (f *dpopFixture) runFlow(t *testing.T) (code, verifier string) {
	t.Helper()
	pkce := scenariokit.NewPKCEPair("")
	res := scenariokit.RunCodeFlow(t, f.tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    f.clientID,
		RedirectURI: f.redirect,
		PKCE:        pkce,
	})
	if res.Code == "" {
		t.Fatalf("runFlow: no code in callback (%+v)", res)
	}
	return res.Code, pkce.Verifier
}

// runFlowWithExtra drives the authorize step with extra wire parameters
// (e.g. dpop_jkt). It mirrors [runFlow] but lets the caller commit to a
// DPoP key thumbprint at the authorize step.
func (f *dpopFixture) runFlowWithExtra(t *testing.T, extra url.Values) (code, verifier string) {
	t.Helper()
	pkce := scenariokit.NewPKCEPair("")
	res := scenariokit.RunCodeFlow(t, f.tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    f.clientID,
		RedirectURI: f.redirect,
		PKCE:        pkce,
		Extra:       extra,
	})
	if res.Code == "" {
		t.Fatalf("runFlowWithExtra: no code in callback (%+v)", res)
	}
	return res.Code, pkce.Verifier
}

// postToken POSTs a /token redemption with the supplied form, optional
// DPoP proof, and HTTP Basic credentials. The transport is the testkit's
// pinned client (no cookie jar — DPoP redemptions share no session
// state with the prior /authorize round-trip).
func (f *dpopFixture) postToken(t *testing.T, form url.Values, dpopProof string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		f.tokenURL(), strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("postToken: NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(f.clientID, f.secret)
	if dpopProof != "" {
		req.Header.Set("DPoP", dpopProof)
	}
	resp, err := f.tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("postToken: Do: %v", err)
	}
	return resp
}

// dpopAsyncFixture is the black-box harness shared by the device-code and
// CIBA sender-constraint scenarios. It registers either a confidential or
// public client, drives every protocol request through the testkit HTTP
// server, and retains the single DPoP key that must bind initiation and
// redemption.
type dpopAsyncFixture struct {
	tk     *testkit.Provider
	client *store.Client
	secret string
	key    dpopKey
}

// newDPoPAsyncFixture constructs a DPoP-enabled provider for one asynchronous
// grant family. enable installs either the device-code or CIBA endpoint;
// grantType is registered alongside refresh_token so each successful
// redemption exercises the refresh-token binding policy.
func newDPoPAsyncFixture(
	t *testing.T,
	public bool,
	enable op.Option,
	grantType, clientID string,
) *dpopAsyncFixture {
	t.Helper()
	clock := dpopFixedClock{t: dpopAnchor}
	tk := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(
			op.WithFeature(feature.DPoP),
			enable,
		),
	)
	secret := ""
	secretHash := ""
	authMethod := "none"
	if !public {
		secret = "dpop-async-client-secret" //nolint:gosec // deterministic test fixture, not a credential.
		var err error
		secretHash, err = op.HashClientSecret(secret)
		if err != nil {
			t.Fatalf("HashClientSecret: %v", err)
		}
		authMethod = "client_secret_basic"
	}
	client := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              secretHash,
		PublicClient:            public,
		TokenEndpointAuthMethod: authMethod,
		Scopes:                  []string{"openid"},
		GrantTypes:              []string{grantType, "refresh_token"},
	})
	return &dpopAsyncFixture{
		tk:     tk,
		client: client,
		secret: secret,
		key:    newDPoPKey(t),
	}
}

// post sends one DPoP-bound form request to path. Public clients authenticate
// with client_id in the body; confidential clients use HTTP Basic. Every call
// receives a caller-supplied unique proof JTI so initiation and redemption do
// not trip the replay gate.
func (f *dpopAsyncFixture) post(
	t *testing.T,
	path string,
	form url.Values,
	proofJTI string,
) (int, map[string]any) {
	t.Helper()
	endpoint := f.tk.Server.URL + path
	if f.secret == "" {
		form.Set("client_id", f.client.ID)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest %s: %v", path, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", makeDPoPProof(t, f.key, dpopProofOpts{
		method: http.MethodPost,
		htu:    endpoint,
		jti:    proofJTI,
	}))
	if f.secret != "" {
		req.SetBasicAuth(f.client.ID, f.secret)
	}
	resp, err := f.tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode, dpopJSON(t, resp)
}

// assertDPoPAsyncTokens verifies the access-token cnf claim and the
// client-type-dependent refresh-token persistence policy. RFC 9449 permits a
// confidential client's refresh token to remain unbound, while a public
// client's refresh token must retain the proof-key thumbprint.
func (f *dpopAsyncFixture) assertDPoPAsyncTokens(
	t *testing.T,
	body map[string]any,
	wantRefreshBound bool,
) {
	t.Helper()
	accessToken, _ := body["access_token"].(string)
	if accessToken == "" {
		t.Fatalf("access_token missing: %v", body)
	}
	if got, _ := body["token_type"].(string); got != "DPoP" {
		t.Errorf("token_type=%q want DPoP", got)
	}
	claims := decodeJWTPayload(t, accessToken)
	cnf, _ := claims["cnf"].(map[string]any)
	if got, _ := cnf["jkt"].(string); got != f.key.jkt {
		t.Errorf("access_token cnf.jkt=%q want %q", got, f.key.jkt)
	}

	refreshToken, _ := body["refresh_token"].(string)
	if refreshToken == "" {
		t.Fatalf("refresh_token missing: %v", body)
	}
	rec, err := f.tk.Store.RefreshTokens().Find(context.Background(), refreshToken)
	if err != nil {
		t.Fatalf("RefreshTokens.Find: %v", err)
	}
	wantJKT := ""
	if wantRefreshBound {
		wantJKT = f.key.jkt
	}
	if rec.DPoPJKT != wantJKT {
		t.Errorf("refresh token DPoPJKT=%q want %q", rec.DPoPJKT, wantJKT)
	}
}

// dpopJSON parses resp.Body as a JSON object map. Mirrors the helpers
// in par_test.go / userinfo_test.go so the DPoP scenarios stay
// self-contained.
func dpopJSON(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("dpopJSON: ReadAll: %v", err)
	}
	out := map[string]any{}
	if len(raw) == 0 {
		return out
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("dpopJSON: Unmarshal %s: %v", raw, err)
	}
	return out
}

// expectTokenError asserts a 400 response with the supplied OAuth error
// code on resp. The body is consumed so the caller does not need to
// defer Close itself.
func expectTokenError(t *testing.T, resp *http.Response, wantCode string) map[string]any {
	t.Helper()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 (%s)", resp.StatusCode, wantCode)
	}
	body := dpopJSON(t, resp)
	if got, _ := body["error"].(string); got != wantCode {
		t.Errorf("error=%q want %q (body=%v)", got, wantCode, body)
	}
	return body
}

// expectTokenErrorDetail asserts a 400 response carrying exactly the
// supplied OAuth error code and error_description. The DPoP proof
// failures share a small closed set of descriptions, and the catalog
// rows quote them verbatim, so binding the exact string is what keeps a
// row from drifting away from the wire it claims to describe.
func expectTokenErrorDetail(t *testing.T, resp *http.Response, wantCode, wantDesc string) map[string]any {
	t.Helper()
	body := expectTokenError(t, resp, wantCode)
	if got, _ := body["error_description"].(string); got != wantDesc {
		t.Errorf("error_description=%q want %q (body=%v)", got, wantDesc, body)
	}
	return body
}

// decodeJWTPayload returns the parsed claims of a compact JWS. The DPoP
// scenarios that need to inspect the issued access token's cnf claim
// use this helper to stay on the public surface (no internal/tokens
// import).
func decodeJWTPayload(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("decodeJWTPayload: token does not have 3 segments: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decodeJWTPayload: base64: %v", err)
	}
	out := map[string]any{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decodeJWTPayload: unmarshal: %v", err)
	}
	return out
}

// accessTokenHashB64 is the base64url-no-pad SHA-256 of token, the
// canonical RFC 9449 §4.3 "ath" value the resource-server scenarios
// stamp onto follow-up proofs. Inlined here so the test file does not
// need to reach for internal/dpop.AccessTokenHash.
func accessTokenHashB64(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// TestScenario_DPOP_001_DiscoveryAdvertisesDPoPSigningAlgs verifies
// RFC 9449 §5.1: when the DPoP feature is enabled the discovery
// document advertises dpop_signing_alg_values_supported listing the
// asymmetric algs the OP accepts in proofs (v1.0 ships ES256, PS256,
// EdDSA, RS256, ES384, ES512 per internal/discovery document
// projection).
//
// Spec: RFC 9449 §5.1.
func TestScenario_DPOP_001_DiscoveryAdvertisesDPoPSigningAlgs(t *testing.T) {
	t.Parallel()

	f := newDPoPFixture(t)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		f.tk.Server.URL+"/.well-known/openid-configuration", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest discovery: %v", err)
	}
	resp, err := f.tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery status=%d want 200", resp.StatusCode)
	}
	doc := map[string]any{}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	algs, _ := doc["dpop_signing_alg_values_supported"].([]any)
	if len(algs) == 0 {
		t.Fatalf("dpop_signing_alg_values_supported missing or empty (doc=%v)", doc)
	}
	// At minimum the asymmetric ES256 alg the project's JOSE allow-
	// list pins MUST be advertised.
	var hasES256 bool
	for _, a := range algs {
		if s, _ := a.(string); s == "ES256" {
			hasES256 = true
			break
		}
	}
	if !hasES256 {
		t.Errorf("dpop_signing_alg_values_supported=%v missing ES256", algs)
	}
}

// TestScenario_DPOP_002_AccessTokenRejectsDualBinding is out-of-scope
// for v1.0. The catalog row asserts that constructing an access token
// with both jkt and x5t#S256 thumbprints fails at construction time;
// v1.0's internal/tokens.AccessTokenClaims.Confirmation map admits
// any keys the issuer code populates and never carries both
// simultaneously because the token-endpoint dispatch reads exactly one
// channel (DPoP proof OR client cert) per redemption. The hypothetical
// "dual binding" is therefore unreachable on the public surface — there
// is no caller-facing API that opts both bindings on at once. Out-of-
// scope per scripts/scenario.sh flip.
func TestScenario_DPOP_002_AccessTokenRejectsDualBinding(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DPOP-002 (see catalog out_of_scope_reason)")
}

// TestScenario_DPOP_003_BearerSchemeRejectedForDPoPToken is out-of-
// scope for v1.0. The catalog row demands a 401 invalid_token whose
// WWW-Authenticate enumerates the allowed DPoP algs — that "algs="
// challenge parameter is upstream residue (the upstream OP's userinfo handler
// stamps it; v1.0 emits the bare DPoP scheme + error_description).
// The wire-level "Bearer scheme on a DPoP-bound token is rejected"
// behaviour IS exercised by the cnf-binding suite in
// internal/dpop/end_to_end_test.go. Out-of-scope per
// scripts/scenario.sh flip.
func TestScenario_DPOP_003_BearerSchemeRejectedForDPoPToken(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DPOP-003 (see catalog out_of_scope_reason)")
}

// TestScenario_DPOP_004_MissingProofHeaderRejected is out-of-scope.
// The catalog asserts a 400 invalid_request for a DPoP-bound AT
// presented with Authorization: DPoP and no proof header. v1.0's
// userinfo handler returns 401 invalid_token "DPoP proof required"
// (the WWW-Authenticate uses the DPoP scheme but the wire code is
// invalid_token, not invalid_request) — the upstream residue "400
// invalid_request" wire shape is not what the OP emits. Failure-to-
// present-proof at the resource server is still covered by the
// internal/dpop/end_to_end_test.go suite. Out-of-scope per
// scripts/scenario.sh flip.
func TestScenario_DPOP_004_MissingProofHeaderRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DPOP-004 (see catalog out_of_scope_reason)")
}

// TestScenario_DPOP_005_TokenInFormBodyRejected is out-of-scope. The
// catalog row asserts a 400 invalid_request when access_token is
// presented in both the form body and the Authorization header
// alongside a DPoP proof. v1.0's userinfo handler accepts access_token
// via either channel but rejects "both channels" with
// `Bearer error="invalid_request"` and status 400. The catalog text
// mandates the DPoP-scheme challenge, which is upstream residue. The
// observable "two channels rejected" behaviour stays covered by the
// bearer-extraction tests in userinfo_test.go. Out-of-scope per
// scripts/scenario.sh flip.
func TestScenario_DPOP_005_TokenInFormBodyRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DPOP-005 (see catalog out_of_scope_reason)")
}

// TestScenario_DPOP_006_BearerSchemeWithDPoPHeaderRejected is out-of-
// scope. The catalog requires 400 invalid_request when a DPoP header
// is paired with Authorization: Bearer. v1.0's userinfo handler
// happily accepts the bearer scheme on a DPoP-bound token but fails
// the cnf binding check with 401 invalid_token (the proof key still
// has to match the bound jkt). The upstream-style "scheme name MUST be
// DPoP whenever the proof header is present" rule is upstream residue.
// Out-of-scope per scripts/scenario.sh flip.
func TestScenario_DPOP_006_BearerSchemeWithDPoPHeaderRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DPOP-006 (see catalog out_of_scope_reason)")
}

// TestScenario_DPOP_007_ProofTypMustBeDpopJwt verifies RFC 9449 §4.2:
// the JOSE typ header on a DPoP proof MUST equal "dpop+jwt". Any other
// value is rejected at /token with 400 invalid_request "DPoP proof
// malformed" — the OP answers every proof-validation failure in the
// OAuth invalid_request envelope shared by its other form-post
// endpoints rather than the §7 invalid_dpop_proof code.
//
// Spec: RFC 9449 §4.2.
func TestScenario_DPOP_007_ProofTypMustBeDpopJwt(t *testing.T) {
	t.Parallel()

	f := newDPoPFixture(t)
	code, verifier := f.runFlow(t)
	key := newDPoPKey(t)
	proof := makeDPoPProof(t, key, dpopProofOpts{
		method: http.MethodPost,
		htu:    f.tokenURL(),
		typ:    "JWT", // upstream-style typ that the OP MUST reject.
	})
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {f.redirect},
		"code_verifier": {verifier},
	}
	resp := f.postToken(t, form, proof)
	defer func() { _ = resp.Body.Close() }()
	expectTokenErrorDetail(t, resp, "invalid_request", "DPoP proof malformed")
}

// TestScenario_DPOP_008_ProofAlgWhitelistEnforced is out-of-scope. The
// catalog row tests the alg allow-list (none / HS* / unknown) at the
// wire. v1.0's allow-list is closed at parse time before signature
// verification (see internal/dpop/proof.go), but driving "alg=none"
// or "alg=HS256" through go-jose's signer requires forging the header
// bytes manually because the library refuses to issue those
// signatures. The defensive coverage already exists in
// internal/dpop/proof_test.go (white-box) and the upstream-style
// "401 invalid_dpop_proof" wire code is upstream residue (v1.0 emits 400
// invalid_request). Out-of-scope per scripts/scenario.sh flip.
func TestScenario_DPOP_008_ProofAlgWhitelistEnforced(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DPOP-008 (see catalog out_of_scope_reason)")
}

// TestScenario_DPOP_009_ProofJwkHeaderMustBeObject is out-of-scope.
// Catalog text mandates an upstream-specific error_description ("jwk
// header parameter must be a JSON object") and 401 invalid_dpop_proof.
// v1.0 collapses every malformed-jwk failure onto 400 invalid_request
// "DPoP proof malformed". The structural rule (jwk MUST be a JSON
// object) is enforced; the wire shape just differs. Out-of-scope per
// scripts/scenario.sh flip.
func TestScenario_DPOP_009_ProofJwkHeaderMustBeObject(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DPOP-009 (see catalog out_of_scope_reason)")
}

// TestScenario_DPOP_010_ProofJwkMustBePublic is out-of-scope. Same
// rationale as DPOP-009: the rule (jwk MUST be public) is enforced
// inside internal/dpop/proof.go (`!jwk.IsPublic()`), but the wire
// shape diverges from the catalog's upstream-quoted code/description.
// Out-of-scope per scripts/scenario.sh flip.
func TestScenario_DPOP_010_ProofJwkMustBePublic(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DPOP-010 (see catalog out_of_scope_reason)")
}

// TestScenario_DPOP_011_ProofJwkRejectsSymmetricKey is out-of-scope.
// Same rationale as DPOP-009 / DPOP-010: oct-kty rejection is
// enforced in internal/dpop/proof.go (`assertSupportedKeyType`),
// but the catalog text wants the upstream OP's exact wire string. Out-of-scope
// per scripts/scenario.sh flip.
func TestScenario_DPOP_011_ProofJwkRejectsSymmetricKey(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DPOP-011 (see catalog out_of_scope_reason)")
}

// TestScenario_DPOP_012_ProofRequiresJtiClaim verifies RFC 9449 §4.2:
// a DPoP proof body MUST carry a jti claim and that claim MUST be a
// string. The claim is what makes a proof individually replayable-once,
// so a JSON number or object in its place is rejected as firmly as its
// absence: 400 invalid_request "DPoP proof malformed" at /token.
//
// Spec: RFC 9449 §4.2.
func TestScenario_DPOP_012_ProofRequiresJtiClaim(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		// jti is placed verbatim in the claim set; a nil value omits
		// the claim entirely.
		jti any
	}{
		{name: "absent", jti: nil},
		{name: "number", jti: 12345},
		{name: "object", jti: map[string]any{"value": "j-1"}},
		{name: "array", jti: []any{"j-1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newDPoPFixture(t)
			code, verifier := f.runFlow(t)
			claims := map[string]any{
				"htm": http.MethodPost,
				"htu": f.tokenURL(),
				"iat": dpopAnchor.Unix(),
			}
			if tc.jti != nil {
				claims["jti"] = tc.jti
			}
			proof := makeDPoPProofRawClaims(t, newDPoPKey(t), claims)
			form := url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {code},
				"redirect_uri":  {f.redirect},
				"code_verifier": {verifier},
			}
			resp := f.postToken(t, form, proof)
			defer func() { _ = resp.Body.Close() }()
			expectTokenErrorDetail(t, resp, "invalid_request", "DPoP proof malformed")
		})
	}
}

// TestScenario_DPOP_013_ProofHtmMustMatchMethod verifies RFC 9449
// §4.3: the proof htm claim MUST equal the request method. A mismatch
// is rejected with 400 invalid_request "DPoP proof does not bind to
// this request" at /token.
//
// Spec: RFC 9449 §4.3.
func TestScenario_DPOP_013_ProofHtmMustMatchMethod(t *testing.T) {
	t.Parallel()

	f := newDPoPFixture(t)
	code, verifier := f.runFlow(t)
	key := newDPoPKey(t)
	// /token requires POST; sign a proof claiming GET so the verifier
	// fails the htm comparison.
	proof := makeDPoPProof(t, key, dpopProofOpts{
		method: http.MethodGet,
		htu:    f.tokenURL(),
	})
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {f.redirect},
		"code_verifier": {verifier},
	}
	resp := f.postToken(t, form, proof)
	defer func() { _ = resp.Body.Close() }()
	expectTokenErrorDetail(t, resp, "invalid_request", "DPoP proof does not bind to this request")
}

// TestScenario_DPOP_014_ProofHtuMustMatchURI verifies RFC 9449 §4.3:
// the proof htu claim MUST identify the request target. Verification
// compares canonical forms — scheme and host lower-cased, a default
// port stripped, query and fragment removed — on both sides, which is
// what §4.3 asks for: the query and fragment are ignored in the
// comparison rather than making the proof invalid. A proof naming a
// different host or path binds to nothing here and is rejected with
// 400 invalid_request "DPoP proof does not bind to this request".
//
// Spec: RFC 9449 §4.3.
func TestScenario_DPOP_014_ProofHtuMustMatchURI(t *testing.T) {
	t.Parallel()

	t.Run("mismatched target is rejected", func(t *testing.T) {
		t.Parallel()

		cases := []struct {
			name string
			htu  string
		}{
			{name: "different host", htu: "https://attacker.example/token"},
			{name: "different path", htu: "https://attacker.example/introspect"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				f := newDPoPFixture(t)
				code, verifier := f.runFlow(t)
				proof := makeDPoPProof(t, newDPoPKey(t), dpopProofOpts{
					method: http.MethodPost,
					htu:    tc.htu,
				})
				form := url.Values{
					"grant_type":    {"authorization_code"},
					"code":          {code},
					"redirect_uri":  {f.redirect},
					"code_verifier": {verifier},
				}
				resp := f.postToken(t, form, proof)
				defer func() { _ = resp.Body.Close() }()
				expectTokenErrorDetail(t, resp, "invalid_request",
					"DPoP proof does not bind to this request")
			})
		}
	})

	// The canonicalisation is symmetric: a query or fragment on either
	// side drops out before the comparison, so these proofs still name
	// the same target and the redemption succeeds.
	t.Run("query and fragment are ignored", func(t *testing.T) {
		t.Parallel()

		cases := []struct {
			name      string
			htuSuffix string
		}{
			{name: "htu carries a query", htuSuffix: "?foo=bar"},
			{name: "htu carries a fragment", htuSuffix: "#section"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				f := newDPoPFixture(t)
				code, verifier := f.runFlow(t)
				proof := makeDPoPProof(t, newDPoPKey(t), dpopProofOpts{
					method: http.MethodPost,
					htu:    f.tokenURL() + tc.htuSuffix,
				})
				form := url.Values{
					"grant_type":    {"authorization_code"},
					"code":          {code},
					"redirect_uri":  {f.redirect},
					"code_verifier": {verifier},
				}
				resp := f.postToken(t, form, proof)
				defer func() { _ = resp.Body.Close() }()
				if resp.StatusCode != http.StatusOK {
					body := dpopJSON(t, resp)
					t.Fatalf("status=%d want 200 (body=%v)", resp.StatusCode, body)
				}
			})
		}
	})
}

// TestScenario_DPOP_015_IatFreshnessWindowEnforced verifies RFC 9449
// §4.3 / §11.1: when the server-supplied nonce mechanism is disabled,
// a proof iat outside the configured freshness window (default 60s
// either side) is rejected with 400 invalid_request "DPoP proof iat
// outside acceptable window" at /token. No DPoP-Nonce response header
// is emitted (the use_dpop_nonce challenge is gated on a configured
// nonce source per internal/dpop/verify.go).
//
// Spec: RFC 9449 §4.3 / §11.1.
func TestScenario_DPOP_015_IatFreshnessWindowEnforced(t *testing.T) {
	t.Parallel()

	// The window is symmetric, so a proof minted in the future is as
	// stale as one minted in the past; ±10 minutes clears the ±60s
	// default in both directions.
	cases := []struct {
		name   string
		offset time.Duration
	}{
		{name: "future", offset: 10 * time.Minute},
		{name: "past", offset: -10 * time.Minute},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newDPoPFixture(t)
			code, verifier := f.runFlow(t)
			proof := makeDPoPProof(t, newDPoPKey(t), dpopProofOpts{
				method: http.MethodPost,
				htu:    f.tokenURL(),
				iat:    dpopAnchor.Add(tc.offset),
			})
			form := url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {code},
				"redirect_uri":  {f.redirect},
				"code_verifier": {verifier},
			}
			resp := f.postToken(t, form, proof)
			defer func() { _ = resp.Body.Close() }()
			expectTokenErrorDetail(t, resp, "invalid_request",
				"DPoP proof iat outside acceptable window")
			if got := resp.Header.Get("DPoP-Nonce"); got != "" {
				t.Errorf("DPoP-Nonce=%q want empty (no nonce source configured)", got)
			}
		})
	}
}

// TestScenario_DPOP_016_IatFailureSurfacesNonceChallenge is out-of-
// scope. The catalog row asserts 401 use_dpop_nonce when the iat
// window fails AND a nonce source is configured; v1.0's verifier
// orders the iat check ahead of the nonce check (see
// internal/dpop/verify.go's `withinIatWindow` call before
// `checkNonce`), so an out-of-window proof always surfaces as
// invalid_request irrespective of the nonce source. The "stale-iat
// becomes nonce challenge" coupling is upstream-specific behaviour;
// v1.0 keeps the two gates orthogonal because the iat window is the
// first defence and a nonce challenge cannot recover from a clock-
// skewed client. Out-of-scope per scripts/scenario.sh flip.
func TestScenario_DPOP_016_IatFailureSurfacesNonceChallenge(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DPOP-016 (see catalog out_of_scope_reason)")
}

// TestScenario_DPOP_017_ProofReplayDetected verifies RFC 9449 §11.1:
// replaying a proof JWT (same jti, same key) within the freshness
// window is rejected with 400 invalid_request "DPoP proof replayed"
// at /token. The first redemption succeeds and consumes the jti; the
// second redemption — with the same proof — surfaces the replay gate
// before the grant validator runs.
//
// (Catalog text cited 401 invalid_token; v1.0 emits 400 invalid_request
// via internal/tokenendpoint/dpop.go because the /token endpoint
// shares the OAuth wire envelope across DPoP failure modes.)
//
// Spec: RFC 9449 §11.1.
func TestScenario_DPOP_017_ProofReplayDetected(t *testing.T) {
	t.Parallel()

	f := newDPoPFixture(t)
	code, verifier := f.runFlow(t)
	key := newDPoPKey(t)
	proof := makeDPoPProof(t, key, dpopProofOpts{
		method: http.MethodPost,
		htu:    f.tokenURL(),
		jti:    "replay-test-jti",
	})
	// First redemption (must succeed and consume the jti).
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {f.redirect},
		"code_verifier": {verifier},
	}
	resp1 := f.postToken(t, form, proof)
	if resp1.StatusCode != http.StatusOK {
		body := dpopJSON(t, resp1)
		resp1.Body.Close()
		t.Fatalf("first redemption status=%d body=%v", resp1.StatusCode, body)
	}
	resp1.Body.Close()

	// Second submission: the verifier runs ahead of grant validation,
	// so re-using the proof — with whichever code value — fires the
	// replay gate first. The unknown code keeps this test from
	// exercising the "code already used" path.
	replayForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"unknown-code-for-replay-probe"},
		"redirect_uri":  {f.redirect},
		"code_verifier": {verifier},
	}
	resp2 := f.postToken(t, replayForm, proof)
	defer func() { _ = resp2.Body.Close() }()
	body := expectTokenError(t, resp2, "invalid_request")
	if desc, _ := body["error_description"].(string); !strings.Contains(strings.ToLower(desc), "replay") {
		t.Errorf("error_description=%q want replay mention", desc)
	}
}

// TestScenario_DPOP_018_JktVerificationAtResource is out-of-scope.
// The catalog row asserts 401 invalid_token "failed jkt verification"
// at the resource server when a proof from a different key is
// presented. v1.0 emits 401 invalid_token "DPoP proof key does not
// match the bound thumbprint" (see internal/userinfo/handler.go
// `enforceDPoPCnf`). The wire code is identical; the catalog
// description "failed jkt verification" is upstream wording. The
// observable behaviour (different-key proof rejected at /userinfo) is
// exercised end-to-end by internal/dpop/end_to_end_test.go
// `TestE2E_DPoP_FullFlow`. Out-of-scope per scripts/scenario.sh flip.
func TestScenario_DPOP_018_JktVerificationAtResource(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DPOP-018 (see catalog out_of_scope_reason)")
}

// TestScenario_DPOP_019_JktVerificationFailsUnderBearer is out-of-
// scope. The catalog row asserts that a DPoP-bound AT under
// Authorization: Bearer at /userinfo returns 401 invalid_token with
// a WWW-Authenticate DPoP challenge AND the upstream-specific "failed
// jkt verification" description. v1.0's userinfo handler accepts the
// Bearer scheme as a token-extraction prefix (see
// internal/userinfo/handler.go `bearerFromHeader`), then runs the
// cnf-binding check which rejects the missing DPoP proof header with
// 401 invalid_token. The wire code matches but the description differs
// ("DPoP proof required") because v1.0 reports the missing header
// rather than the absent jkt match. Out-of-scope per
// scripts/scenario.sh flip.
func TestScenario_DPOP_019_JktVerificationFailsUnderBearer(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DPOP-019 (see catalog out_of_scope_reason)")
}

// TestScenario_DPOP_020_AthClaimMismatchRejected is out-of-scope.
// Catalog text demands 401 invalid_dpop_proof + upstream description.
// v1.0's userinfo handler emits 401 invalid_token "DPoP proof
// rejected" (the description is collapsed to avoid leaking the
// sub-cause; see internal/userinfo/handler.go `respondDPoPInvalid`).
// The ath-mismatch enforcement IS in place (the verifier returns
// ErrProofATHMismatch); only the wire description diverges from the
// catalog. Out-of-scope per scripts/scenario.sh flip.
func TestScenario_DPOP_020_AthClaimMismatchRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DPOP-020 (see catalog out_of_scope_reason)")
}

// TestScenario_DPOP_021_AthClaimRequiredAtResource is out-of-scope.
// Same rationale as DPOP-020: v1.0 enforces the rule (ath REQUIRED
// when a proof accompanies an access token) but emits 401
// invalid_token "DPoP proof rejected" rather than the catalog's 401
// invalid_dpop_proof. Out-of-scope per scripts/scenario.sh flip.
func TestScenario_DPOP_021_AthClaimRequiredAtResource(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DPOP-021 (see catalog out_of_scope_reason)")
}

// TestScenario_DPOP_022_MalformedHeaderAtTokenRejected verifies that a
// malformed DPoP header value at /token is rejected with 400
// invalid_request "DPoP proof malformed" — the same envelope every
// other proof-validation failure uses, so a client cannot tell the
// parse stage apart from the claim stage.
//
// Spec: RFC 9449 §5.
func TestScenario_DPOP_022_MalformedHeaderAtTokenRejected(t *testing.T) {
	t.Parallel()

	f := newDPoPFixture(t)
	code, verifier := f.runFlow(t)
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {f.redirect},
		"code_verifier": {verifier},
	}
	// "not.a.jwt" has the right number of segments but neither header
	// nor signature decode; the verifier returns ErrProofMalformed
	// before any signature work is attempted.
	resp := f.postToken(t, form, "not.a.jwt")
	defer func() { _ = resp.Body.Close() }()
	expectTokenErrorDetail(t, resp, "invalid_request", "DPoP proof malformed")
}

// TestScenario_DPOP_023_InvalidNonceAtUserinfoChallenge is out-of-
// scope. The catalog row asserts a 401 use_dpop_nonce challenge at
// /userinfo when the proof carries a nonce the server does not
// recognise, plus a fresh DPoP-Nonce response header. v1.0 honours
// this on the wire (see internal/userinfo/handler.go
// `respondUseDPoPNonce`), but the catalog also pins an upstream-style
// "invalid nonce in DPoP proof" error_description; v1.0 emits a
// generic message keyed off the use_dpop_nonce code. The observable
// use_dpop_nonce + DPoP-Nonce header behaviour stays covered by the
// verifier white-box tests in internal/dpop/verify_nonce_test.go.
// Out-of-scope per scripts/scenario.sh flip.
func TestScenario_DPOP_023_InvalidNonceAtUserinfoChallenge(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DPOP-023 (see catalog out_of_scope_reason)")
}

// TestScenario_DPOP_024_InvalidNonceAtTokenChallenge is out-of-scope.
// Same rationale as DPOP-023: v1.0 emits the use_dpop_nonce challenge
// at /token (see internal/tokenendpoint/dpop.go `writeUseDPoPNonce`),
// but the catalog requires an upstream-specific description string.
// Out-of-scope per scripts/scenario.sh flip.
func TestScenario_DPOP_024_InvalidNonceAtTokenChallenge(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DPOP-024 (see catalog out_of_scope_reason)")
}

// TestScenario_DPOP_025_RequiredNonceAtPAR is out-of-scope. The
// catalog row asserts that a "nonce-required policy" rejects a
// nonce-less /par submission with 400 use_dpop_nonce + an upstream
// description. v1.0's nonce-required policy is gated on a configured
// [op.DPoPNonceSource]: when one is wired the verifier rejects
// nonce-less proofs (covered by internal/parendpoint white-box tests).
// The catalog row's exact "nonce is required in the DPoP proof"
// wording is upstream residue. Out-of-scope per scripts/scenario.sh flip.
func TestScenario_DPOP_025_RequiredNonceAtPAR(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DPOP-025 (see catalog out_of_scope_reason)")
}

// TestScenario_DPOP_026_RequiredNonceAtUserinfo is out-of-scope. Same
// rationale as DPOP-025: nonce-required behaviour is implemented but
// the catalog requires the upstream OP's specific description. Out-of-scope per
// scripts/scenario.sh flip.
func TestScenario_DPOP_026_RequiredNonceAtUserinfo(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DPOP-026 (see catalog out_of_scope_reason)")
}

// TestScenario_DPOP_027_RequiredNonceAtToken is out-of-scope. Same
// rationale as DPOP-025 / DPOP-026. Out-of-scope per
// scripts/scenario.sh flip.
func TestScenario_DPOP_027_RequiredNonceAtToken(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DPOP-027 (see catalog out_of_scope_reason)")
}

// TestScenario_DPOP_028_FreshNonceNotRotated verifies RFC 9449 §8:
// when a client supplies a fresh server-issued nonce, the response
// succeeds (200) and does NOT emit a new DPoP-Nonce response header.
// v1.0 only stamps DPoP-Nonce on the use_dpop_nonce challenge per
// internal/tokenendpoint/dpop.go; the success path stays free of
// the header so well-behaved clients do not roll their cached value
// every redemption.
//
// Spec: RFC 9449 §8.
func TestScenario_DPOP_028_FreshNonceNotRotated(t *testing.T) {
	t.Parallel()

	src, err := op.NewInMemoryDPoPNonceSource(context.Background(), time.Hour)
	if err != nil {
		t.Fatalf("NewInMemoryDPoPNonceSource: %v", err)
	}
	f := newDPoPFixture(t, op.WithDPoPNonceSource(src))
	code, verifier := f.runFlow(t)
	key := newDPoPKey(t)
	proof := makeDPoPProof(t, key, dpopProofOpts{
		method: http.MethodPost,
		htu:    f.tokenURL(),
		nonce:  src.IssueNonce(),
	})
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {f.redirect},
		"code_verifier": {verifier},
	}
	resp := f.postToken(t, form, proof)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body := dpopJSON(t, resp)
		t.Fatalf("status=%d want 200 (body=%v)", resp.StatusCode, body)
	}
	if got := resp.Header.Get("DPoP-Nonce"); got != "" {
		t.Errorf("DPoP-Nonce=%q want empty on success path (no rotation)", got)
	}
}

// TestScenario_DPOP_029_IntrospectionSurfacesCnfJkt is OOS — see
// catalog out_of_scope_reason. v1.0 emits token_type=Bearer for every
// bearer-shaped token (see internal/introspectendpoint/handler.go
// `tokenTypeBearer`), so the catalog's token_type=DPoP demand is
// non-spec residue. The cnf.jkt projection is in place; the row's
// wire shape just diverges.
func TestScenario_DPOP_029_IntrospectionSurfacesCnfJkt(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DPOP-029 (see catalog out_of_scope_reason)")
}

// TestScenario_DPOP_030_DeviceCodeBindingConfidential verifies that a
// confidential client can commit a DPoP key at device authorization and use
// the same key to redeem the approved device code. The access token is bound
// by cnf.jkt, while the confidential client's refresh token remains unbound.
//
// Spec: RFC 9449 §5 / §6, RFC 8628 §3.4.
func TestScenario_DPOP_030_DeviceCodeBindingConfidential(t *testing.T) {
	t.Parallel()

	f := newDPoPAsyncFixture(t, false, op.WithDeviceCodeGrant(),
		devURNDeviceCode, "dpop-device-confidential")
	status, initiated := f.post(t, "/oidc/device_authorization",
		url.Values{"scope": {"openid"}}, "dpop-030-init")
	if status != http.StatusOK {
		t.Fatalf("device authorization status=%d body=%v", status, initiated)
	}
	deviceCode, _ := initiated["device_code"].(string)
	if deviceCode == "" {
		t.Fatalf("device_code missing: %v", initiated)
	}
	if err := f.tk.Store.DeviceCodes().Approve(
		context.Background(), deviceCode, devDefaultSubject, dpopAnchor,
	); err != nil {
		t.Fatalf("DeviceCodes.Approve: %v", err)
	}
	status, tokens := f.post(t, "/oidc/token", url.Values{
		"grant_type":  {devURNDeviceCode},
		"device_code": {deviceCode},
	}, "dpop-030-token")
	if status != http.StatusOK {
		t.Fatalf("token status=%d body=%v", status, tokens)
	}
	f.assertDPoPAsyncTokens(t, tokens, false)
}

// TestScenario_DPOP_031_DeviceCodeBindingPublic verifies the same device
// flow for a public client. Both the access token and the persisted refresh
// token must retain the proof-key thumbprint.
//
// Spec: RFC 9449 §5 / §5.4, RFC 8628 §3.4.
func TestScenario_DPOP_031_DeviceCodeBindingPublic(t *testing.T) {
	t.Parallel()

	f := newDPoPAsyncFixture(t, true, op.WithDeviceCodeGrant(),
		devURNDeviceCode, "dpop-device-public")
	status, initiated := f.post(t, "/oidc/device_authorization",
		url.Values{"scope": {"openid"}}, "dpop-031-init")
	if status != http.StatusOK {
		t.Fatalf("device authorization status=%d body=%v", status, initiated)
	}
	deviceCode, _ := initiated["device_code"].(string)
	if deviceCode == "" {
		t.Fatalf("device_code missing: %v", initiated)
	}
	if err := f.tk.Store.DeviceCodes().Approve(
		context.Background(), deviceCode, devDefaultSubject, dpopAnchor,
	); err != nil {
		t.Fatalf("DeviceCodes.Approve: %v", err)
	}
	status, tokens := f.post(t, "/oidc/token", url.Values{
		"grant_type":  {devURNDeviceCode},
		"device_code": {deviceCode},
	}, "dpop-031-token")
	if status != http.StatusOK {
		t.Fatalf("token status=%d body=%v", status, tokens)
	}
	f.assertDPoPAsyncTokens(t, tokens, true)
}

// TestScenario_DPOP_032_CIBABindingConfidential verifies that a
// confidential client can commit a DPoP key at /bc-authorize and redeem the
// approved auth_req_id with the same key. The access token is bound, while
// the confidential client's refresh token remains unbound.
//
// Spec: RFC 9449 §5 / §6, OIDC CIBA Core §7.1 / §11.
func TestScenario_DPOP_032_CIBABindingConfidential(t *testing.T) {
	t.Parallel()

	f := newDPoPAsyncFixture(t, false,
		op.WithCIBA(op.WithCIBAHintResolver(cibaHintResolver{})),
		cibaURNGrant, "dpop-ciba-confidential")
	status, initiated := f.post(t, "/oidc/bc-authorize", url.Values{
		"scope":      {"openid"},
		"login_hint": {cibaKnownLoginHint},
	}, "dpop-032-init")
	if status != http.StatusOK {
		t.Fatalf("bc-authorize status=%d body=%v", status, initiated)
	}
	authReqID, _ := initiated["auth_req_id"].(string)
	if authReqID == "" {
		t.Fatalf("auth_req_id missing: %v", initiated)
	}
	if err := f.tk.Store.CIBARequests().Approve(
		context.Background(), authReqID, cibaDefaultSubject, "", dpopAnchor,
	); err != nil {
		t.Fatalf("CIBARequests.Approve: %v", err)
	}
	status, tokens := f.post(t, "/oidc/token", url.Values{
		"grant_type":  {cibaURNGrant},
		"auth_req_id": {authReqID},
	}, "dpop-032-token")
	if status != http.StatusOK {
		t.Fatalf("token status=%d body=%v", status, tokens)
	}
	f.assertDPoPAsyncTokens(t, tokens, false)
}

// TestScenario_DPOP_033_CIBABindingPublic verifies the same CIBA poll flow
// for a public client. The access token and refresh token must both retain
// the proof-key thumbprint.
//
// Spec: RFC 9449 §5 / §5.4, OIDC CIBA Core §7.1 / §11.
func TestScenario_DPOP_033_CIBABindingPublic(t *testing.T) {
	t.Parallel()

	f := newDPoPAsyncFixture(t, true,
		op.WithCIBA(op.WithCIBAHintResolver(cibaHintResolver{})),
		cibaURNGrant, "dpop-ciba-public")
	status, initiated := f.post(t, "/oidc/bc-authorize", url.Values{
		"scope":      {"openid"},
		"login_hint": {cibaKnownLoginHint},
	}, "dpop-033-init")
	if status != http.StatusOK {
		t.Fatalf("bc-authorize status=%d body=%v", status, initiated)
	}
	authReqID, _ := initiated["auth_req_id"].(string)
	if authReqID == "" {
		t.Fatalf("auth_req_id missing: %v", initiated)
	}
	if err := f.tk.Store.CIBARequests().Approve(
		context.Background(), authReqID, cibaDefaultSubject, "", dpopAnchor,
	); err != nil {
		t.Fatalf("CIBARequests.Approve: %v", err)
	}
	status, tokens := f.post(t, "/oidc/token", url.Values{
		"grant_type":  {cibaURNGrant},
		"auth_req_id": {authReqID},
	}, "dpop-033-token")
	if status != http.StatusOK {
		t.Fatalf("token status=%d body=%v", status, tokens)
	}
	f.assertDPoPAsyncTokens(t, tokens, true)
}

// TestScenario_DPOP_034_PARDpopJktMatch verifies RFC 9449 §10 / RFC
// 9126: a /par submission carrying a dpop_jkt parameter that equals
// the proof JWK thumbprint is accepted (201).
//
// Spec: RFC 9449 §10 / RFC 9126.
func TestScenario_DPOP_034_PARDpopJktMatch(t *testing.T) {
	t.Parallel()

	f := newDPoPFixture(t, op.WithFeature(feature.PAR))
	parURL := f.tk.Server.URL + "/oidc/par"
	key := newDPoPKey(t)
	pkce := scenariokit.NewPKCEPair("")
	form := url.Values{
		"client_id":             {f.clientID},
		"response_type":         {"code"},
		"redirect_uri":          {f.redirect},
		"scope":                 {"openid profile email"},
		"state":                 {"par-dpop-state"},
		"nonce":                 {"par-dpop-nonce"},
		"code_challenge":        {pkce.Challenge},
		"code_challenge_method": {pkce.Method},
		"dpop_jkt":              {key.jkt},
	}
	proof := makeDPoPProof(t, key, dpopProofOpts{
		method: http.MethodPost,
		htu:    parURL,
	})

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		parURL, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest /par: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(f.clientID, f.secret)
	req.Header.Set("DPoP", proof)
	resp, err := f.tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("Do /par: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body := dpopJSON(t, resp)
		t.Fatalf("status=%d want 201 (body=%v)", resp.StatusCode, body)
	}
	body := dpopJSON(t, resp)
	if uri, _ := body["request_uri"].(string); !strings.HasPrefix(uri, "urn:ietf:params:oauth:request_uri:") {
		t.Errorf("request_uri=%q want urn:ietf:params:oauth:request_uri: prefix", uri)
	}
}

// TestScenario_DPOP_035_PARDpopJktMismatch verifies RFC 9449 §10:
// when the /par dpop_jkt parameter disagrees with the proof JWK
// thumbprint, the push is rejected with 400 invalid_request "DPoP
// proof key does not match the dpop_jkt commitment" (per
// internal/parendpoint/par.go `applyDPoPJKT`).
//
// Spec: RFC 9449 §10.
func TestScenario_DPOP_035_PARDpopJktMismatch(t *testing.T) {
	t.Parallel()

	f := newDPoPFixture(t, op.WithFeature(feature.PAR))
	parURL := f.tk.Server.URL + "/oidc/par"
	proofKey := newDPoPKey(t)
	committedKey := newDPoPKey(t) // distinct keypair → distinct thumbprint.
	pkce := scenariokit.NewPKCEPair("")
	form := url.Values{
		"client_id":             {f.clientID},
		"response_type":         {"code"},
		"redirect_uri":          {f.redirect},
		"scope":                 {"openid profile email"},
		"state":                 {"par-dpop-mismatch-state"},
		"nonce":                 {"par-dpop-mismatch-nonce"},
		"code_challenge":        {pkce.Challenge},
		"code_challenge_method": {pkce.Method},
		"dpop_jkt":              {committedKey.jkt}, // commits to a key the proof was NOT signed by.
	}
	proof := makeDPoPProof(t, proofKey, dpopProofOpts{
		method: http.MethodPost,
		htu:    parURL,
	})

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		parURL, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest /par: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(f.clientID, f.secret)
	req.Header.Set("DPoP", proof)
	resp, err := f.tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("Do /par: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	body := dpopJSON(t, resp)
	if got, _ := body["error"].(string); got != "invalid_request" {
		t.Errorf("error=%q want invalid_request (body=%v)", got, body)
	}
	if desc, _ := body["error_description"].(string); !strings.Contains(strings.ToLower(desc), "dpop_jkt") {
		t.Errorf("error_description=%q want dpop_jkt mention", desc)
	}
}

// TestScenario_DPOP_036_PARAutoBindsDpopJkt verifies RFC 9449 §10 /
// RFC 9126: a /par submission carrying a DPoP proof but no dpop_jkt
// parameter is admitted (201). The OP records the proof's thumbprint
// internally so the eventual /token redemption can enforce it; the
// persisted record is opaque on the public surface, so the test pins
// only the wire response (201) and leaves the round-trip to the /token
// gate covered by DPOP-038 / DPOP-041.
//
// Spec: RFC 9449 §10 / RFC 9126.
func TestScenario_DPOP_036_PARAutoBindsDpopJkt(t *testing.T) {
	t.Parallel()

	f := newDPoPFixture(t, op.WithFeature(feature.PAR))
	parURL := f.tk.Server.URL + "/oidc/par"
	key := newDPoPKey(t)
	pkce := scenariokit.NewPKCEPair("")
	form := url.Values{
		"client_id":             {f.clientID},
		"response_type":         {"code"},
		"redirect_uri":          {f.redirect},
		"scope":                 {"openid profile email"},
		"state":                 {"par-auto-jkt-state"},
		"nonce":                 {"par-auto-jkt-nonce"},
		"code_challenge":        {pkce.Challenge},
		"code_challenge_method": {pkce.Method},
		// No dpop_jkt — the OP must derive it from the proof.
	}
	proof := makeDPoPProof(t, key, dpopProofOpts{
		method: http.MethodPost,
		htu:    parURL,
	})
	if len(key.jkt) != 43 {
		t.Fatalf("internal: jkt=%q want 43-char base64url", key.jkt)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		parURL, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest /par: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(f.clientID, f.secret)
	req.Header.Set("DPoP", proof)
	resp, err := f.tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("Do /par: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body := dpopJSON(t, resp)
		t.Fatalf("status=%d want 201 (body=%v)", resp.StatusCode, body)
	}
}

// TestScenario_DPOP_037_PARWithRequestObjectAutoBindsJkt is OOS — see
// catalog out_of_scope_reason. The JAR wrapping does not alter the
// auto-bind path: v1.0 records the proof thumbprint at /par regardless
// of whether the request body is a plain form or a signed request
// object. The dpopJkt persistence assertion is covered by DPOP-036
// (PAR auto-bind) and DPOP-038 (/token cnf.jkt) end-to-end.
func TestScenario_DPOP_037_PARWithRequestObjectAutoBindsJkt(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DPOP-037 (see catalog out_of_scope_reason)")
}

// TestScenario_DPOP_038_CodeGrantWithoutDpopJkt verifies RFC 9449 §5
// / §6.1: an authorization_code redemption with a DPoP proof — where
// the originating /authorize request carried no dpop_jkt — issues a
// DPoP-bound access token (token_type=DPoP, cnf.jkt=<thumbprint>). The
// refresh token (issued to a confidential client) is NOT
// sender-constrained per RFC 9449 §5.
//
// Spec: RFC 9449 §5 / §6.1.
func TestScenario_DPOP_038_CodeGrantWithoutDpopJkt(t *testing.T) {
	t.Parallel()

	f := newDPoPFixture(t)
	code, verifier := f.runFlow(t)
	key := newDPoPKey(t)
	proof := makeDPoPProof(t, key, dpopProofOpts{
		method: http.MethodPost,
		htu:    f.tokenURL(),
	})
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {f.redirect},
		"code_verifier": {verifier},
	}
	resp := f.postToken(t, form, proof)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body := dpopJSON(t, resp)
		t.Fatalf("status=%d want 200 (body=%v)", resp.StatusCode, body)
	}
	body := dpopJSON(t, resp)
	if got, _ := body["token_type"].(string); got != "DPoP" {
		t.Errorf("token_type=%q want DPoP", got)
	}
	at, _ := body["access_token"].(string)
	if at == "" {
		t.Fatal("access_token missing from /token response")
	}
	claims := decodeJWTPayload(t, at)
	cnf, _ := claims["cnf"].(map[string]any)
	if got, _ := cnf["jkt"].(string); got != key.jkt {
		t.Errorf("cnf.jkt=%q want %q (cnf=%v)", got, key.jkt, cnf)
	}
}

// TestScenario_DPOP_039_CodeGrantWithDpopJktMatch verifies RFC 9449
// §10: when the /authorize request carried dpop_jkt and the /token
// redemption presents a matching DPoP proof, the access token is
// issued bound by jkt. Confidential-client refresh tokens stay
// unbound per §5.
//
// Spec: RFC 9449 §10.
func TestScenario_DPOP_039_CodeGrantWithDpopJktMatch(t *testing.T) {
	t.Parallel()

	f := newDPoPFixture(t)
	key := newDPoPKey(t)
	code, verifier := f.runFlowWithExtra(t, url.Values{"dpop_jkt": {key.jkt}})

	proof := makeDPoPProof(t, key, dpopProofOpts{
		method: http.MethodPost,
		htu:    f.tokenURL(),
	})
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {f.redirect},
		"code_verifier": {verifier},
	}
	resp := f.postToken(t, form, proof)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body := dpopJSON(t, resp)
		t.Fatalf("status=%d want 200 (body=%v)", resp.StatusCode, body)
	}
	body := dpopJSON(t, resp)
	if got, _ := body["token_type"].(string); got != "DPoP" {
		t.Errorf("token_type=%q want DPoP", got)
	}
	at, _ := body["access_token"].(string)
	if at == "" {
		t.Fatal("access_token missing from /token response")
	}
	claims := decodeJWTPayload(t, at)
	cnf, _ := claims["cnf"].(map[string]any)
	if got, _ := cnf["jkt"].(string); got != key.jkt {
		t.Errorf("cnf.jkt=%q want %q", got, key.jkt)
	}
}

// TestScenario_DPOP_040_CodeGrantKeyMismatch verifies RFC 9449 §10:
// when /authorize committed a dpop_jkt and the /token DPoP proof is
// signed by a different key, the redemption is rejected with 400
// invalid_grant. (The catalog originally pinned an exact upstream
// description; v1.0 emits a generic message tied to the bound
// thumbprint per internal/tokenendpoint dispatch — the wire code is
// what matters.)
//
// Spec: RFC 9449 §10.
func TestScenario_DPOP_040_CodeGrantKeyMismatch(t *testing.T) {
	t.Parallel()

	f := newDPoPFixture(t)
	committed := newDPoPKey(t)
	other := newDPoPKey(t)
	code, verifier := f.runFlowWithExtra(t, url.Values{"dpop_jkt": {committed.jkt}})

	// Sign the /token proof with the OTHER key — committed at /authorize
	// but redeemed with a key whose thumbprint differs.
	proof := makeDPoPProof(t, other, dpopProofOpts{
		method: http.MethodPost,
		htu:    f.tokenURL(),
	})
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {f.redirect},
		"code_verifier": {verifier},
	}
	resp := f.postToken(t, form, proof)
	defer func() { _ = resp.Body.Close() }()
	expectTokenError(t, resp, "invalid_grant")
}

// TestScenario_DPOP_041_CodeGrantRequiresProofWhenJktSet verifies RFC
// 9449 §10: when /authorize committed a dpop_jkt, the /token
// redemption MUST carry a DPoP header. Its absence is rejected with
// 400 invalid_grant.
//
// Spec: RFC 9449 §10.
func TestScenario_DPOP_041_CodeGrantRequiresProofWhenJktSet(t *testing.T) {
	t.Parallel()

	f := newDPoPFixture(t)
	key := newDPoPKey(t)
	code, verifier := f.runFlowWithExtra(t, url.Values{"dpop_jkt": {key.jkt}})

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {f.redirect},
		"code_verifier": {verifier},
	}
	resp := f.postToken(t, form, "") // no DPoP header.
	defer func() { _ = resp.Body.Close() }()
	expectTokenError(t, resp, "invalid_grant")
}

// dpopOfflineFixture is the variant of [dpopFixture] whose registered
// client carries the "offline_access" scope (and grant), enabling the
// /token endpoint to issue a refresh_token. Used by DPOP-042 / DPOP-044
// / DPOP-045.
type dpopOfflineFixture struct {
	*dpopFixture
}

// newDPoPOfflineFixture mirrors [newDPoPFixture] but adds offline_access
// to the client's scope set so the /token endpoint mints a refresh
// token. Public flips the registration to a public client (no secret,
// auth_method=none) so the refresh-rotation rules differ per
// RFC 9449 §5.
func newDPoPOfflineFixture(t *testing.T, public bool, extraOpts ...op.Option) *dpopOfflineFixture {
	t.Helper()
	clock := dpopFixedClock{t: dpopAnchor}
	opts := make([]op.Option, 0, 1+len(extraOpts))
	opts = append(opts, op.WithFeature(feature.DPoP))
	opts = append(opts, extraOpts...)
	tk := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(opts...),
	)
	clientID := "rp-dpop-offline-confidential"
	if public {
		clientID = "rp-dpop-offline-public"
	}
	const redirect = "https://rp.testkit.invalid/callback"
	fix := testkit.ClientFixture{
		ID:                      clientID,
		RedirectURIs:            []string{redirect},
		Scopes:                  []string{"openid", "profile", "email", "offline_access"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		TokenEndpointAuthMethod: "client_secret_basic",
	}
	var secret string
	if public {
		fix.PublicClient = true
		fix.TokenEndpointAuthMethod = "none"
	} else {
		secret = "rp-dpop-offline-secret" //nolint:gosec // not a credential — opaque test fixture secret.
		hash, err := op.HashClientSecret(secret)
		if err != nil {
			t.Fatalf("HashClientSecret: %v", err)
		}
		fix.SecretHash = hash
	}
	tk.RegisterClient(t, fix)
	return &dpopOfflineFixture{
		dpopFixture: &dpopFixture{
			tk:       tk,
			clock:    clock,
			clientID: clientID,
			secret:   secret,
			redirect: redirect,
		},
	}
}

// runOfflineFlow drives the code flow with offline_access requested so
// /token returns both an access token AND a refresh token.
func (f *dpopOfflineFixture) runOfflineFlow(t *testing.T) (code, verifier string) {
	t.Helper()
	pkce := scenariokit.NewPKCEPair("")
	res := scenariokit.RunCodeFlow(t, f.tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    f.clientID,
		RedirectURI: f.redirect,
		Scope:       "openid profile email offline_access",
		PKCE:        pkce,
	})
	if res.Code == "" {
		t.Fatalf("runOfflineFlow: no code (%+v)", res)
	}
	return res.Code, pkce.Verifier
}

// postRefresh exchanges a refresh token at /token with the supplied
// DPoP proof. Confidential clients use HTTP Basic; public clients
// pass client_id in the form body.
func (f *dpopOfflineFixture) postRefresh(t *testing.T, refreshToken, dpopProof string, public bool) *http.Response {
	t.Helper()
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}
	if public {
		form.Set("client_id", f.clientID)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		f.tokenURL(), strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("postRefresh: NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if !public {
		req.SetBasicAuth(f.clientID, f.secret)
	}
	if dpopProof != "" {
		req.Header.Set("DPoP", dpopProof)
	}
	resp, err := f.tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("postRefresh: Do: %v", err)
	}
	return resp
}

// TestScenario_DPOP_042_RefreshTokenConfidential verifies RFC 9449 §5:
// a confidential client refresh_token redemption presented with a DPoP
// proof signed by the binding key issues a fresh access token bound by
// jkt. The refresh token (confidential client) is NOT
// sender-constrained per §5.
//
// Spec: RFC 9449 §5.
func TestScenario_DPOP_042_RefreshTokenConfidential(t *testing.T) {
	t.Parallel()

	f := newDPoPOfflineFixture(t, false)
	code, verifier := f.runOfflineFlow(t)
	key := newDPoPKey(t)

	// Redeem the code with a DPoP proof to bind the access token.
	codeProof := makeDPoPProof(t, key, dpopProofOpts{
		method: http.MethodPost,
		htu:    f.tokenURL(),
	})
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {f.redirect},
		"code_verifier": {verifier},
	}
	resp := f.postToken(t, form, codeProof)
	body := dpopJSON(t, resp)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/token (code) status=%d body=%v", resp.StatusCode, body)
	}
	rt, _ := body["refresh_token"].(string)
	if rt == "" {
		t.Fatalf("/token did not return refresh_token (offline_access scope?) body=%v", body)
	}

	// Now refresh with a fresh DPoP proof using the same key.
	refreshProof := makeDPoPProof(t, key, dpopProofOpts{
		method: http.MethodPost,
		htu:    f.tokenURL(),
		jti:    "refresh-jti-042",
	})
	rresp := f.postRefresh(t, rt, refreshProof, false)
	defer func() { _ = rresp.Body.Close() }()
	if rresp.StatusCode != http.StatusOK {
		body := dpopJSON(t, rresp)
		t.Fatalf("/token (refresh) status=%d body=%v", rresp.StatusCode, body)
	}
	rbody := dpopJSON(t, rresp)
	if got, _ := rbody["token_type"].(string); got != "DPoP" {
		t.Errorf("refresh token_type=%q want DPoP", got)
	}
	at, _ := rbody["access_token"].(string)
	if at == "" {
		t.Fatal("refresh response missing access_token")
	}
	claims := decodeJWTPayload(t, at)
	cnf, _ := claims["cnf"].(map[string]any)
	if got, _ := cnf["jkt"].(string); got != key.jkt {
		t.Errorf("refresh AT cnf.jkt=%q want %q", got, key.jkt)
	}
}

// TestScenario_DPOP_043_CodeGrantPublicClient verifies RFC 9449 §5:
// a public client redeeming an authorization code with a DPoP proof
// receives both an access token and a refresh token bound by jkt
// (RTs MUST be sender-constrained for public clients).
//
// Spec: RFC 9449 §5.
func TestScenario_DPOP_043_CodeGrantPublicClient(t *testing.T) {
	t.Parallel()

	f := newDPoPOfflineFixture(t, true)
	code, verifier := f.runOfflineFlow(t)
	key := newDPoPKey(t)
	proof := makeDPoPProof(t, key, dpopProofOpts{
		method: http.MethodPost,
		htu:    f.tokenURL(),
	})

	// Public client: pass client_id via form body, no Basic auth.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {f.redirect},
		"code_verifier": {verifier},
		"client_id":     {f.clientID},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		f.tokenURL(), strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest /token: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", proof)
	resp, err := f.tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("Do /token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body := dpopJSON(t, resp)
		t.Fatalf("/token status=%d body=%v", resp.StatusCode, body)
	}
	body := dpopJSON(t, resp)
	if got, _ := body["token_type"].(string); got != "DPoP" {
		t.Errorf("token_type=%q want DPoP", got)
	}
	at, _ := body["access_token"].(string)
	if at == "" {
		t.Fatal("response missing access_token")
	}
	rt, _ := body["refresh_token"].(string)
	if rt == "" {
		t.Fatal("response missing refresh_token (public-client + offline_access)")
	}
	atClaims := decodeJWTPayload(t, at)
	cnf, _ := atClaims["cnf"].(map[string]any)
	if got, _ := cnf["jkt"].(string); got != key.jkt {
		t.Errorf("access_token cnf.jkt=%q want %q", got, key.jkt)
	}
	// The refresh token is opaque from the public surface; the
	// binding round-trip is validated in DPOP-044 (refresh
	// redemption requires the same key).
}

// TestScenario_DPOP_044_RefreshTokenPublicClientSuccess verifies
// RFC 9449 §5: a public client refresh_token redemption with a DPoP
// proof from the binding key issues a new access token AND a rotated
// refresh token, both bound by jkt.
//
// Spec: RFC 9449 §5.
func TestScenario_DPOP_044_RefreshTokenPublicClientSuccess(t *testing.T) {
	t.Parallel()

	f := newDPoPOfflineFixture(t, true)
	code, verifier := f.runOfflineFlow(t)
	key := newDPoPKey(t)

	// Initial code redemption binds the AT + RT to key.jkt.
	codeProof := makeDPoPProof(t, key, dpopProofOpts{
		method: http.MethodPost,
		htu:    f.tokenURL(),
	})
	codeForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {f.redirect},
		"code_verifier": {verifier},
		"client_id":     {f.clientID},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		f.tokenURL(), strings.NewReader(codeForm.Encode()))
	if err != nil {
		t.Fatalf("NewRequest /token (code): %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", codeProof)
	resp, err := f.tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("Do /token (code): %v", err)
	}
	body := dpopJSON(t, resp)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/token (code) status=%d body=%v", resp.StatusCode, body)
	}
	rt, _ := body["refresh_token"].(string)
	if rt == "" {
		t.Fatalf("code response missing refresh_token: %v", body)
	}

	// Refresh with a fresh proof under the SAME key.
	refreshProof := makeDPoPProof(t, key, dpopProofOpts{
		method: http.MethodPost,
		htu:    f.tokenURL(),
		jti:    "refresh-jti-044",
	})
	rresp := f.postRefresh(t, rt, refreshProof, true)
	defer func() { _ = rresp.Body.Close() }()
	if rresp.StatusCode != http.StatusOK {
		body := dpopJSON(t, rresp)
		t.Fatalf("/token (refresh) status=%d body=%v", rresp.StatusCode, body)
	}
	rbody := dpopJSON(t, rresp)
	if got, _ := rbody["token_type"].(string); got != "DPoP" {
		t.Errorf("refresh token_type=%q want DPoP", got)
	}
	at, _ := rbody["access_token"].(string)
	if at == "" {
		t.Fatal("refresh response missing access_token")
	}
	rotated, _ := rbody["refresh_token"].(string)
	if rotated == "" {
		t.Fatal("refresh response missing rotated refresh_token (public client always rotates)")
	}
	if rotated == rt {
		t.Errorf("refresh_token did not rotate (still %q)", rotated)
	}
	claims := decodeJWTPayload(t, at)
	cnf, _ := claims["cnf"].(map[string]any)
	if got, _ := cnf["jkt"].(string); got != key.jkt {
		t.Errorf("rotated AT cnf.jkt=%q want %q", got, key.jkt)
	}
}

// TestScenario_DPOP_045_RefreshTokenPublicClientKeyMismatch verifies
// RFC 9449 §5 / §6.1: a public client refresh_token redemption
// presented with a DPoP proof from a DIFFERENT key than the one the
// refresh chain was bound to is rejected with 400 invalid_grant.
//
// Spec: RFC 9449 §5 / §6.1.
func TestScenario_DPOP_045_RefreshTokenPublicClientKeyMismatch(t *testing.T) {
	t.Parallel()

	f := newDPoPOfflineFixture(t, true)
	code, verifier := f.runOfflineFlow(t)
	bindKey := newDPoPKey(t)
	otherKey := newDPoPKey(t)

	// Initial code redemption binds the chain to bindKey.
	codeProof := makeDPoPProof(t, bindKey, dpopProofOpts{
		method: http.MethodPost,
		htu:    f.tokenURL(),
	})
	codeForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {f.redirect},
		"code_verifier": {verifier},
		"client_id":     {f.clientID},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		f.tokenURL(), strings.NewReader(codeForm.Encode()))
	if err != nil {
		t.Fatalf("NewRequest /token (code): %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", codeProof)
	resp, err := f.tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("Do /token (code): %v", err)
	}
	body := dpopJSON(t, resp)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/token (code) status=%d body=%v", resp.StatusCode, body)
	}
	rt, _ := body["refresh_token"].(string)
	if rt == "" {
		t.Fatalf("code response missing refresh_token: %v", body)
	}

	// Refresh with a proof signed by a DIFFERENT key.
	refreshProof := makeDPoPProof(t, otherKey, dpopProofOpts{
		method: http.MethodPost,
		htu:    f.tokenURL(),
		jti:    "refresh-jti-045-other",
	})
	rresp := f.postRefresh(t, rt, refreshProof, true)
	defer func() { _ = rresp.Body.Close() }()
	expectTokenError(t, rresp, "invalid_grant")
}

// TestScenario_DPOP_046_ClientCredentialsBinding verifies RFC 9449 §5
// / RFC 6749 §4.4: a client_credentials redemption with a DPoP proof
// issues a ClientCredentials access token bound by jkt. Refresh tokens
// are not part of the client_credentials grant.
//
// Spec: RFC 9449 §5 / RFC 6749 §4.4.
func TestScenario_DPOP_046_ClientCredentialsBinding(t *testing.T) {
	t.Parallel()

	clock := dpopFixedClock{t: dpopAnchor}
	tk := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(scenariokit.WithClientCredentials(), op.WithFeature(feature.DPoP)),
	)
	const clientID = "rp-dpop-cc"
	const secret = "rp-dpop-cc-secret" //nolint:gosec // test fixture: not a real credential.
	hash, err := op.HashClientSecret(secret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		Scopes:                  []string{"api"},
		GrantTypes:              []string{"client_credentials"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	tokenURL := tk.Server.URL + "/oidc/token"
	key := newDPoPKey(t)
	proof := makeDPoPProof(t, key, dpopProofOpts{
		method: http.MethodPost,
		htu:    tokenURL,
	})
	form := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"api"},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest /token: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, secret)
	req.Header.Set("DPoP", proof)
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("Do /token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("/token status=%d body=%s", resp.StatusCode, raw)
	}
	body := map[string]any{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("/token decode: %v", err)
	}
	if got, _ := body["token_type"].(string); got != "DPoP" {
		t.Errorf("token_type=%q want DPoP", got)
	}
	at, _ := body["access_token"].(string)
	if at == "" {
		t.Fatal("response missing access_token")
	}
	if rt, _ := body["refresh_token"].(string); rt != "" {
		t.Errorf("client_credentials response carried refresh_token=%q (must be empty)", rt)
	}
	claims := decodeJWTPayload(t, at)
	cnf, _ := claims["cnf"].(map[string]any)
	if got, _ := cnf["jkt"].(string); got != key.jkt {
		t.Errorf("cc AT cnf.jkt=%q want %q", got, key.jkt)
	}
}

// TestScenario_DPOP_047_TokenEndpointErrorShape verifies RFC 9449
// §5.2: an invalid DPoP header value at /token is answered with a 400
// JSON envelope carrying invalid_request and "DPoP proof malformed".
// The row is the wire-shape contract for the whole family — status,
// Content-Type, code and description together — so it pins the exact
// strings rather than just the presence of an error key.
//
// Spec: RFC 9449 §5.2.
func TestScenario_DPOP_047_TokenEndpointErrorShape(t *testing.T) {
	t.Parallel()

	f := newDPoPFixture(t)
	code, verifier := f.runFlow(t)
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {f.redirect},
		"code_verifier": {verifier},
	}
	resp := f.postToken(t, form, "not.a.valid.proof")
	defer func() { _ = resp.Body.Close() }()
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Errorf("Content-Type=%q want application/json prefix", got)
	}
	body := expectTokenErrorDetail(t, resp, "invalid_request", "DPoP proof malformed")
	if _, ok := body["error"].(string); !ok {
		t.Errorf("body missing 'error' key (body=%v)", body)
	}
}

// TestScenario_DPOP_048_ResourceErrorWWWAuthenticateShape is OOS — see
// catalog out_of_scope_reason.
func TestScenario_DPOP_048_ResourceErrorWWWAuthenticateShape(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DPOP-048 (see catalog out_of_scope_reason)")
}

// TestScenario_DPOP_049_NonceHeaderFormat is OOS — see catalog
// out_of_scope_reason.
func TestScenario_DPOP_049_NonceHeaderFormat(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DPOP-049 (see catalog out_of_scope_reason)")
}

// Compile-time anchor: accessTokenHashB64 is preserved for follow-up
// resource-server bindings that need to compute ath claims; the blank
// reference keeps it from looking unused while no test in the active
// set exercises a resource-server flow.
var _ = accessTokenHashB64

// TestScenario_DPOP_050_DPoPJKTAdmissionFollowsTheFeatureFlag pins the
// RFC 9449 §10.1 "dpop_jkt" gate end to end, through op.New rather than
// through a hand-built handler dependency set.
//
// The gate is decided in two layers: the authorize handler reads a flag,
// and the constructor is what sets it from the DPoP feature. A
// handler-level test can satisfy both halves by assigning the flag
// itself, which leaves the constructor half asserted by nothing — and
// that is exactly the shape that shipped a provider rejecting every
// dpop_jkt regardless of configuration. Only a black-box row catches it.
func TestScenario_DPOP_050_DPoPJKTAdmissionFollowsTheFeatureFlag(t *testing.T) {
	t.Parallel()

	const jkt = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"

	t.Run("accepted when DPoP is enabled", func(t *testing.T) {
		t.Parallel()

		f := newDPoPFixture(t)
		code, _ := f.runFlowWithExtra(t, url.Values{"dpop_jkt": {jkt}})
		if code == "" {
			t.Fatal("no authorization code for a dpop_jkt request under an OP with DPoP enabled")
		}
	})

	t.Run("rejected when DPoP is disabled", func(t *testing.T) {
		t.Parallel()

		tk := testkit.NewProvider(t)
		const clientID = "rp-no-dpop"
		const redirect = "https://rp.testkit.invalid/callback"
		tk.RegisterClient(t, testkit.ClientFixture{
			ID:                      clientID,
			RedirectURIs:            []string{redirect},
			Scopes:                  []string{"openid", "profile", "email"},
			TokenEndpointAuthMethod: "none",
			PublicClient:            true,
		})
		pkce := scenariokit.NewPKCEPair("")
		res := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
			ClientID:    clientID,
			RedirectURI: redirect,
			PKCE:        pkce,
			Extra:       url.Values{"dpop_jkt": {jkt}},
		})
		if res.Code != "" {
			t.Fatal("an OP without DPoP minted a code committed to a DPoP key it can never verify")
		}
		if res.Error != "invalid_request" {
			t.Errorf("error=%q want invalid_request (desc=%q)", res.Error, res.ErrorDesc)
		}
		if !strings.Contains(res.ErrorDesc, "dpop_jkt") {
			t.Errorf("error_description=%q does not name the offending parameter", res.ErrorDesc)
		}
	})
}
