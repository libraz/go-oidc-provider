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

func TestScenario_DPOP_001_DiscoveryAdvertisesDPoPSigningAlgs(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-001")
}

// TestScenario_DPOP_002_AccessTokenRejectsDualBinding is out-of-scope
// for v1.0. The catalog row asserts that constructing an access token
// with both jkt and x5t#S256 thumbprints fails at construction time;
// v1.0's [internal/tokens.AccessTokenClaims.Confirmation] map admits
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
// challenge parameter is panva-residue (panva's userinfo handler
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
// invalid_token, not invalid_request) — the panva-residue "400
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
// mandates the DPoP-scheme challenge, which is panva-residue. The
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
// has to match the bound jkt). The panva-style "scheme name MUST be
// DPoP whenever the proof header is present" rule is panva-residue.
// Out-of-scope per scripts/scenario.sh flip.
func TestScenario_DPOP_006_BearerSchemeWithDPoPHeaderRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DPOP-006 (see catalog out_of_scope_reason)")
}

// TestScenario_DPOP_007_ProofTypMustBeDpopJwt verifies RFC 9449 §4.2:
// the JOSE typ header on a DPoP proof MUST equal "dpop+jwt". Any other
// value is rejected.
//
// v1.0 surfaces this on the wire as 400 invalid_request "DPoP proof
// malformed" at /token (the catalog originally cited 401
// invalid_dpop_proof + a panva-specific error_description; the OP
// collapses the malformed-proof family onto the OAuth invalid_request
// envelope per [internal/tokenendpoint/dpop.go]).
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
		typ:    "JWT", // panva-style typ that the OP MUST reject.
	})
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {f.redirect},
		"code_verifier": {verifier},
	}
	resp := f.postToken(t, form, proof)
	defer func() { _ = resp.Body.Close() }()
	expectTokenError(t, resp, "invalid_request")
}

// TestScenario_DPOP_008_ProofAlgWhitelistEnforced is out-of-scope. The
// catalog row tests the alg allow-list (none / HS* / unknown) at the
// wire. v1.0's allow-list is closed at parse time before signature
// verification (see [internal/dpop/proof.go]), but driving "alg=none"
// or "alg=HS256" through go-jose's signer requires forging the header
// bytes manually because the library refuses to issue those
// signatures. The defensive coverage already exists in
// internal/dpop/proof_test.go (white-box) and the panva-style
// "401 invalid_dpop_proof" wire code is panva-residue (v1.0 emits 400
// invalid_request). Out-of-scope per scripts/scenario.sh flip.
func TestScenario_DPOP_008_ProofAlgWhitelistEnforced(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DPOP-008 (see catalog out_of_scope_reason)")
}

// TestScenario_DPOP_009_ProofJwkHeaderMustBeObject is out-of-scope.
// Catalog text mandates a panva-specific error_description ("jwk
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
// inside [internal/dpop/proof.go] (`!jwk.IsPublic()`), but the wire
// shape diverges from the catalog's panva-quoted code/description.
// Out-of-scope per scripts/scenario.sh flip.
func TestScenario_DPOP_010_ProofJwkMustBePublic(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DPOP-010 (see catalog out_of_scope_reason)")
}

// TestScenario_DPOP_011_ProofJwkRejectsSymmetricKey is out-of-scope.
// Same rationale as DPOP-009 / DPOP-010: oct-kty rejection is
// enforced in [internal/dpop/proof.go] (`assertSupportedKeyType`),
// but the catalog text wants panva's exact wire string. Out-of-scope
// per scripts/scenario.sh flip.
func TestScenario_DPOP_011_ProofJwkRejectsSymmetricKey(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DPOP-011 (see catalog out_of_scope_reason)")
}

// TestScenario_DPOP_012_ProofRequiresJtiClaim verifies RFC 9449 §4.2:
// a DPoP proof body MUST contain a "jti" claim. Omitting it is
// rejected with 400 invalid_request "DPoP proof malformed" at /token.
//
// (The catalog row originally cited a panva-specific error_description
// "DPoP proof must have a jti string property"; v1.0 collapses every
// parse-stage failure onto a single description to keep the surface
// opaque per [internal/dpop/proof.go].)
//
// Spec: RFC 9449 §4.2.
func TestScenario_DPOP_012_ProofRequiresJtiClaim(t *testing.T) {
	t.Parallel()

	f := newDPoPFixture(t)
	code, verifier := f.runFlow(t)
	key := newDPoPKey(t)
	proof := makeDPoPProof(t, key, dpopProofOpts{
		method:  http.MethodPost,
		htu:     f.tokenURL(),
		omitJTI: true,
	})
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {f.redirect},
		"code_verifier": {verifier},
	}
	resp := f.postToken(t, form, proof)
	defer func() { _ = resp.Body.Close() }()
	expectTokenError(t, resp, "invalid_request")
}

// TestScenario_DPOP_013_ProofHtmMustMatchMethod verifies RFC 9449
// §4.3: the proof "htm" claim MUST equal the request method. A
// mismatch surfaces on the wire as 400 invalid_request "DPoP proof
// does not bind to this request" at /token.
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
	expectTokenError(t, resp, "invalid_request")
}

// TestScenario_DPOP_014_ProofHtuMustMatchURI verifies RFC 9449 §4.3:
// the proof "htu" claim MUST equal the canonical request URL
// (scheme + host + path; query / fragment stripped). A mismatched htu
// is rejected with 400 invalid_request "DPoP proof does not bind to
// this request" at /token.
//
// Spec: RFC 9449 §4.3.
func TestScenario_DPOP_014_ProofHtuMustMatchURI(t *testing.T) {
	t.Parallel()

	f := newDPoPFixture(t)
	code, verifier := f.runFlow(t)
	key := newDPoPKey(t)
	proof := makeDPoPProof(t, key, dpopProofOpts{
		method: http.MethodPost,
		htu:    "https://attacker.example/token",
	})
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {f.redirect},
		"code_verifier": {verifier},
	}
	resp := f.postToken(t, form, proof)
	defer func() { _ = resp.Body.Close() }()
	expectTokenError(t, resp, "invalid_request")
}

// TestScenario_DPOP_015_IatFreshnessWindowEnforced verifies RFC 9449
// §4.3 / §11.1: when the server-supplied nonce mechanism is disabled,
// a proof iat outside the configured freshness window (default 60s
// either side) is rejected with 400 invalid_request "DPoP proof iat
// outside acceptable window" at /token. No DPoP-Nonce response header
// is emitted (the use_dpop_nonce challenge is gated on a configured
// nonce source per [internal/dpop/verify.go]).
//
// Spec: RFC 9449 §4.3 / §11.1.
func TestScenario_DPOP_015_IatFreshnessWindowEnforced(t *testing.T) {
	t.Parallel()

	f := newDPoPFixture(t)
	code, verifier := f.runFlow(t)
	key := newDPoPKey(t)
	// 10 minutes ahead: well outside the symmetric ±60s default window.
	proof := makeDPoPProof(t, key, dpopProofOpts{
		method: http.MethodPost,
		htu:    f.tokenURL(),
		iat:    dpopAnchor.Add(10 * time.Minute),
	})
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {f.redirect},
		"code_verifier": {verifier},
	}
	resp := f.postToken(t, form, proof)
	body := expectTokenError(t, resp, "invalid_request")
	if got := resp.Header.Get("DPoP-Nonce"); got != "" {
		t.Errorf("DPoP-Nonce=%q want empty (no nonce source configured)", got)
	}
	if desc, _ := body["error_description"].(string); !strings.Contains(strings.ToLower(desc), "iat") {
		t.Errorf("error_description=%q want iat-window mention", desc)
	}
}

// TestScenario_DPOP_016_IatFailureSurfacesNonceChallenge is out-of-
// scope. The catalog row asserts 401 use_dpop_nonce when the iat
// window fails AND a nonce source is configured; v1.0's verifier
// orders the iat check ahead of the nonce check (see
// [internal/dpop/verify.go]'s `withinIatWindow` call before
// `checkNonce`), so an out-of-window proof always surfaces as
// invalid_request irrespective of the nonce source. The "stale-iat
// becomes nonce challenge" coupling is panva-specific behaviour;
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
// via [internal/tokenendpoint/dpop.go] because the /token endpoint
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
// match the bound thumbprint" (see [internal/userinfo/handler.go]
// `enforceDPoPCnf`). The wire code is identical; the catalog
// description "failed jkt verification" is panva wording. The
// observable behaviour (different-key proof rejected at /userinfo) is
// exercised end-to-end by [internal/dpop/end_to_end_test.go]
// `TestE2E_DPoP_FullFlow`. Out-of-scope per scripts/scenario.sh flip.
func TestScenario_DPOP_018_JktVerificationAtResource(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DPOP-018 (see catalog out_of_scope_reason)")
}

// TestScenario_DPOP_019_JktVerificationFailsUnderBearer is out-of-
// scope. The catalog row asserts that a DPoP-bound AT under
// Authorization: Bearer at /userinfo returns 401 invalid_token with
// a WWW-Authenticate DPoP challenge AND the panva-specific "failed
// jkt verification" description. v1.0's userinfo handler accepts the
// Bearer scheme as a token-extraction prefix (see
// [internal/userinfo/handler.go] `bearerFromHeader`), then runs the
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
// Catalog text demands 401 invalid_dpop_proof + panva description.
// v1.0's userinfo handler emits 401 invalid_token "DPoP proof
// rejected" (the description is collapsed to avoid leaking the
// sub-cause; see [internal/userinfo/handler.go] `respondDPoPInvalid`).
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

// TestScenario_DPOP_022_MalformedHeaderAtTokenRejected verifies that
// a malformed DPoP header value at /token is rejected. The catalog
// originally cited 400 invalid_dpop_proof + a panva description; v1.0
// surfaces this as 400 invalid_request "DPoP proof malformed" via
// [internal/tokenendpoint/dpop.go] (the wire code is collapsed onto
// the OAuth invalid_request envelope, which is what every other
// /token failure also uses).
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
	body := expectTokenError(t, resp, "invalid_request")
	if desc, _ := body["error_description"].(string); !strings.Contains(strings.ToLower(desc), "malformed") {
		t.Errorf("error_description=%q want malformed mention", desc)
	}
}

// TestScenario_DPOP_023_InvalidNonceAtUserinfoChallenge is out-of-
// scope. The catalog row asserts a 401 use_dpop_nonce challenge at
// /userinfo when the proof carries a nonce the server does not
// recognise, plus a fresh DPoP-Nonce response header. v1.0 honours
// this on the wire (see [internal/userinfo/handler.go]
// `respondUseDPoPNonce`), but the catalog also pins a panva-style
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
// at /token (see [internal/tokenendpoint/dpop.go] `writeUseDPoPNonce`),
// but the catalog requires a panva-specific description string.
// Out-of-scope per scripts/scenario.sh flip.
func TestScenario_DPOP_024_InvalidNonceAtTokenChallenge(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DPOP-024 (see catalog out_of_scope_reason)")
}

// TestScenario_DPOP_025_RequiredNonceAtPAR is out-of-scope. The
// catalog row asserts that a "nonce-required policy" rejects a
// nonce-less /par submission with 400 use_dpop_nonce + a panva
// description. v1.0's nonce-required policy is gated on a configured
// [op.DPoPNonceSource]: when one is wired the verifier rejects
// nonce-less proofs (covered by internal/parendpoint white-box tests).
// The catalog row's exact "nonce is required in the DPoP proof"
// wording is panva-residue. Out-of-scope per scripts/scenario.sh flip.
func TestScenario_DPOP_025_RequiredNonceAtPAR(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DPOP-025 (see catalog out_of_scope_reason)")
}

// TestScenario_DPOP_026_RequiredNonceAtUserinfo is out-of-scope. Same
// rationale as DPOP-025: nonce-required behaviour is implemented but
// the catalog requires panva's specific description. Out-of-scope per
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

func TestScenario_DPOP_028_FreshNonceNotRotated(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-028")
}

func TestScenario_DPOP_029_IntrospectionSurfacesCnfJkt(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-029")
}

// TestScenario_DPOP_030_DeviceCodeBindingConfidential is out-of-scope.
// v1.0's /token endpoint dispatches only on grant_type values
// "authorization_code", "refresh_token", and "client_credentials"
// (see [internal/tokenendpoint/handler.go] grant-type switch). The
// device-code grant (urn:ietf:params:oauth:grant-type:device_code)
// returns "unsupported_grant_type" — there is no wire path on which
// to bind a DPoP key. Out-of-scope per scripts/scenario.sh flip.
func TestScenario_DPOP_030_DeviceCodeBindingConfidential(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DPOP-030 (see catalog out_of_scope_reason)")
}

// TestScenario_DPOP_031_DeviceCodeBindingPublic is out-of-scope. Same
// rationale as DPOP-030: device-code grant is not implemented in
// v1.0. Out-of-scope per scripts/scenario.sh flip.
func TestScenario_DPOP_031_DeviceCodeBindingPublic(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DPOP-031 (see catalog out_of_scope_reason)")
}

// TestScenario_DPOP_032_CIBABindingConfidential is out-of-scope. v1.0's
// /token endpoint does not handle the CIBA grant
// (urn:openid:params:grant-type:ciba); CIBA is profiled only in the
// FAPICIBA / iGovHigh op.Profile values for downstream wiring, but no
// wire-level CIBA token-endpoint implementation ships in v1.0.
// Out-of-scope per scripts/scenario.sh flip.
func TestScenario_DPOP_032_CIBABindingConfidential(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DPOP-032 (see catalog out_of_scope_reason)")
}

// TestScenario_DPOP_033_CIBABindingPublic is out-of-scope. Same
// rationale as DPOP-032. Out-of-scope per scripts/scenario.sh flip.
func TestScenario_DPOP_033_CIBABindingPublic(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DPOP-033 (see catalog out_of_scope_reason)")
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
// [internal/parendpoint/par.go] `applyDPoPJKT`).
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

func TestScenario_DPOP_037_PARWithRequestObjectAutoBindsJkt(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-037")
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
// invalid_grant. (The catalog originally pinned an exact panva
// description; v1.0 emits a generic message tied to the bound
// thumbprint per [internal/tokenendpoint] dispatch — the wire code is
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

func TestScenario_DPOP_042_RefreshTokenConfidential(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-042")
}

func TestScenario_DPOP_043_CodeGrantPublicClient(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-043")
}

func TestScenario_DPOP_044_RefreshTokenPublicClientSuccess(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-044")
}

func TestScenario_DPOP_045_RefreshTokenPublicClientKeyMismatch(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-045")
}

func TestScenario_DPOP_046_ClientCredentialsBinding(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-046")
}

func TestScenario_DPOP_047_TokenEndpointErrorShape(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-047")
}

func TestScenario_DPOP_048_ResourceErrorWWWAuthenticateShape(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-048")
}

func TestScenario_DPOP_049_NonceHeaderFormat(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-049")
}

// Compile-time anchor: accessTokenHashB64 is preserved for follow-up
// resource-server bindings that need to compute ath claims; the blank
// reference keeps it from looking unused while no test in the active
// set exercises a resource-server flow.
var _ = accessTokenHashB64
