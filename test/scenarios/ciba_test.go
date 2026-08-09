package scenarios_test

// Catalog: test/scenarios/catalog/ciba.yaml (CIBA-NNN)
// Spec:
//   - OpenID Connect Client-Initiated Backchannel Authentication Flow — Core 1.0
//   - OpenID Connect Discovery 1.0 §3 (CIBA metadata)
//   - RFC 9126 — Pushed Authorization Requests (interaction with CIBA)
//   - RFC 9101 — JWT-Secured Authorization Request
//   - FAPI-CIBA Profile
//   - RFC 6749 §5.2 — Error response
//   - RFC 7519 §4.1 — Registered JWT claims

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	"github.com/libraz/go-oidc-provider/op/profile"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// cibaURNGrant is the wire form of the CIBA grant_type. The constant is
// hard-coded here rather than imported from op/grant so a rename of the
// public symbol surfaces as a loud test failure on the row that pins
// the discovery shape.
const cibaURNGrant = "urn:openid:params:grant-type:ciba"

// cibaClientSecret is the deterministic confidential-client secret the
// CIBA suite reuses. Mirrors the DEV / CG suite style: a fixed fixture
// so a failure trace can be replayed without seeding the RNG. The
// `-do-not-use` suffix keeps gosec's hardcoded-credential heuristic
// from flagging the const without resorting to a per-line nolint.
const cibaClientSecret = "ciba-client-secret-do-not-use"

// cibaDefaultSubject is the subject the configured HintResolver returns
// for the canonical login_hint "alice". Kept distinct from
// scenariokit.DefaultSubject so a future refactor of the code-flow
// helper does not silently change CIBA's expected subject.
const cibaDefaultSubject = "user-ciba"

// cibaKnownLoginHint is the login_hint / login_hint_token / id_token_hint
// value the resolver maps to cibaDefaultSubject. Any other inbound hint
// produces op.ErrUnknownCIBAUser.
const cibaKnownLoginHint = "alice"

// cibaFixedClock pins the OP's notion of "now" so signed-request claim
// windows (iat / exp / nbf) under FAPI-CIBA behave deterministically.
type cibaFixedClock struct{ t time.Time }

func (c cibaFixedClock) Now() time.Time { return c.t }

// cibaAnchor is the canonical "now" the FAPI-CIBA scenarios pin the OP
// clock to. Mid-day UTC keeps the ±60s skew window well clear of day
// boundaries and the FAPI-CIBA 60s exp / nbf cap composes cleanly
// around it.
var cibaAnchor = time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

// cibaHintResolver is the deterministic [op.HintResolver] every CIBA
// test reuses. "alice" (or whatever cibaKnownLoginHint resolves to)
// returns the canonical subject; any other value returns
// op.ErrUnknownCIBAUser so the unknown_user_id surface can be
// exercised.
type cibaHintResolver struct{}

func (cibaHintResolver) Resolve(_ context.Context, _ op.HintKind, value string) (string, error) {
	// cibaDefaultSubject is accepted alongside the login_hint because
	// the id_token_hint branch never reaches a resolver with a JWT: the
	// OP verifies the token itself and hands over the "sub" it minted
	// (CIBA Core 1.0 §7.1). A resolver keyed only on the login_hint
	// spelling would answer unknown_user_id for a subject the OP had
	// just proved it issued.
	if value == cibaKnownLoginHint || value == cibaDefaultSubject {
		return cibaDefaultSubject, nil
	}
	return "", op.ErrUnknownCIBAUser
}

// cibaProvider bundles the testkit provider with a pre-registered
// CIBA-capable confidential client. The struct exists so each row's
// setup boilerplate stays a single line.
type cibaProvider struct {
	tk     *testkit.Provider
	client *store.Client
}

// newCIBAProvider constructs a fully wired provider with the CIBA grant
// enabled. Returns the provider plus a single confidential client whose
// registered grant_types include the CIBA URN and whose
// token_endpoint_auth_method is client_secret_basic. extra carries
// additional [op.Option] values the caller layers on top of the CIBA
// opt-in (typical use: [op.WithFeature(feature.JAR)] for CIBA-002 /
// 023 / 034). CIBA sub-options (WithCIBAMaxExpiresIn etc.) flow through
// [newCIBAProviderWithCIBAOpts] which composes them inside [op.WithCIBA].
func newCIBAProvider(t *testing.T, scopes []string, extra ...op.Option) *cibaProvider {
	return newCIBAProviderWithCIBAOpts(t, scopes, nil, extra...)
}

// newCIBAProviderWithCIBAOpts mirrors [newCIBAProvider] but lets the
// caller pass [op.CIBAOption] sub-options the test exercises (typical
// use: [op.WithCIBAMaxExpiresIn] for CIBA-017). The HintResolver is
// always wired by the harness so callers cannot forget the
// resolver-presence invariant.
func newCIBAProviderWithCIBAOpts(t *testing.T, scopes []string, cibaOpts []op.CIBAOption, extra ...op.Option) *cibaProvider {
	return newCIBAProviderWithResources(t, scopes, nil, cibaOpts, extra...)
}

// newCIBAProviderWithResources is the resource-aware variant of
// [newCIBAProviderWithCIBAOpts]: it threads resources onto the
// registered client's Resources allowlist so /bc-authorize can admit
// the values the test row sends. A nil/empty resources slice matches
// the default helper.
func newCIBAProviderWithResources(t *testing.T, scopes, resources []string, cibaOpts []op.CIBAOption, extra ...op.Option) *cibaProvider {
	t.Helper()
	hash, err := op.HashClientSecret(cibaClientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	allCIBAOpts := append([]op.CIBAOption{op.WithCIBAHintResolver(cibaHintResolver{})}, cibaOpts...)
	opts := append([]op.Option{op.WithCIBA(allCIBAOpts...)}, extra...)
	tk := testkit.NewProvider(t, testkit.WithOptions(opts...))
	client := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "ciba-rp",
		SecretHash:              hash,
		Scopes:                  scopes,
		Resources:               append([]string(nil), resources...),
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes: []string{
			"authorization_code",
			"refresh_token",
			cibaURNGrant,
		},
	})
	return &cibaProvider{tk: tk, client: client}
}

// cibaPairwiseSalt is the deterministic 32-byte salt the pairwise CIBA
// row wires through op.WithPairwiseSubject. Kept distinct from the
// issuance suite's salt so neither suite's fixtures move when the other
// is edited.
var cibaPairwiseSalt = []byte("ciba-pairwise-fixed-salt-32bytes")

// newCIBAPairwiseProvider mirrors [newCIBAProvider] but registers the
// CIBA client with subject_type=pairwise. It exists for the single row
// that pins how the id_token_hint branch behaves when the client's
// "sub" values are per-sector pseudonyms.
func newCIBAPairwiseProvider(t *testing.T) *cibaProvider {
	t.Helper()
	hash, err := op.HashClientSecret(cibaClientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithCIBA(op.WithCIBAHintResolver(cibaHintResolver{})),
		op.WithPairwiseSubject(cibaPairwiseSalt),
	))
	client := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "ciba-rp",
		SecretHash:              hash,
		Scopes:                  []string{"openid"},
		SubjectType:             "pairwise",
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes: []string{
			"authorization_code",
			"refresh_token",
			cibaURNGrant,
		},
	})
	return &cibaProvider{tk: tk, client: client}
}

// cibaIDTokenHintClaims is the claim set the id_token_hint rows sign.
// Only the members the OP verifies are modelled; iat / exp are carried
// because a real ID Token has them, not because the hint path reads
// them (CIBA Core 1.0 §7.1 verification here is signature, iss, and
// audience — freshness is deliberately not a gate).
type cibaIDTokenHintClaims struct {
	Iss string   `json:"iss"`
	Sub string   `json:"sub"`
	Aud []string `json:"aud"`
	AZP string   `json:"azp,omitempty"`
	Iat int64    `json:"iat,omitempty"`
	Exp int64    `json:"exp,omitempty"`
}

// mintIDTokenHint signs an ID Token with the OP's own active key,
// addressed to the registered CIBA client and naming the subject the
// harness resolver knows. mutate lets a row bend one claim to exercise
// a rejection path; the timestamps are derived from [cibaAnchor] rather
// than the wall clock so a row's outcome never depends on when it ran.
func (p *cibaProvider) mintIDTokenHint(t *testing.T, mutate func(*cibaIDTokenHintClaims)) string {
	t.Helper()
	c := cibaIDTokenHintClaims{
		Iss: p.tk.Issuer,
		Sub: cibaDefaultSubject,
		Aud: []string{p.client.ID},
		Iat: cibaAnchor.Add(-time.Hour).Unix(),
		Exp: cibaAnchor.Add(time.Hour).Unix(),
	}
	if mutate != nil {
		mutate(&c)
	}
	tok, err := p.tk.SignedJWT(c)
	if err != nil {
		t.Fatalf("SignedJWT: %v", err)
	}
	return tok
}

// stubCIBADPoPNonceSource is a minimal [op.DPoPNonceSource] used by
// FAPI-CIBA tests so the profile's DPoP nonce-source mandate is
// satisfied without exercising the runtime nonce-rotation flow.
type stubCIBADPoPNonceSource struct{}

func (stubCIBADPoPNonceSource) IssueNonce() string         { return "ciba-nonce" }
func (stubCIBADPoPNonceSource) Validate(nonce string) bool { return nonce != "" }

// cibaFAPIFixture bundles a FAPI-CIBA-profile testkit Provider with a
// confidential client whose JWKs the harness controls. The signed-
// request rows (CIBA-037..040) reuse the harness across rows.
//
// FAPI-CIBA mandates sender-constrained tokens (DPoP or mTLS), so the
// fixture mints a DPoP keypair alongside the request-object signing
// key and stamps a DPoP proof header on every /bc-authorize POST.
type cibaFAPIFixture struct {
	tk          *testkit.Provider
	clientID    string
	priv        *ecdsa.PrivateKey
	kid         string
	clock       cibaFixedClock
	signTimeRef time.Time
	dpopPriv    *ecdsa.PrivateKey
	dpopJWK     josev4.JSONWebKey
}

// newCIBAFAPIFixture constructs a FAPI-CIBA-profile provider with JAR
// and DPoP enabled, registers a confidential client whose JWKS the
// fixture controls, and returns the harness used to build signed
// request objects against /bc-authorize. The pinned clock keeps the
// FAPI-CIBA 60s exp / nbf window deterministic.
//
// The client is registered with token_endpoint_auth_method=private_key_jwt
// so it satisfies the FAPI-CIBA closed set (private_key_jwt /
// tls_client_auth / self_signed_tls_client_auth) while still
// authenticating to /bc-authorize via a JWT-bearer assertion the
// fixture mints alongside the request object.
func newCIBAFAPIFixture(t *testing.T) *cibaFAPIFixture {
	t.Helper()
	clock := cibaFixedClock{t: cibaAnchor}
	tk := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(
			op.WithCIBA(op.WithCIBAHintResolver(cibaHintResolver{})),
			op.WithProfile(profile.FAPICIBA),
			op.WithFeature(feature.DPoP),
			op.WithDPoPNonceSource(stubCIBADPoPNonceSource{}),
		),
	)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	const kid = "rp-ciba-kid"
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
	const clientID = "ciba-fapi-rp"
	//nolint:gosec // G101: test fixture, not a real credential.
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		Scopes:                  []string{"openid", "profile"},
		TokenEndpointAuthMethod: "private_key_jwt",
		GrantTypes: []string{
			"authorization_code",
			"refresh_token",
			cibaURNGrant,
		},
	})
	updated := *rp
	updated.JWKs = jwksRaw
	if err := tk.Store.UpdateClient(context.Background(), &updated); err != nil {
		t.Fatalf("UpdateClient(JWKs): %v", err)
	}
	dpopPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey(dpop): %v", err)
	}
	dpopJWK := josev4.JSONWebKey{
		Key:       &dpopPriv.PublicKey,
		Algorithm: string(josev4.ES256),
		Use:       "sig",
	}
	return &cibaFAPIFixture{
		tk:          tk,
		clientID:    clientID,
		priv:        priv,
		kid:         kid,
		clock:       clock,
		signTimeRef: clock.t,
		dpopPriv:    dpopPriv,
		dpopJWK:     dpopJWK,
	}
}

// dpopProof returns a fresh DPoP proof JWS for the fixture's
// /bc-authorize endpoint. Each call mints a unique jti so successive
// /bc-authorize POSTs in the same test do not collide on the
// consumed-jti gate the verifier maintains. iat is anchored on the
// fixture's pinned clock. The proof carries the FAPI-CIBA-mandated
// "nonce" claim (RFC 9449 §8) using the value the fixture's
// stubCIBADPoPNonceSource issues; FAPI-CIBA verifiers reject proofs
// without it via the use_dpop_nonce challenge.
func (f *cibaFAPIFixture) dpopProof(t *testing.T) string {
	t.Helper()
	signerOpts := (&josev4.SignerOptions{}).
		WithType("dpop+jwt").
		WithHeader("jwk", f.dpopJWK)
	signer, err := josev4.NewSigner(
		josev4.SigningKey{Algorithm: josev4.ES256, Key: f.dpopPriv},
		signerOpts,
	)
	if err != nil {
		t.Fatalf("dpopProof: NewSigner: %v", err)
	}
	var jtiBytes [16]byte
	if _, err := rand.Read(jtiBytes[:]); err != nil {
		t.Fatalf("dpopProof: rand.Read: %v", err)
	}
	htu := f.tk.Server.URL + "/oidc/bc-authorize"
	claims := map[string]any{
		"htm":   http.MethodPost,
		"htu":   htu,
		"iat":   f.signTimeRef.Unix(),
		"jti":   "ciba-dpop-" + base64.RawURLEncoding.EncodeToString(jtiBytes[:]),
		"nonce": stubCIBADPoPNonceSource{}.IssueNonce(),
	}
	out, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("dpopProof: Serialize: %v", err)
	}
	return out
}

// dpopJKT returns the SHA-256 thumbprint of the fixture's DPoP key.
// Tests that assert on cnf.jkt persistence consult this value.
//
//nolint:unused // available to future rows that exercise cnf.jkt persistence.
func (f *cibaFAPIFixture) dpopJKT(t *testing.T) string {
	t.Helper()
	thumb, err := f.dpopJWK.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatalf("dpopJKT: Thumbprint: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(thumb)
}

// happyClaims returns the canonical request-object claim set the
// FAPI-CIBA scenarios start from. Tests mutate the returned map
// (typically by deleting a single registered claim) before signing.
// Each call mints a fresh jti so successive request objects in the
// same test do not collide on the consumed-jti gate.
func (f *cibaFAPIFixture) happyClaims() map[string]any {
	now := f.signTimeRef
	return map[string]any{
		"iss":        f.clientID,
		"aud":        f.tk.Issuer,
		"exp":        now.Add(30 * time.Second).Unix(),
		"iat":        now.Unix(),
		"nbf":        now.Unix(),
		"jti":        freshCIBAJTI(),
		"client_id":  f.clientID,
		"scope":      "openid",
		"login_hint": cibaKnownLoginHint,
	}
}

// signES256 serialises claims as a compact ES256 JWS using the
// fixture's keypair / kid.
func (f *cibaFAPIFixture) signES256(t *testing.T, claims map[string]any) string {
	t.Helper()
	signer, err := josev4.NewSigner(josev4.SigningKey{
		Algorithm: josev4.ES256,
		Key: josev4.JSONWebKey{
			Key:       f.priv,
			KeyID:     f.kid,
			Algorithm: string(josev4.ES256),
			Use:       "sig",
		},
	}, (&josev4.SignerOptions{}).WithType("oauth-authz-req+jwt"))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	out, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return out
}

// signClientAssertion mints a private_key_jwt client assertion for the
// fixture's confidential client. /bc-authorize accepts the same client
// authentication contract as /token, so the assertion's aud is the
// issuer + endpoint URL.
func (f *cibaFAPIFixture) signClientAssertion(t *testing.T) string {
	t.Helper()
	now := f.signTimeRef
	claims := map[string]any{
		"iss": f.clientID,
		"sub": f.clientID,
		"aud": f.tk.Issuer,
		"exp": now.Add(30 * time.Second).Unix(),
		"iat": now.Unix(),
		"jti": freshCIBAJTI(),
	}
	return f.signES256(t, claims)
}

// freshCIBAJTI mints a 128-bit random JWT identifier suitable for a
// single end-to-end request object. crypto/rand is used directly so
// successive request objects in the same test never collide on the
// consumed-jti gate (RFC 9101 §10.8).
func freshCIBAJTI() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return "ciba-jti-" + hex.EncodeToString(b[:])
}

// bcAuthorizeForm wraps a form-encoded POST against /bc-authorize using
// the registered client's basic-auth credentials. It returns the
// status code, the decoded JSON body (or nil on a non-JSON response),
// and the response headers.
func (p *cibaProvider) bcAuthorizeForm(t *testing.T, form url.Values) (int, map[string]any, http.Header) {
	t.Helper()
	return p.bcAuthorizeFormWithAuth(t, form, p.client.ID, cibaClientSecret, "application/x-www-form-urlencoded")
}

// bcAuthorizeFormWithAuth lets a caller vary the basic-auth credentials
// or the Content-Type. The helper returns (status, decoded body,
// response headers); the body is nil when the response is not JSON.
func (p *cibaProvider) bcAuthorizeFormWithAuth(t *testing.T, form url.Values, user, pass, contentType string) (int, map[string]any, http.Header) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		p.tk.Server.URL+"/oidc/bc-authorize", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest /bc-authorize: %v", err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	resp, err := p.tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /bc-authorize: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var decoded map[string]any
	if len(body) > 0 && strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "application/json") {
		if err := json.Unmarshal(body, &decoded); err != nil {
			t.Fatalf("unmarshal /bc-authorize body=%q: %v", body, err)
		}
	}
	return resp.StatusCode, decoded, resp.Header.Clone()
}

// bcAuthorizeFAPIForm wraps a form-encoded POST against /bc-authorize
// using the FAPI fixture: it stamps the private_key_jwt client
// assertion plus the DPoP proof header (FAPI-CIBA mandates sender-
// constrained tokens) and returns the parsed response. Tests that
// exercise the signed-request channel set form["request"] to the
// encoded JWS.
func (f *cibaFAPIFixture) bcAuthorizeFAPIForm(t *testing.T, form url.Values) (int, map[string]any) {
	t.Helper()
	form.Set("client_id", f.clientID)
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", f.signClientAssertion(t))
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		f.tk.Server.URL+"/oidc/bc-authorize", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest /bc-authorize: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", f.dpopProof(t))
	resp, err := f.tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /bc-authorize: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var decoded map[string]any
	if len(body) > 0 && strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "application/json") {
		if err := json.Unmarshal(body, &decoded); err != nil {
			t.Fatalf("unmarshal /bc-authorize body=%q: %v", body, err)
		}
	}
	return resp.StatusCode, decoded
}

// fetchCIBADiscovery returns the OP's discovery document as a decoded
// JSON map. Mirrors fetchDevDiscovery so the CIBA suite stays
// self-contained.
func fetchCIBADiscovery(t *testing.T, base string) map[string]any {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		base+"/.well-known/openid-configuration", nil)
	if err != nil {
		t.Fatalf("NewRequest discovery: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery status=%d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read discovery body: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshal discovery: %v", err)
	}
	return doc
}

// expectCIBAError asserts the body shape of an RFC 6749 §5.2 error
// envelope. The helper short-circuits the boilerplate that every
// rejection row would otherwise repeat.
func expectCIBAError(t *testing.T, body map[string]any, wantCode string) {
	t.Helper()
	got, _ := body["error"].(string)
	if got != wantCode {
		t.Errorf("error=%q want %q (body=%v)", got, wantCode, body)
	}
	if _, present := body["auth_req_id"]; present {
		t.Errorf("rejection must not mint auth_req_id: %v", body)
	}
}

// findCIBARecord looks up the persisted store.CIBARequest behind an
// auth_req_id. Tests use it to assert on subject / scope / hint kind
// the handler stamped on the record.
func (p *cibaProvider) findCIBARecord(t *testing.T, authReqID string) *store.CIBARequest {
	t.Helper()
	rec, err := p.tk.Store.CIBARequests().FindByAuthReqID(context.Background(), authReqID)
	if err != nil {
		t.Fatalf("FindByAuthReqID(%q): %v", authReqID, err)
	}
	return rec
}

// ---------------------------------------------------------------------
// Discovery — CIBA-001, CIBA-002
// ---------------------------------------------------------------------

// TestScenario_CIBA_001_DiscoveryAdvertisesCIBAMetadata pins the
// CIBA-on / JAR-off discovery surface: backchannel_authentication_endpoint
// is published under the OP's mountPrefix; the delivery-modes list is
// poll-only (ping is deferred); the user-code flag is false; and the
// signed-request alg list MUST be absent because that field shares the
// JAR verifier and JAR is not enabled.
//
// Spec: CIBA Core §4, OIDC Discovery §3.
func TestScenario_CIBA_001_DiscoveryAdvertisesCIBAMetadata(t *testing.T) {
	t.Parallel()
	p := newCIBAProvider(t, []string{"openid", "profile"})
	doc := fetchCIBADiscovery(t, p.tk.Server.URL)

	endpoint, _ := doc["backchannel_authentication_endpoint"].(string)
	if endpoint == "" {
		t.Fatalf("backchannel_authentication_endpoint missing: %v", doc)
	}
	if !strings.HasPrefix(endpoint, p.tk.Issuer) {
		t.Errorf("backchannel_authentication_endpoint=%q must be under issuer %q", endpoint, p.tk.Issuer)
	}
	if !strings.HasSuffix(endpoint, "/bc-authorize") {
		t.Errorf("backchannel_authentication_endpoint=%q must end with /bc-authorize", endpoint)
	}

	modes, ok := doc["backchannel_token_delivery_modes_supported"].([]any)
	if !ok || len(modes) != 1 {
		t.Fatalf("backchannel_token_delivery_modes_supported=%v want single-entry [poll]", doc["backchannel_token_delivery_modes_supported"])
	}
	if got, _ := modes[0].(string); got != "poll" {
		t.Errorf("delivery mode[0]=%q want poll", got)
	}

	// The discovery document tags backchannel_user_code_parameter_supported
	// with omitempty, so JSON treats false ≡ absent. Both shapes are
	// acceptable; what we forbid is the field appearing as true.
	if userCode, ok := doc["backchannel_user_code_parameter_supported"].(bool); ok && userCode {
		t.Errorf("backchannel_user_code_parameter_supported=true want false (or absent)")
	}

	if _, present := doc["backchannel_authentication_request_signing_alg_values_supported"]; present {
		t.Errorf("backchannel_authentication_request_signing_alg_values_supported MUST be absent without JAR feature")
	}
}

// TestScenario_CIBA_002_DiscoveryAdvertisesSignedRequestAlgs pins the
// CIBA + JAR discovery surface: with JAR enabled,
// backchannel_authentication_request_signing_alg_values_supported is
// published as the FAPI-CIBA-compatible asymmetric set
// (RS256, PS256, ES256, EdDSA). The list MUST exclude HS-family
// algorithms — FAPI-CIBA forbids symmetric request-object signatures.
//
// Spec: CIBA Core §7.1.1, FAPI-CIBA §5.2.2, OIDC Discovery §3.
func TestScenario_CIBA_002_DiscoveryAdvertisesSignedRequestAlgs(t *testing.T) {
	t.Parallel()
	p := newCIBAProvider(t, []string{"openid"}, op.WithFeature(feature.JAR))
	doc := fetchCIBADiscovery(t, p.tk.Server.URL)

	raw, ok := doc["backchannel_authentication_request_signing_alg_values_supported"].([]any)
	if !ok {
		t.Fatalf("backchannel_authentication_request_signing_alg_values_supported missing or not a list: %v",
			doc["backchannel_authentication_request_signing_alg_values_supported"])
	}
	got := make([]string, 0, len(raw))
	for _, v := range raw {
		s, _ := v.(string)
		got = append(got, s)
	}
	wantAll := map[string]bool{"RS256": false, "PS256": false, "ES256": false, "EdDSA": false}
	for _, alg := range got {
		if _, ok := wantAll[alg]; ok {
			wantAll[alg] = true
		}
		if strings.HasPrefix(alg, "HS") {
			t.Errorf("alg %q (HS-family) MUST NOT appear; FAPI-CIBA forbids symmetric request-object signatures", alg)
		}
	}
	for alg, present := range wantAll {
		if !present {
			t.Errorf("alg %q missing from list %v", alg, got)
		}
	}
}

// ---------------------------------------------------------------------
// Permanent OOS — backchannelResult provider API (CIBA-003..011)
// ---------------------------------------------------------------------

// TestScenario_CIBA_003_BackchannelResultResolvesRequestJTI is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_003_BackchannelResultResolvesRequestJTI(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-003 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_004_BackchannelResultAcceptsTypedRequest is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_004_BackchannelResultAcceptsTypedRequest(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-004 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_005_BackchannelResultRejectsInvalidRequestType is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_005_BackchannelResultRejectsInvalidRequestType(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-005 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_006_BackchannelResultResolvesGrantJTI is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_006_BackchannelResultResolvesGrantJTI(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-006 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_007_BackchannelResultRejectsInvalidResultType is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_007_BackchannelResultRejectsInvalidResultType(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-007 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_008_BackchannelResultRejectsUnknownClient is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_008_BackchannelResultRejectsUnknownClient(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-008 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_009_BackchannelResultRejectsClientMismatch is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_009_BackchannelResultRejectsClientMismatch(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-009 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_010_BackchannelResultRejectsAccountMismatch is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_010_BackchannelResultRejectsAccountMismatch(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-010 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_011_BackchannelResultPersistsUnsavedRequest is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_011_BackchannelResultPersistsUnsavedRequest(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-011 (see catalog out_of_scope_reason)")
}

// ---------------------------------------------------------------------
// Permanent OOS — ping-mode delivery (CIBA-012..014)
// ---------------------------------------------------------------------

// TestScenario_CIBA_012_PingDeliverySuccess204 is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_012_PingDeliverySuccess204(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-012 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_013_PingDeliverySuccess200 is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_013_PingDeliverySuccess200(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-013 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_014_PingDeliveryFailure400 is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_014_PingDeliveryFailure400(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-014 (see catalog out_of_scope_reason)")
}

// ---------------------------------------------------------------------
// /bc-authorize endpoint — happy paths
// ---------------------------------------------------------------------

// TestScenario_CIBA_015_BackchannelHappyPathWithLoginHint pins the
// canonical happy path: POST /bc-authorize with login_hint and
// scope=openid + valid client auth returns 200 application/json with a
// non-empty auth_req_id, expires_in, and interval. The persisted
// store.CIBARequest carries the resolver-supplied subject and the
// requested scope.
//
// Spec: CIBA Core §7.1, §7.3.
func TestScenario_CIBA_015_BackchannelHappyPathWithLoginHint(t *testing.T) {
	t.Parallel()
	p := newCIBAProvider(t, []string{"openid", "profile"})

	form := url.Values{
		"login_hint": {cibaKnownLoginHint},
		"scope":      {"openid"},
	}
	status, body, headers := p.bcAuthorizeForm(t, form)
	if status != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%v", status, body)
	}
	if got := headers.Get("Content-Type"); !strings.HasPrefix(strings.ToLower(got), "application/json") {
		t.Errorf("Content-Type=%q want application/json*", got)
	}
	if got := headers.Get("Cache-Control"); !strings.Contains(strings.ToLower(got), "no-store") {
		t.Errorf("Cache-Control=%q must contain no-store", got)
	}

	authReqID, _ := body["auth_req_id"].(string)
	if authReqID == "" {
		t.Fatalf("auth_req_id missing/empty: %v", body)
	}
	for _, field := range []string{"expires_in", "interval"} {
		got, ok := body[field].(float64)
		if !ok || got <= 0 {
			t.Errorf("%s=%v want positive number", field, body[field])
		}
	}

	rec := p.findCIBARecord(t, authReqID)
	if rec.Subject != cibaDefaultSubject {
		t.Errorf("persisted subject=%q want %q", rec.Subject, cibaDefaultSubject)
	}
	if len(rec.Scope) != 1 || rec.Scope[0] != "openid" {
		t.Errorf("persisted scope=%v want [openid]", rec.Scope)
	}
	if rec.ClientID != p.client.ID {
		t.Errorf("persisted client_id=%q want %q", rec.ClientID, p.client.ID)
	}
}

// TestScenario_CIBA_016_BackchannelBypassesPARRequirement pins that
// /bc-authorize is its own request channel and does not flow through
// PAR. A deployment with PAR enabled MUST still accept a direct
// /bc-authorize POST — there is no request_uri push step in CIBA.
//
// Spec: CIBA Core §7.1, RFC 9126 §2.
func TestScenario_CIBA_016_BackchannelBypassesPARRequirement(t *testing.T) {
	t.Parallel()
	p := newCIBAProvider(t, []string{"openid"}, op.WithFeature(feature.PAR))

	status, body, _ := p.bcAuthorizeForm(t, url.Values{
		"login_hint": {cibaKnownLoginHint},
		"scope":      {"openid"},
	})
	if status != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%v", status, body)
	}
	if id, _ := body["auth_req_id"].(string); id == "" {
		t.Errorf("auth_req_id missing: %v", body)
	}
}

// TestScenario_CIBA_017_RequestedExpiryIsHonoured pins the
// requested_expiry honour-and-clamp surface: when the OP's CIBA
// max-expiry is at least 300s and the client supplies
// requested_expiry=300, the response expires_in is exactly 300.
//
// Spec: CIBA Core §7.1.
func TestScenario_CIBA_017_RequestedExpiryIsHonoured(t *testing.T) {
	t.Parallel()
	p := newCIBAProviderWithCIBAOpts(t, []string{"openid"},
		[]op.CIBAOption{op.WithCIBAMaxExpiresIn(10 * time.Minute)})

	status, body, _ := p.bcAuthorizeForm(t, url.Values{
		"login_hint":       {cibaKnownLoginHint},
		"scope":            {"openid"},
		"requested_expiry": {"300"},
	})
	if status != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%v", status, body)
	}
	got, ok := body["expires_in"].(float64)
	if !ok {
		t.Fatalf("expires_in=%v not a number", body["expires_in"])
	}
	if int(got) != 300 {
		t.Errorf("expires_in=%d want 300", int(got))
	}
}

// TestScenario_CIBA_018_BackchannelHappyPathWithLoginHintToken pins the
// login_hint_token branch: same wire shape as login_hint but the
// persisted record's hint_kind is "login_hint_token".
//
// Spec: CIBA Core §7.1.
func TestScenario_CIBA_018_BackchannelHappyPathWithLoginHintToken(t *testing.T) {
	t.Parallel()
	p := newCIBAProvider(t, []string{"openid"})

	status, body, _ := p.bcAuthorizeForm(t, url.Values{
		"login_hint_token": {cibaKnownLoginHint},
		"scope":            {"openid"},
	})
	if status != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%v", status, body)
	}
	authReqID, _ := body["auth_req_id"].(string)
	if authReqID == "" {
		t.Fatalf("auth_req_id missing: %v", body)
	}
	rec := p.findCIBARecord(t, authReqID)
	if rec.Subject != cibaDefaultSubject {
		t.Errorf("subject=%q want %q", rec.Subject, cibaDefaultSubject)
	}
}

// TestScenario_CIBA_019_BackchannelHappyPathWithIDTokenHint pins the
// id_token_hint branch: the OP verifies the token itself — signature
// against its own keyset, iss, and an audience naming the client that
// authenticated on this request — and hands the resolver the verified
// "sub" rather than the JWT. A hint that clears those checks and names
// a subject the resolver knows yields 200 OK.
//
// Spec: CIBA Core §7.1.
func TestScenario_CIBA_019_BackchannelHappyPathWithIDTokenHint(t *testing.T) {
	t.Parallel()
	p := newCIBAProvider(t, []string{"openid"})

	status, body, _ := p.bcAuthorizeForm(t, url.Values{
		"id_token_hint": {p.mintIDTokenHint(t, nil)},
		"scope":         {"openid"},
	})
	if status != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%v", status, body)
	}
	authReqID, _ := body["auth_req_id"].(string)
	if authReqID == "" {
		t.Fatalf("auth_req_id missing: %v", body)
	}
	rec := p.findCIBARecord(t, authReqID)
	if rec.Subject != cibaDefaultSubject {
		t.Errorf("subject=%q want %q", rec.Subject, cibaDefaultSubject)
	}
}

// TestScenario_CIBA_050_BackchannelRejectsUnverifiableIDTokenHint pins
// the gate CIBA Core 1.0 §7.1 places on the OP. Each row hands
// /bc-authorize a token that fails exactly one of the checks the OP
// owes, and each MUST be refused before any HintResolver runs.
//
// The audience row is the load-bearing one: without it, any client
// registered for CIBA could present an ID Token minted for a different
// client and have the authentication ceremony addressed to a subject it
// was never entitled to name. The others close the surrounding paths —
// an unsigned-by-us token, a token from another issuer, and a bare
// opaque string, which is what an id_token_hint looks like when the
// verification is skipped entirely.
//
// Spec: CIBA Core §7.1, OIDC Core 1.0 §2 (azp).
func TestScenario_CIBA_050_BackchannelRejectsUnverifiableIDTokenHint(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		hint func(t *testing.T, p *cibaProvider) string
	}{
		{
			name: "issued to another client",
			hint: func(t *testing.T, p *cibaProvider) string {
				t.Helper()
				return p.mintIDTokenHint(t, func(c *cibaIDTokenHintClaims) {
					c.Aud = []string{"some-other-rp"}
				})
			},
		},
		{
			name: "azp names another client",
			hint: func(t *testing.T, p *cibaProvider) string {
				t.Helper()
				return p.mintIDTokenHint(t, func(c *cibaIDTokenHintClaims) {
					c.Aud = []string{p.client.ID, "some-other-rp"}
					c.AZP = "some-other-rp"
				})
			},
		},
		{
			name: "minted by another issuer",
			hint: func(t *testing.T, p *cibaProvider) string {
				t.Helper()
				return p.mintIDTokenHint(t, func(c *cibaIDTokenHintClaims) {
					c.Iss = "https://other-op.example.com"
				})
			},
		},
		{
			name: "not a JWS at all",
			hint: func(t *testing.T, _ *cibaProvider) string {
				t.Helper()
				return cibaKnownLoginHint
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := newCIBAProvider(t, []string{"openid"})

			status, body, _ := p.bcAuthorizeForm(t, url.Values{
				"id_token_hint": {tc.hint(t, p)},
				"scope":         {"openid"},
			})
			if status != http.StatusBadRequest {
				t.Fatalf("status=%d want 400 body=%v", status, body)
			}
			if body["error"] != "invalid_request" {
				t.Errorf("error=%v want invalid_request", body["error"])
			}
		})
	}
}

// TestScenario_CIBA_051_BackchannelAcceptsExpiredIDTokenHint pins a
// deliberate policy choice rather than a spec clause. A CIBA
// consumption device legitimately holds an ID Token minted during a
// session that ended long ago; ID Tokens are short-lived, so an exp
// gate would reject nearly every real hint and the primary CIBA use
// case would not work. Freshness also buys nothing here — the client
// has authenticated at the endpoint, and it is the signature plus the
// audience binding that establish who is asking.
//
// The same choice is made for RP-Initiated Logout's id_token_hint, so
// the two hint surfaces stay consistent.
func TestScenario_CIBA_051_BackchannelAcceptsExpiredIDTokenHint(t *testing.T) {
	t.Parallel()
	p := newCIBAProvider(t, []string{"openid"})

	hint := p.mintIDTokenHint(t, func(c *cibaIDTokenHintClaims) {
		c.Iat = cibaAnchor.Add(-48 * time.Hour).Unix()
		c.Exp = cibaAnchor.Add(-47 * time.Hour).Unix()
	})
	status, body, _ := p.bcAuthorizeForm(t, url.Values{
		"id_token_hint": {hint},
		"scope":         {"openid"},
	})
	if status != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%v", status, body)
	}
	authReqID, _ := body["auth_req_id"].(string)
	if authReqID == "" {
		t.Fatalf("auth_req_id missing: %v", body)
	}
	if rec := p.findCIBARecord(t, authReqID); rec.Subject != cibaDefaultSubject {
		t.Errorf("subject=%q want %q", rec.Subject, cibaDefaultSubject)
	}
}

// TestScenario_CIBA_052_BackchannelRefusesIDTokenHintFromPairwiseClient
// pins the one configuration where the OP cannot honour an
// id_token_hint at all. A pairwise client's "sub" is a per-sector
// pseudonym (OIDC Core §8.1) that the OP keeps no reverse index for,
// so passing it to a resolver would either fail confusingly or invite
// the embedder to guess. The refusal is explicit and names the
// alternatives; the same client's login_hint path still works, which
// is what distinguishes "this hint kind is unsupported here" from
// "pairwise clients cannot use CIBA".
//
// Spec: CIBA Core §7.1, OIDC Core §8.1.
func TestScenario_CIBA_052_BackchannelRefusesIDTokenHintFromPairwiseClient(t *testing.T) {
	t.Parallel()
	p := newCIBAPairwiseProvider(t)

	status, body, _ := p.bcAuthorizeForm(t, url.Values{
		"id_token_hint": {p.mintIDTokenHint(t, nil)},
		"scope":         {"openid"},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("id_token_hint: status=%d want 400 body=%v", status, body)
	}
	if body["error"] != "invalid_request" {
		t.Errorf("error=%v want invalid_request", body["error"])
	}

	status, body, _ = p.bcAuthorizeForm(t, url.Values{
		"login_hint": {cibaKnownLoginHint},
		"scope":      {"openid"},
	})
	if status != http.StatusOK {
		t.Fatalf("login_hint: status=%d want 200 body=%v", status, body)
	}
}

// ---------------------------------------------------------------------
// /bc-authorize — client-binding gates (CIBA-020, CIBA-021)
// ---------------------------------------------------------------------

// TestScenario_CIBA_020_BackchannelRequiresGrantTypeAllowance pins the
// per-client gate on /bc-authorize: a client whose registered
// grant_types do not include the CIBA URN MUST be rejected with 400
// unauthorized_client and the description "client is not authorized
// for the ciba grant".
//
// Spec: CIBA Core §4.
func TestScenario_CIBA_020_BackchannelRequiresGrantTypeAllowance(t *testing.T) {
	t.Parallel()
	hash, err := op.HashClientSecret(cibaClientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithCIBA(op.WithCIBAHintResolver(cibaHintResolver{})),
	))
	client := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "ciba-rp-no-grant",
		SecretHash:              hash,
		Scopes:                  []string{"openid"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code"}, // no CIBA URN
	})

	form := url.Values{
		"login_hint": {cibaKnownLoginHint},
		"scope":      {"openid"},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/bc-authorize", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(client.ID, cibaClientSecret)
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not JSON: %v (raw=%q)", err, body)
	}
	expectCIBAError(t, env, "unauthorized_client")
}

// TestScenario_CIBA_021_BackchannelRejectsUnknownClient pins the
// client-authentication gate on /bc-authorize: an unknown or wrongly-
// authenticated client receives 401 invalid_client per RFC 6749 §5.2.
//
// Spec: RFC 6749 §5.2, CIBA Core §7.1.
func TestScenario_CIBA_021_BackchannelRejectsUnknownClient(t *testing.T) {
	t.Parallel()
	p := newCIBAProvider(t, []string{"openid"})

	status, body, _ := p.bcAuthorizeFormWithAuth(t, url.Values{
		"login_hint": {cibaKnownLoginHint},
		"scope":      {"openid"},
	}, "no-such-client", "no-such-secret", "application/x-www-form-urlencoded")
	if status != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 body=%v", status, body)
	}
	expectCIBAError(t, body, "invalid_client")
}

// ---------------------------------------------------------------------
// /bc-authorize — wire-shape gates (CIBA-022, CIBA-023)
// ---------------------------------------------------------------------

// TestScenario_CIBA_022_BackchannelRejectsNonFormBody pins the
// content-type gate on /bc-authorize: any media type other than
// application/x-www-form-urlencoded yields 400 invalid_request with
// the description "content-type must be application/x-www-form-urlencoded".
//
// Spec: CIBA Core §7, RFC 6749 §3.2.
func TestScenario_CIBA_022_BackchannelRejectsNonFormBody(t *testing.T) {
	t.Parallel()
	p := newCIBAProvider(t, []string{"openid"})

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		p.tk.Server.URL+"/oidc/bc-authorize", strings.NewReader(`{"scope":"openid"}`))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(p.client.ID, cibaClientSecret)
	resp, err := p.tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not JSON: %v (raw=%q)", err, body)
	}
	expectCIBAError(t, env, "invalid_request")
}

// TestScenario_CIBA_023_BackchannelRejectsRequestWithoutJAR pins that
// /bc-authorize rejects a "request" form parameter when the JAR
// feature is off: 400 invalid_request with the description
// "request is not supported by this OP". CIBA Core §13 enumerates a
// closed wire-error list for the backchannel-authentication endpoint
// (invalid_request, invalid_scope, invalid_client, expired_login_hint_token,
// unknown_user_id, unauthorized_client, missing_user_code, invalid_user_code,
// invalid_binding_message, invalid_client, transaction_failed, access_denied);
// invalid_request_object is NOT on that list, so any JAR-side failure
// surfaces as the closest §13 entry — invalid_request.
//
// Spec: CIBA Core §7.1.1, §13.
func TestScenario_CIBA_023_BackchannelRejectsRequestWithoutJAR(t *testing.T) {
	t.Parallel()
	p := newCIBAProvider(t, []string{"openid"}) // JAR feature off

	status, body, _ := p.bcAuthorizeForm(t, url.Values{
		"login_hint": {cibaKnownLoginHint},
		"scope":      {"openid"},
		"request":    {"eyJhbGciOiJub25lIn0.e30."},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", status, body)
	}
	expectCIBAError(t, body, "invalid_request")
}

// ---------------------------------------------------------------------
// Permanent OOS — request_uri / registration parameters (CIBA-024, 025)
// ---------------------------------------------------------------------

// TestScenario_CIBA_024_BackchannelRejectsRequestURI is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_024_BackchannelRejectsRequestURI(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-024 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_025_BackchannelRejectsRegistration is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_025_BackchannelRejectsRegistration(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-025 (see catalog out_of_scope_reason)")
}

// ---------------------------------------------------------------------
// /bc-authorize — hint resolution (CIBA-026, CIBA-027)
// ---------------------------------------------------------------------

// TestScenario_CIBA_026_BackchannelRejectsUnknownLoginHint pins the
// unknown_user_id surface on the login_hint branch: when the
// HintResolver returns op.ErrUnknownCIBAUser, /bc-authorize returns
// 400 unknown_user_id with the description "the hint did not resolve
// to a known end-user".
//
// Spec: CIBA Core §7.1, §13.
func TestScenario_CIBA_026_BackchannelRejectsUnknownLoginHint(t *testing.T) {
	t.Parallel()
	p := newCIBAProvider(t, []string{"openid"})

	status, body, _ := p.bcAuthorizeForm(t, url.Values{
		"login_hint": {"unknown-user"},
		"scope":      {"openid"},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", status, body)
	}
	expectCIBAError(t, body, "unknown_user_id")
}

// TestScenario_CIBA_027_BackchannelRejectsUnknownLoginHintToken pins
// the unknown_user_id surface on the login_hint_token branch: the
// resolver's op.ErrUnknownCIBAUser maps to the same wire envelope as
// for login_hint.
//
// Spec: CIBA Core §7.1.1.
func TestScenario_CIBA_027_BackchannelRejectsUnknownLoginHintToken(t *testing.T) {
	t.Parallel()
	p := newCIBAProvider(t, []string{"openid"})

	status, body, _ := p.bcAuthorizeForm(t, url.Values{
		"login_hint_token": {"unknown-token-value"},
		"scope":            {"openid"},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", status, body)
	}
	expectCIBAError(t, body, "unknown_user_id")
}

// ---------------------------------------------------------------------
// /bc-authorize — scope / requested_expiry / hint combinatorics
// ---------------------------------------------------------------------

// TestScenario_CIBA_028_BackchannelRequiresScope pins the
// scope-required gate: a request omitting scope is rejected with 400
// invalid_request and the description "scope parameter is required".
//
// Spec: CIBA Core §7.1.
func TestScenario_CIBA_028_BackchannelRequiresScope(t *testing.T) {
	t.Parallel()
	p := newCIBAProvider(t, []string{"openid"})

	status, body, _ := p.bcAuthorizeForm(t, url.Values{
		"login_hint": {cibaKnownLoginHint},
		// no scope
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", status, body)
	}
	expectCIBAError(t, body, "invalid_request")
}

// TestScenario_CIBA_029_PingRequiresClientNotificationToken is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_029_PingRequiresClientNotificationToken(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-029 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_030_BackchannelRequiresOpenIDScope pins the
// scope-must-include-openid gate: a scope value that lacks openid is
// rejected with 400 invalid_scope and the description "the openid
// scope value is required for ciba".
//
// Spec: CIBA Core §7.1.
func TestScenario_CIBA_030_BackchannelRequiresOpenIDScope(t *testing.T) {
	t.Parallel()
	p := newCIBAProvider(t, []string{"openid", "profile"})

	status, body, _ := p.bcAuthorizeForm(t, url.Values{
		"login_hint": {cibaKnownLoginHint},
		"scope":      {"profile"}, // lacks openid
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", status, body)
	}
	expectCIBAError(t, body, "invalid_scope")
}

// TestScenario_CIBA_031_BackchannelValidatesRequestedExpiry pins the
// requested_expiry shape gate: zero, negative, and non-numeric values
// MUST all be rejected with 400 invalid_request and the description
// "requested_expiry must be a positive integer".
//
// Spec: CIBA Core §7.1.
func TestScenario_CIBA_031_BackchannelValidatesRequestedExpiry(t *testing.T) {
	t.Parallel()
	p := newCIBAProvider(t, []string{"openid"})

	for _, raw := range []string{"0", "-1", "abc"} {
		t.Run("requested_expiry="+raw, func(t *testing.T) {
			t.Parallel()
			status, body, _ := p.bcAuthorizeForm(t, url.Values{
				"login_hint":       {cibaKnownLoginHint},
				"scope":            {"openid"},
				"requested_expiry": {raw},
			})
			if status != http.StatusBadRequest {
				t.Fatalf("status=%d want 400 body=%v", status, body)
			}
			expectCIBAError(t, body, "invalid_request")
		})
	}
}

// TestScenario_CIBA_032_BackchannelRequiresAtLeastOneHint pins the
// hint-required gate: a request supplying none of login_hint /
// id_token_hint / login_hint_token is rejected with 400
// invalid_request and the description "exactly one of login_hint,
// id_token_hint, or login_hint_token is required".
//
// Spec: CIBA Core §7.1.
func TestScenario_CIBA_032_BackchannelRequiresAtLeastOneHint(t *testing.T) {
	t.Parallel()
	p := newCIBAProvider(t, []string{"openid"})

	status, body, _ := p.bcAuthorizeForm(t, url.Values{
		"scope": {"openid"},
		// no hint
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", status, body)
	}
	expectCIBAError(t, body, "invalid_request")
}

// TestScenario_CIBA_033_BackchannelRejectsMultipleHints pins the
// exactly-one-hint gate: a request supplying more than one hint is
// rejected with the same 400 invalid_request envelope as CIBA-032.
//
// Spec: CIBA Core §7.1.
func TestScenario_CIBA_033_BackchannelRejectsMultipleHints(t *testing.T) {
	t.Parallel()
	p := newCIBAProvider(t, []string{"openid"})

	status, body, _ := p.bcAuthorizeForm(t, url.Values{
		"login_hint":    {cibaKnownLoginHint},
		"id_token_hint": {cibaKnownLoginHint},
		"scope":         {"openid"},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", status, body)
	}
	expectCIBAError(t, body, "invalid_request")
}

// TestScenario_CIBA_034_BackchannelRejectsRequestParamWithoutJAR pins
// the complement of CIBA-023: with JAR enabled but no FAPI-CIBA
// profile active, /bc-authorize accepts plain form requests that omit
// a "request" parameter. The signed-request channel is opt-in for
// vanilla deployments — only FAPI-CIBA mandates the signed shape.
//
// Spec: CIBA Core §7.1.
func TestScenario_CIBA_034_BackchannelRejectsRequestParamWithoutJAR(t *testing.T) {
	t.Parallel()
	p := newCIBAProvider(t, []string{"openid"}, op.WithFeature(feature.JAR))

	status, body, _ := p.bcAuthorizeForm(t, url.Values{
		"login_hint": {cibaKnownLoginHint},
		"scope":      {"openid"},
	})
	if status != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%v", status, body)
	}
	if id, _ := body["auth_req_id"].(string); id == "" {
		t.Errorf("auth_req_id missing: %v", body)
	}
}

// TestScenario_CIBA_035_BackchannelRejectsRequestURIWithJAR is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_035_BackchannelRejectsRequestURIWithJAR(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-035 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_036_BackchannelRejectsRegistrationWithJAR is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_036_BackchannelRejectsRegistrationWithJAR(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-036 (see catalog out_of_scope_reason)")
}

// ---------------------------------------------------------------------
// /bc-authorize — FAPI-CIBA signed Request Object (CIBA-037..040)
// ---------------------------------------------------------------------

// TestScenario_CIBA_037_BackchannelRequiresSignedRequestObject pins the
// FAPI-CIBA mandate that every /bc-authorize POST be a signed
// authentication request. Without a "request" parameter, the handler
// returns 400 invalid_request "request object is required by the
// active profile". Retrying with a valid signed Request Object yields
// 200 OK.
//
// Spec: CIBA Core §7.1.1, FAPI-CIBA §5.2.2.
func TestScenario_CIBA_037_BackchannelRequiresSignedRequestObject(t *testing.T) {
	t.Parallel()
	f := newCIBAFAPIFixture(t)

	// First call: no "request" parameter — must reject.
	status, body := f.bcAuthorizeFAPIForm(t, url.Values{
		"login_hint": {cibaKnownLoginHint},
		"scope":      {"openid"},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", status, body)
	}
	expectCIBAError(t, body, "invalid_request")

	// Retry with a valid signed Request Object.
	signed := f.signES256(t, f.happyClaims())
	status, body = f.bcAuthorizeFAPIForm(t, url.Values{
		"request": {signed},
	})
	if status != http.StatusOK {
		t.Fatalf("retry status=%d want 200 body=%v", status, body)
	}
	if id, _ := body["auth_req_id"].(string); id == "" {
		t.Errorf("auth_req_id missing: %v", body)
	}
}

// TestScenario_CIBA_038_RequestObjectRequiresExpClaim pins the FAPI-
// CIBA exp-claim mandate: a signed Request Object missing exp is
// rejected with 400 invalid_request. The JAR verifier flags the
// absence via ErrExpired; the cibaendpoint handler collapses every
// JAR sentinel onto invalid_request because CIBA Core §13's closed
// error list does not name invalid_request_object.
//
// Spec: CIBA Core §7.1.1, §13, RFC 9101 §10.8.
func TestScenario_CIBA_038_RequestObjectRequiresExpClaim(t *testing.T) {
	t.Parallel()
	f := newCIBAFAPIFixture(t)

	claims := f.happyClaims()
	delete(claims, "exp")
	signed := f.signES256(t, claims)

	status, body := f.bcAuthorizeFAPIForm(t, url.Values{"request": {signed}})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", status, body)
	}
	expectCIBAError(t, body, "invalid_request")
}

// TestScenario_CIBA_039_RequestObjectRequiresNbfClaim pins the FAPI-
// CIBA nbf-claim mandate: a signed Request Object missing nbf is
// rejected with 400 invalid_request. The JAR verifier flips
// RequireNbf=true when any FAPI profile is active per FAPI 2.0
// Message Signing §5.6 (FAPI-CIBA inherits the same rule); the
// cibaendpoint handler collapses every JAR sentinel onto
// invalid_request per CIBA Core §13.
//
// Spec: CIBA Core §7.1.1, §13, FAPI-CIBA §5.2.2.
func TestScenario_CIBA_039_RequestObjectRequiresNbfClaim(t *testing.T) {
	t.Parallel()
	f := newCIBAFAPIFixture(t)

	claims := f.happyClaims()
	delete(claims, "nbf")
	signed := f.signES256(t, claims)

	status, body := f.bcAuthorizeFAPIForm(t, url.Values{"request": {signed}})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", status, body)
	}
	expectCIBAError(t, body, "invalid_request")
}

// TestScenario_CIBA_040_RequestObjectRequiresJtiClaim pins the FAPI-
// CIBA jti-claim mandate: a signed Request Object missing jti is
// rejected with 400 invalid_request. FAPI-CIBA §5.2.2 promotes jti
// from OPTIONAL (RFC 9101 §6.1 / FAPI 2.0 Security Profile baseline)
// to MUST on the backchannel-authentication request object; the JAR
// verifier flips AllowMissingJTI=false under profile.FAPICIBA, and
// the cibaendpoint handler collapses every JAR sentinel onto
// invalid_request per CIBA Core §13.
//
// Spec: FAPI-CIBA §5.2.2; CIBA Core §7.1.1, §13; RFC 9101 §10.8.
func TestScenario_CIBA_040_RequestObjectRequiresJtiClaim(t *testing.T) {
	t.Parallel()
	f := newCIBAFAPIFixture(t)

	claims := f.happyClaims()
	delete(claims, "jti")
	signed := f.signES256(t, claims)

	status, body := f.bcAuthorizeFAPIForm(t, url.Values{"request": {signed}})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", status, body)
	}
	expectCIBAError(t, body, "invalid_request")
}

// TestScenario_CIBA_041_RequestObjectRequiresIatClaim is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_041_RequestObjectRequiresIatClaim(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-041 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_042_BackchannelRejectsEncryptedRequestObject is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_042_BackchannelRejectsEncryptedRequestObject(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-042 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_043_BackchannelRejectsDuplicateSingleValuedParams
// pins the RFC 6749 §3.2 "MUST NOT include more than once" rule for
// the CIBA Core 1.0 §7.1 single-valued parameters. /authorize and
// /token already enforce this at parse time; the row pins the same
// guarantee for /bc-authorize so a request that doubles, say,
// login_hint cannot silently pick one. The RFC 8707 §2 resource
// indicator stays multi-valued and the table omits it; the unit
// suite under internal/cibaendpoint additionally pins that sibling
// invariant.
//
// Spec: RFC 6749 §3.2, CIBA Core §7.1.
func TestScenario_CIBA_043_BackchannelRejectsDuplicateSingleValuedParams(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		param string
		other string
	}{
		{name: "login_hint", param: "login_hint", other: "bob"},
		{name: "binding_message", param: "binding_message", other: "stop"},
		{name: "acr_values", param: "acr_values", other: "urn:mace:incommon:iap:silver"},
		{name: "requested_expiry", param: "requested_expiry", other: "120"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := newCIBAProvider(t, []string{"openid", "profile"})
			form := url.Values{}
			form.Set("scope", "openid")
			if tc.param != "login_hint" {
				form.Set("login_hint", cibaKnownLoginHint)
			}
			form.Add(tc.param, "first")
			form.Add(tc.param, tc.other)
			status, body, _ := p.bcAuthorizeForm(t, form)
			if status != http.StatusBadRequest {
				t.Fatalf("status=%d want 400 body=%v", status, body)
			}
			expectCIBAError(t, body, "invalid_request")
		})
	}
}

// TestScenario_CIBA_044_FAPICIBARejectsRequestedExpiryAboveTenMinutes
// pins the FAPI-CIBA-ID1 §5 / FAPI 2.0 §3.1.9 ten-minute lifetime cap
// at /bc-authorize. Under the FAPI-CIBA profile, requested_expiry
// above 600s MUST yield 400 invalid_request rather than being clamped
// silently; the cap is operator-mandated under the profile and a
// silent clamp would hide the deviation from the requesting client.
// Boundary cases: requested_expiry=600 succeeds, requested_expiry=601
// fails. Vanilla CIBA Core deployments retain the clamp behaviour;
// the unit suite under internal/cibaendpoint additionally pins the
// vanilla branch.
//
// Spec: FAPI-CIBA-ID1 §5, FAPI 2.0 §3.1.9, CIBA Core §7.1.
func TestScenario_CIBA_044_FAPICIBARejectsRequestedExpiryAboveTenMinutes(t *testing.T) {
	t.Parallel()
	f := newCIBAFAPIFixture(t)

	// requested_expiry=601 — must reject.
	overSpec := f.happyClaims()
	overSpec["requested_expiry"] = int64(601)
	signed := f.signES256(t, overSpec)
	status, body := f.bcAuthorizeFAPIForm(t, url.Values{"request": {signed}})
	if status != http.StatusBadRequest {
		t.Fatalf("over-spec status=%d want 400 body=%v", status, body)
	}
	expectCIBAError(t, body, "invalid_request")

	// requested_expiry=600 — boundary, must succeed.
	atCap := f.happyClaims()
	atCap["requested_expiry"] = int64(600)
	signed = f.signES256(t, atCap)
	status, body = f.bcAuthorizeFAPIForm(t, url.Values{"request": {signed}})
	if status != http.StatusOK {
		t.Fatalf("boundary status=%d want 200 body=%v", status, body)
	}
	got, ok := body["expires_in"].(float64)
	if !ok || int(got) != 600 {
		t.Errorf("expires_in=%v want 600", body["expires_in"])
	}
}

// TestScenario_CIBA_045_BackchannelRejectsUnadvertisedACRValue pins
// the OIDC Core §3.1.2.1 + CIBA Core §7.1 acr_values gate. With the
// OP advertising acr_values_supported via op.WithACRValuesSupported,
// any client-requested acr_values value outside that list MUST be
// rejected with 400 invalid_request — silently accepting it would
// let the client drive the issued id_token's acr claim to an
// arbitrary string the operator never enrolled. The positive arm
// confirms a value present in the advertised list still succeeds.
//
// Spec: OIDC Core §3.1.2.1, CIBA Core §7.1.
func TestScenario_CIBA_045_BackchannelRejectsUnadvertisedACRValue(t *testing.T) {
	t.Parallel()
	const supportedACR = "urn:mace:incommon:iap:bronze"
	p := newCIBAProvider(t, []string{"openid"},
		op.WithACRValuesSupported(supportedACR))

	// Negative: an unsupported value is rejected.
	status, body, _ := p.bcAuthorizeForm(t, url.Values{
		"login_hint": {cibaKnownLoginHint},
		"scope":      {"openid"},
		"acr_values": {"urn:not-supported"},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("unsupported status=%d want 400 body=%v", status, body)
	}
	expectCIBAError(t, body, "invalid_request")

	// Positive: the advertised value is accepted.
	status, body, _ = p.bcAuthorizeForm(t, url.Values{
		"login_hint": {cibaKnownLoginHint},
		"scope":      {"openid"},
		"acr_values": {supportedACR},
	})
	if status != http.StatusOK {
		t.Fatalf("supported status=%d want 200 body=%v", status, body)
	}
	authReqID, _ := body["auth_req_id"].(string)
	if authReqID == "" {
		t.Fatalf("auth_req_id missing: %v", body)
	}
	rec := p.findCIBARecord(t, authReqID)
	if len(rec.ACRValues) != 1 || rec.ACRValues[0] != supportedACR {
		t.Errorf("persisted ACRValues=%v want [%s]", rec.ACRValues, supportedACR)
	}
}

// TestScenario_CIBA_046_BackchannelRejectsUserCodeWhenUnsupported
// pins the discovery-consistency gate for
// backchannel_user_code_parameter_supported. The library advertises
// the parameter as unsupported in v1.0 (the option to flip the
// flag is reserved for a future release); CIBA Core §7.1 requires
// the client to refrain from sending parameters the OP has not
// advertised, so any non-empty user_code MUST surface as 400
// invalid_request with the description "user_code parameter is not
// supported". The positive arm confirms an absent user_code still
// succeeds.
//
// Spec: CIBA Core §7.1.
func TestScenario_CIBA_046_BackchannelRejectsUserCodeWhenUnsupported(t *testing.T) {
	t.Parallel()
	p := newCIBAProvider(t, []string{"openid"})

	// Negative: a non-empty user_code is rejected.
	status, body, _ := p.bcAuthorizeForm(t, url.Values{
		"login_hint": {cibaKnownLoginHint},
		"scope":      {"openid"},
		"user_code":  {"12345678"},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", status, body)
	}
	expectCIBAError(t, body, "invalid_request")

	// Positive: an absent user_code still succeeds.
	status, body, _ = p.bcAuthorizeForm(t, url.Values{
		"login_hint": {cibaKnownLoginHint},
		"scope":      {"openid"},
	})
	if status != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%v", status, body)
	}
	if id, _ := body["auth_req_id"].(string); id == "" {
		t.Errorf("auth_req_id missing: %v", body)
	}
}

// TestScenario_CIBA_047_BackchannelRejectsUnregisteredResource pins
// the audience-escalation gate at /bc-authorize: a request whose
// resource is a syntactically valid absolute URI but does not
// appear in the client's Resources allowlist MUST be rejected with
// 400 invalid_target.
//
// Spec: RFC 8707 §2, CIBA Core §7.1.
func TestScenario_CIBA_047_BackchannelRejectsUnregisteredResource(t *testing.T) {
	t.Parallel()
	p := newCIBAProviderWithResources(t,
		[]string{"openid"},
		[]string{"https://api-allowed.example"}, nil)

	status, body, _ := p.bcAuthorizeForm(t, url.Values{
		"login_hint": {cibaKnownLoginHint},
		"scope":      {"openid"},
		"resource":   {"https://api-other.example/"},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", status, body)
	}
	expectCIBAError(t, body, "invalid_target")
}

// TestScenario_CIBA_048_BackchannelRejectsMultiResource pins the
// single-audience invariant: even when both values are individually
// in the client's allowlist, a request carrying more than one
// resource= entry MUST be rejected with 400 invalid_target rather
// than silently truncated to the first value at issuance.
//
// Spec: RFC 8707 §2, CIBA Core §7.1.
func TestScenario_CIBA_048_BackchannelRejectsMultiResource(t *testing.T) {
	t.Parallel()
	p := newCIBAProviderWithResources(t,
		[]string{"openid"},
		[]string{"https://api-a.example", "https://api-b.example"}, nil)

	form := url.Values{}
	form.Set("login_hint", cibaKnownLoginHint)
	form.Set("scope", "openid")
	form.Add("resource", "https://api-a.example/")
	form.Add("resource", "https://api-b.example/")
	status, body, _ := p.bcAuthorizeForm(t, form)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", status, body)
	}
	expectCIBAError(t, body, "invalid_target")
}

// TestScenario_CIBA_049_IDTokenStampsACRWithoutAMR marks where the
// scenario-level acr/amr test would go. Driving a redemption end to end
// needs an approve hook the public surface does not expose, so the row
// names its own coverage in `covered_by` and the gate resolves that
// name. The prose that used to sit here named a test that had since
// been renamed, and nothing noticed.
//
// Spec: OIDC Core §2, CIBA Core §7.1.
func TestScenario_CIBA_049_IDTokenStampsACRWithoutAMR(t *testing.T) {
	t.Parallel()
	t.Skip("covered outside the suite; see the ciba catalog row's covered_by")
}

// Compile-time guard: ensure the OOS sentinel sentinel is reachable
// from this package even when no active row exercises it. This catches
// a future rename of op.ErrUnknownCIBAUser at build time rather than
// at the next test run.
var _ = errors.Is(op.ErrUnknownCIBAUser, op.ErrUnknownCIBAUser)
