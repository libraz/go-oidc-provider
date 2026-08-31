package scenarios_test

// Catalog: test/scenarios/catalog/mtls_certificate_binding.yaml (MTLS-NNN)
// Spec:
//   - RFC 8705 — OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens
//   - RFC 7662 — OAuth 2.0 Token Introspection
//   - RFC 6749 — OAuth 2.0 Authorization Framework
//   - RFC 8628 — Device Authorization Grant
//   - OpenID CIBA Core 1.0

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
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
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

// mtlsCert is a self-signed leaf with deterministic NotBefore/NotAfter
// pinned to literal timestamps so the cert bytes are independent of the
// wall clock. ECDSA P-256 mirrors the rest of the project's posture.
func mtlsCert(tb testing.TB) *x509.Certificate {
	tb.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rp.testkit.invalid"},
		NotBefore:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2125, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		tb.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

// mtlsThumbprint reproduces the RFC 8705 §3.1 algorithm
// (base64url-no-pad of SHA-256 over the DER bytes) without importing
// internal/mtls. The scenario tests verify the wire shape, so
// recomputing it from scratch is the right level of decoupling: a
// regression in the OP's internal helper would still surface here.
func mtlsThumbprint(cert *x509.Certificate) string {
	if cert == nil || len(cert.Raw) == 0 {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// mtlsServeWithCert dispatches a request through the [op.Provider]
// handler with a fabricated TLS handshake state. The testkit's
// [httptest.Server] does not configure client-cert handshake, so
// scenarios that need to thread a client cert reach into the handler
// directly via [op.Provider.ServeHTTP]. This is a public surface — the
// provider is an [http.Handler] — so the helper imports nothing from
// internal/.
func mtlsServeWithCert(
	tb testing.TB,
	prov *testkit.Provider,
	method, urlStr string,
	form url.Values,
	cert *x509.Certificate,
	mutate func(*http.Request),
) *http.Response {
	tb.Helper()
	var body io.Reader = http.NoBody
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(context.Background(), method, urlStr, body)
	if err != nil {
		tb.Fatalf("NewRequest: %v", err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cert != nil {
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	}
	if mutate != nil {
		mutate(req)
	}
	rec := httptest.NewRecorder()
	prov.OP.ServeHTTP(rec, req)
	return rec.Result()
}

// mtlsDecodeJSON parses a response body as a JSON object; an empty
// body decodes to an empty map.
func mtlsDecodeJSON(tb testing.TB, resp *http.Response) map[string]any {
	tb.Helper()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		tb.Fatalf("read body: %v", err)
	}
	out := map[string]any{}
	if len(raw) == 0 {
		return out
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		tb.Fatalf("decode body %q: %v", string(raw), err)
	}
	return out
}

// mtlsAccessTokenCnf parses the access-token JWT and returns the cnf
// claim as a string-keyed map. Verification keys are not consulted —
// the test only inspects payload claims, so an unsigned parse is
// enough.
func mtlsAccessTokenCnf(tb testing.TB, raw string) map[string]string {
	tb.Helper()
	tok, err := jwt.ParseSigned(raw, []josev4.SignatureAlgorithm{josev4.ES256})
	if err != nil {
		tb.Fatalf("ParseSigned access token: %v", err)
	}
	var claims struct {
		Cnf map[string]string `json:"cnf"`
	}
	if err := tok.UnsafeClaimsWithoutVerification(&claims); err != nil {
		tb.Fatalf("UnsafeClaimsWithoutVerification: %v", err)
	}
	return claims.Cnf
}

// mtlsConfidentialFixture seeds an MTLS-enabled provider with a
// confidential client suitable for HTTP Basic at /token. The fixture
// also seeds a user record so /authorize and /userinfo can resolve
// claims.
type mtlsConfidentialFixture struct {
	tk     *testkit.Provider
	client *store.Client
	secret string
}

func newMTLSConfidentialFixture(tb testing.TB, opts ...op.Option) *mtlsConfidentialFixture {
	tb.Helper()
	all := append([]op.Option{
		op.WithFeature(feature.MTLS),
		scenariokit.WithClientCredentials(),
	}, opts...)
	tk := testkit.NewProvider(tb, testkit.WithOptions(all...))
	const secret = "rp-mtls-conf-secret" //nolint:gosec // not a credential — opaque test fixture secret.
	hash, err := op.HashClientSecret(secret)
	if err != nil {
		tb.Fatalf("HashClientSecret: %v", err)
	}
	client := tk.RegisterClient(tb, testkit.ClientFixture{
		ID:                      "rp-mtls-conf",
		SecretHash:              hash,
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		Scopes:                  []string{"openid", "profile", "email", "offline_access"},
		GrantTypes:              []string{"authorization_code", "refresh_token", "client_credentials"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	tk.Store.PutUser(context.Background(), &store.User{
		Subject: scenariokit.DefaultSubject,
		Claims: map[string]any{
			"email":          "alice@example.com",
			"email_verified": true,
		},
	})
	return &mtlsConfidentialFixture{tk: tk, client: client, secret: secret}
}

// mtlsPublicFixture seeds an MTLS-enabled provider with a public
// (auth method none) client. Public clients drive the
// sender-constrained refresh-token paths because the rotation policy
// for confidential clients differs across binding mechanisms.
type mtlsPublicFixture struct {
	tk     *testkit.Provider
	client *store.Client
}

func newMTLSPublicFixture(tb testing.TB, opts ...op.Option) *mtlsPublicFixture {
	tb.Helper()
	all := append([]op.Option{op.WithFeature(feature.MTLS)}, opts...)
	tk := testkit.NewProvider(tb, testkit.WithOptions(all...))
	client := tk.RegisterClient(tb, testkit.ClientFixture{
		ID:           "rp-mtls-public",
		PublicClient: true,
		RedirectURIs: []string{"https://rp.testkit.invalid/callback"},
		Scopes:       []string{"openid", "profile", "email", "offline_access"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
	})
	tk.Store.PutUser(context.Background(), &store.User{
		Subject: scenariokit.DefaultSubject,
		Claims: map[string]any{
			"email":          "alice@example.com",
			"email_verified": true,
		},
	})
	return &mtlsPublicFixture{tk: tk, client: client}
}

// mtlsRunCodeFlow drives /authorize → /interaction → callback for the
// fixture's client and returns the issued authorization code.
func mtlsRunCodeFlow(t *testing.T, tk *testkit.Provider, client *store.Client) (code string, pkce scenariokit.PKCEPair) {
	t.Helper()
	pkce = scenariokit.NewPKCEPair("")
	res := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    client.ID,
		RedirectURI: client.RedirectURIs[0],
		Scope:       "openid email offline_access",
		PKCE:        pkce,
	})
	if res.Error != "" {
		t.Fatalf("authorize error=%s desc=%s", res.Error, res.ErrorDesc)
	}
	if res.Code == "" {
		t.Fatalf("authorize did not return a code: %+v", res)
	}
	return res.Code, pkce
}

// mtlsTokenURL is the absolute /token URL the OP advertises in its
// discovery metadata. The helper builds it from the fixture's issuer so
// scenarios that bypass the [httptest.Server] (and dispatch directly
// through [op.Provider.ServeHTTP]) still hit the routed endpoint.
func mtlsTokenURL(tk *testkit.Provider) string {
	return tk.Issuer + "/oidc/token"
}

func mtlsUserInfoURL(tk *testkit.Provider) string {
	return tk.Issuer + "/oidc/userinfo"
}

// TestScenario_MTLS_001_DiscoveryAdvertisesCertBoundFlag pins the
// RFC 8705 §3.3 discovery surface: when [feature.MTLS] is enabled the
// /.well-known/openid-configuration document carries
// tls_client_certificate_bound_access_tokens=true. The discovery
// builder is the public-facing contract RP libraries key off when
// deciding whether to thread a client cert through the resource-
// server hop.
//
// The same field is checked from the client_auth angle by CA-DISC-07
// (focus there: discovery advertises the auth-method allow-list);
// this binding focuses on the cert-bound flag itself.
//
// Spec: RFC 8705 §3.3 / OpenID Connect Discovery 1.0 §3.
func TestScenario_MTLS_001_DiscoveryAdvertisesCertBoundFlag(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithFeature(feature.MTLS)))
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		tk.Server.URL+"/.well-known/openid-configuration", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery status=%d want 200", resp.StatusCode)
	}
	doc := mtlsDecodeJSON(t, resp)
	got, ok := doc["tls_client_certificate_bound_access_tokens"].(bool)
	if !ok {
		t.Fatalf("tls_client_certificate_bound_access_tokens missing or not a bool (doc=%v)", doc["tls_client_certificate_bound_access_tokens"])
	}
	if !got {
		t.Errorf("tls_client_certificate_bound_access_tokens=false want true under feature.MTLS")
	}
}

// TestScenario_MTLS_002_AccessTokenRejectsDualBinding is OOS: the
// catalog claim that "setting both x5t#S256 and jkt thumbprints on a
// single AT MUST fail with a construction error" describes a
// upstream-style policy that v1.0 deliberately does not implement. The
// token endpoint instead prefers DPoP over mTLS at issuance (DPoP
// wins; the access token then carries cnf.jkt and skips the
// cert-thumbprint lookup), so a single token never carries both
// confirmation members in the first place. The userinfo path still
// enforces both proofs when a token does carry both members
// (defensive against forged tokens), which is the contract a v1.0
// embedder relies on.
func TestScenario_MTLS_002_AccessTokenRejectsDualBinding(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: MTLS-002 (see catalog out_of_scope_reason)")
}

// TestScenario_MTLS_003_UserinfoNoCertRejected pins the cnf.x5t#S256
// enforcement at /userinfo: a cert-bound access token presented as
// Bearer with no client cert MUST be rejected with 401. The OP
// surfaces invalid_token via the WWW-Authenticate challenge.
func TestScenario_MTLS_003_UserinfoNoCertRejected(t *testing.T) {
	t.Parallel()

	f := newMTLSConfidentialFixture(t)
	cert := mtlsCert(t)
	at := mtlsIssueAuthCodeAccessToken(t, f, cert)

	// Bearer at /userinfo with NO client cert: must 401.
	resp := mtlsServeWithCert(t, f.tk, http.MethodGet, mtlsUserInfoURL(f.tk), nil, nil, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+at)
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/userinfo no-cert status=%d want 401", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); !strings.Contains(got, "invalid_token") {
		t.Errorf("WWW-Authenticate=%q want to contain invalid_token", got)
	}
}

// TestScenario_MTLS_004_UserinfoMalformedCertRejected drives the
// proxy-header path with a malformed (non-PEM) value. The OP returns
// 401 invalid_token without leaking the parse-cause to the client.
//
// The scenario configures [op.WithMTLSProxy] so the OP accepts a
// header from the testkit's loopback prefix (httptest.Server binds to
// 127.0.0.1), then drives a request through the live HTTPS server
// without a TLS handshake cert so the malformed-header path is the
// only way the OP can resolve a thumbprint.
func TestScenario_MTLS_004_UserinfoMalformedCertRejected(t *testing.T) {
	t.Parallel()

	const headerName = "X-Client-Cert"
	f := newMTLSConfidentialFixture(t,
		op.WithMTLSProxy(headerName, []string{"127.0.0.1/32", "::1/128"}),
	)
	cert := mtlsCert(t)
	at := mtlsIssueAuthCodeAccessToken(t, f, cert)

	// Drive over the live HTTPS server (so RemoteAddr is 127.0.0.1)
	// with a malformed header value: garbage that contains no PEM
	// block. The handler MUST surface 401 invalid_token rather than
	// the malformed-cert detail.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, f.tk.Server.URL+"/oidc/userinfo", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+at)
	req.Header.Set(headerName, "this-is-not-a-pem-block")
	resp, err := f.tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/userinfo malformed-cert status=%d want 401", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); !strings.Contains(got, "invalid_token") {
		t.Errorf("WWW-Authenticate=%q want to contain invalid_token", got)
	}
}

// TestScenario_MTLS_005_UserinfoSuccessWithBindingCert drives the
// happy path: a cert-bound access token presented at /userinfo with
// the matching client cert is accepted (200) and the response body
// carries the requested claims. This is the canonical RFC 8705 §3.1
// proof-of-possession success case.
func TestScenario_MTLS_005_UserinfoSuccessWithBindingCert(t *testing.T) {
	t.Parallel()

	f := newMTLSConfidentialFixture(t)
	cert := mtlsCert(t)
	at := mtlsIssueAuthCodeAccessToken(t, f, cert)

	resp := mtlsServeWithCert(t, f.tk, http.MethodGet, mtlsUserInfoURL(f.tk), nil, cert, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+at)
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("/userinfo status=%d body=%s", resp.StatusCode, dump)
	}
	body := mtlsDecodeJSON(t, resp)
	if got, _ := body["sub"].(string); got != scenariokit.DefaultSubject {
		t.Errorf("sub=%q want %q", got, scenariokit.DefaultSubject)
	}
}

// TestScenario_MTLS_006_IntrospectionSurfacesCnfX5T pins the RFC 8705
// §3.2 / RFC 7662 introspection contract for cert-bound access
// tokens: a successful /introspect response carries the cnf.x5t#S256
// thumbprint copied verbatim from the JWT AT, alongside
// token_type=Bearer (RFC 9449 §6.1 / RFC 8705 §3.1 keep the bearer
// label even when a sender-constraint binding is layered on).
//
// The fixture is the confidential MTLS fixture with Introspect
// additionally enabled; the test issues a cert-bound AT via the
// authorization_code grant and then introspects it via HTTP Basic.
//
// Spec: RFC 8705 §3.2 / RFC 7662 §2.2.
func TestScenario_MTLS_006_IntrospectionSurfacesCnfX5T(t *testing.T) {
	t.Parallel()

	f := newMTLSConfidentialFixture(t, op.WithFeature(feature.Introspect))
	cert := mtlsCert(t)
	at := mtlsIssueAuthCodeAccessToken(t, f, cert)
	wantThumb := mtlsThumbprint(cert)

	form := url.Values{"token": {at}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		f.tk.Server.URL+"/oidc/introspect", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest /introspect: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(f.client.ID, f.secret)
	resp, err := f.tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("Do /introspect: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("/introspect status=%d body=%s", resp.StatusCode, string(body))
	}
	body := mtlsDecodeJSON(t, resp)
	if active, _ := body["active"].(bool); !active {
		t.Fatalf("introspect active=false want true (body=%v)", body)
	}
	if got, _ := body["token_type"].(string); got != "Bearer" {
		t.Errorf("token_type=%q want Bearer (RFC 8705 §3.1 keeps bearer label even when cert-bound)", got)
	}
	cnf, _ := body["cnf"].(map[string]any)
	if cnf == nil {
		t.Fatalf("introspect response missing cnf (body=%v)", body)
	}
	if got, _ := cnf["x5t#S256"].(string); got != wantThumb {
		t.Errorf("cnf.x5t#S256=%q want %q", got, wantThumb)
	}
	if _, hasJKT := cnf["jkt"]; hasJKT {
		t.Errorf("cnf must not carry jkt for an mTLS-only bound token (cnf=%v)", cnf)
	}
}

// TestScenario_MTLS_007_ThumbprintAlgorithm pins the wire shape of
// x5t#S256 to RFC 8705 §3.1 base64url-no-pad of SHA-256 over the
// DER bytes. Tested by exchanging a code with a known cert and
// checking the cnf claim equals the locally re-computed hash.
func TestScenario_MTLS_007_ThumbprintAlgorithm(t *testing.T) {
	t.Parallel()

	f := newMTLSConfidentialFixture(t)
	cert := mtlsCert(t)
	at := mtlsIssueAuthCodeAccessToken(t, f, cert)

	cnf := mtlsAccessTokenCnf(t, at)
	got := cnf["x5t#S256"]
	want := mtlsThumbprint(cert)
	if got != want {
		t.Errorf("cnf.x5t#S256=%q want %q", got, want)
	}
	// Validate the alphabet is base64url with no padding.
	if want == "" {
		t.Fatal("re-computed thumbprint is empty")
	}
	for _, c := range want {
		switch {
		case c >= 'A' && c <= 'Z',
			c >= 'a' && c <= 'z',
			c >= '0' && c <= '9',
			c == '-', c == '_':
		default:
			t.Errorf("thumbprint char %q outside base64url-no-pad alphabet", c)
		}
	}
}

// TestScenario_MTLS_008_DeviceCodeBindingConfidential drives the
// device-code family end to end for a confidential client: the cert
// presented at /device_authorization is committed onto the
// device-authorization record, the poll at /token presents the same
// cert, and the issued access token carries cnf.x5t#S256. The refresh
// token inherits the binding as well — v1.0 propagates the certificate
// binding onto the refresh record for confidential and public clients
// alike, so a stolen refresh token is unusable without the certificate.
//
// Spec: RFC 8705 §3 / RFC 8628 §3.4.
func TestScenario_MTLS_008_DeviceCodeBindingConfidential(t *testing.T) {
	t.Parallel()

	f := newMTLSAsyncFixture(t, false, op.WithDeviceCodeGrant(),
		devURNDeviceCode, "rp-mtls-device-conf")
	body := f.redeemDeviceCode(t, f.cert)
	f.assertBoundTokens(t, body)
}

// TestScenario_MTLS_009_DeviceCodeRequiresMTLS pins the downgrade
// refusal on the device-code family: a record that committed to a
// certificate at /device_authorization may not be redeemed by a poll
// that presents none. Minting an unbound token from a bound record
// would hand a device_code thief a token the legitimate device's
// certificate was supposed to gate, so the OP answers 400
// invalid_grant and issues nothing.
//
// Spec: RFC 8705 §3 / RFC 8628 §3.5.
func TestScenario_MTLS_009_DeviceCodeRequiresMTLS(t *testing.T) {
	t.Parallel()

	f := newMTLSAsyncFixture(t, false, op.WithDeviceCodeGrant(),
		devURNDeviceCode, "rp-mtls-device-nocert")
	status, body := f.redeemDeviceCodeStatus(t, nil)
	assertMTLSGrantRejected(t, status, body)
}

// TestScenario_MTLS_010_DeviceCodeBindingPublic runs the device-code
// binding for a public client (auth method none). The client has no
// secret, so the certificate is the only thing standing between a
// leaked device_code and a usable token pair: both the access token
// and the persisted refresh token MUST carry the thumbprint.
//
// Spec: RFC 8705 §3 / RFC 8628 §3.4.
func TestScenario_MTLS_010_DeviceCodeBindingPublic(t *testing.T) {
	t.Parallel()

	f := newMTLSAsyncFixture(t, true, op.WithDeviceCodeGrant(),
		devURNDeviceCode, "rp-mtls-device-public")
	body := f.redeemDeviceCode(t, f.cert)
	f.assertBoundTokens(t, body)
}

// TestScenario_MTLS_011_CIBABindingConfidential is the CIBA analogue of
// MTLS-008: the certificate presented at /bc-authorize is committed
// onto the CIBA record, the poll at /token presents the same
// certificate, and the issued access token plus refresh token carry
// the x5t#S256 binding.
//
// Spec: RFC 8705 §3 / OIDC CIBA Core 1.0 §7.1 / §11.
func TestScenario_MTLS_011_CIBABindingConfidential(t *testing.T) {
	t.Parallel()

	f := newMTLSAsyncFixture(t, false,
		op.WithCIBA(op.WithCIBAHintResolver(cibaHintResolver{})),
		cibaURNGrant, "rp-mtls-ciba-conf")
	body := f.redeemCIBA(t, f.cert)
	f.assertBoundTokens(t, body)
}

// TestScenario_MTLS_012_CIBARequiresMTLS is the CIBA analogue of
// MTLS-009: a CIBA record that committed to a certificate refuses a
// certificate-less poll with 400 invalid_grant rather than minting an
// unbound token.
//
// Spec: RFC 8705 §3 / OIDC CIBA Core 1.0 §11.
func TestScenario_MTLS_012_CIBARequiresMTLS(t *testing.T) {
	t.Parallel()

	f := newMTLSAsyncFixture(t, false,
		op.WithCIBA(op.WithCIBAHintResolver(cibaHintResolver{})),
		cibaURNGrant, "rp-mtls-ciba-nocert")
	status, body := f.redeemCIBAStatus(t, nil)
	assertMTLSGrantRejected(t, status, body)
}

// TestScenario_MTLS_013_CIBABindingPublic runs the CIBA binding for a
// public client. As in MTLS-010 the certificate is the only sender
// constraint available, so both issued credentials MUST carry it.
//
// Spec: RFC 8705 §3 / OIDC CIBA Core 1.0 §7.1 / §11.
func TestScenario_MTLS_013_CIBABindingPublic(t *testing.T) {
	t.Parallel()

	f := newMTLSAsyncFixture(t, true,
		op.WithCIBA(op.WithCIBAHintResolver(cibaHintResolver{})),
		cibaURNGrant, "rp-mtls-ciba-public")
	body := f.redeemCIBA(t, f.cert)
	f.assertBoundTokens(t, body)
}

// TestScenario_MTLS_014_AuthCodeBindingConfidential is OOS. The
// catalog assertion has two halves: (a) a confidential client's AT
// is bound by x5t#S256 when a cert is presented at /token, and (b)
// "the refresh token is NOT sender-constrained". Half (a) is the
// canonical RFC 8705 §3 happy path and is covered by MTLS-018 (the
// public-client variant exercises the same issuance path) and by
// MTLS-007 (which pins the thumbprint encoding); half (b) is a
// upstream-style policy that v1.0 deliberately rejects. The
// implementation propagates the cert binding onto the rotated
// refresh-token record for both confidential AND public clients
// (internal/tokenendpoint/authcode.go MTLSCertThumbprint:
// binding.MTLSThumbprint) — leaving the RT unbound would silently
// downgrade the chain on first refresh and is the less-secure
// posture. Re-binding when the OP narrows the policy in a future
// release is left as a follow-up; the v1.0 contract is "bind once,
// enforce always".
func TestScenario_MTLS_014_AuthCodeBindingConfidential(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: MTLS-014 (see catalog out_of_scope_reason)")
}

// TestScenario_MTLS_015_AuthCodeRequiresMTLS is OOS. The catalog
// asserts a per-client "cert-binding-required" policy: a client
// flagged as MTLS-required MUST have its authorization_code
// redemption rejected when no cert is presented. v1.0 binds
// opportunistically — RFC 8705 §3 is permissive — and does not ship a
// per-client policy knob to require certs. Embedders that need this
// posture compose it from FAPI 2.0 profile + WithMTLSProxy + their
// own gateway layer; the OP itself never rejects a cert-less
// request that is otherwise well-formed. Revisit when the OP grows
// a per-client mTLS-required policy surface.
func TestScenario_MTLS_015_AuthCodeRequiresMTLS(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: MTLS-015 (see catalog out_of_scope_reason)")
}

// TestScenario_MTLS_016_RefreshTokenBindingConfidential is OOS for
// the same reason as MTLS-014: the catalog claim that "the refresh
// token remains unbound" describes the upstream OP's loose-binding policy and
// not v1.0's posture. The implementation always inherits the cert
// binding onto the rotated RT record, regardless of the client's
// auth method. Whether this is the right policy is debated upstream
// (RFC 8705 §3 is silent on RT binding for confidential clients);
// the project chooses the safer posture and asserts on it through
// the public-client paths (MTLS-020/-021/-022).
func TestScenario_MTLS_016_RefreshTokenBindingConfidential(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: MTLS-016 (see catalog out_of_scope_reason)")
}

// TestScenario_MTLS_017_RefreshTokenRequiresMTLSConfidential pins
// the refresh-time enforcement: a confidential client whose RT is
// already mTLS-bound MUST present a matching cert on subsequent
// refreshes; omitting the cert yields 400 invalid_grant.
func TestScenario_MTLS_017_RefreshTokenRequiresMTLSConfidential(t *testing.T) {
	t.Parallel()

	f := newMTLSConfidentialFixture(t)
	cert := mtlsCert(t)

	// Drive an authorization_code exchange WITH the cert so the RT
	// inherits the binding, then refresh WITHOUT the cert.
	code, pkce := mtlsRunCodeFlow(t, f.tk, f.client)
	tokForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {f.client.RedirectURIs[0]},
		"code_verifier": {pkce.Verifier},
	}
	tokResp := mtlsServeWithCert(t, f.tk, http.MethodPost, mtlsTokenURL(f.tk), tokForm, cert, func(r *http.Request) {
		r.SetBasicAuth(f.client.ID, f.secret)
	})
	defer tokResp.Body.Close()
	if tokResp.StatusCode != http.StatusOK {
		t.Fatalf("/token status=%d want 200", tokResp.StatusCode)
	}
	body := mtlsDecodeJSON(t, tokResp)
	rt, _ := body["refresh_token"].(string)
	if rt == "" {
		t.Fatal("refresh_token missing from /token response")
	}

	// Refresh with NO client cert: must 400 invalid_grant.
	refForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rt},
	}
	refResp := mtlsServeWithCert(t, f.tk, http.MethodPost, mtlsTokenURL(f.tk), refForm, nil, func(r *http.Request) {
		r.SetBasicAuth(f.client.ID, f.secret)
	})
	defer refResp.Body.Close()
	if refResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("refresh no-cert status=%d want 400", refResp.StatusCode)
	}
	refBody := mtlsDecodeJSON(t, refResp)
	if got, _ := refBody["error"].(string); got != "invalid_grant" {
		t.Errorf("error=%q want invalid_grant", got)
	}
}

// TestScenario_MTLS_018_AuthCodeBindingPublic exercises the
// public-client (auth method none) authorization_code path: the
// issued AT carries cnf.x5t#S256 and the rotated RT inherits the
// thumbprint so subsequent refreshes are gated on the cert.
func TestScenario_MTLS_018_AuthCodeBindingPublic(t *testing.T) {
	t.Parallel()

	f := newMTLSPublicFixture(t)
	cert := mtlsCert(t)
	want := mtlsThumbprint(cert)

	code, pkce := mtlsRunCodeFlow(t, f.tk, f.client)
	tokForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {f.client.RedirectURIs[0]},
		"code_verifier": {pkce.Verifier},
		"client_id":     {f.client.ID},
	}
	resp := mtlsServeWithCert(t, f.tk, http.MethodPost, mtlsTokenURL(f.tk), tokForm, cert, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("/token status=%d body=%s", resp.StatusCode, dump)
	}
	body := mtlsDecodeJSON(t, resp)
	at, _ := body["access_token"].(string)
	rt, _ := body["refresh_token"].(string)
	if at == "" || rt == "" {
		t.Fatalf("missing tokens at=%q rt=%q", at, rt)
	}

	// AT cnf.x5t#S256 matches the cert's thumbprint.
	cnf := mtlsAccessTokenCnf(t, at)
	if got := cnf["x5t#S256"]; got != want {
		t.Errorf("AT cnf.x5t#S256=%q want %q", got, want)
	}
	if _, hasJKT := cnf["jkt"]; hasJKT {
		t.Errorf("AT cnf must not carry jkt for an mTLS-bound token")
	}

	// RT record carries the same thumbprint (sender-constrained).
	rec, err := f.tk.Store.RefreshTokens().Find(context.Background(), rt)
	if err != nil {
		t.Fatalf("RefreshTokens.Find: %v", err)
	}
	if rec.MTLSCertThumbprint != want {
		t.Errorf("RT MTLSCertThumbprint=%q want %q", rec.MTLSCertThumbprint, want)
	}
}

// TestScenario_MTLS_019_AuthCodeRequiresMTLSPublic is OOS for the
// same reason as MTLS-015: v1.0 has no per-client cert-binding-
// required policy. A public client without a cert on /token still
// receives a (bearer) access token, which is the
// opportunistic-binding posture RFC 8705 §3 prescribes.
func TestScenario_MTLS_019_AuthCodeRequiresMTLSPublic(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: MTLS-019 (see catalog out_of_scope_reason)")
}

// TestScenario_MTLS_020_RefreshTokenBindingPublic drives the
// public-client refresh: presenting the same cert rotates the RT
// while preserving the thumbprint binding on both the new AT and
// the new RT record.
func TestScenario_MTLS_020_RefreshTokenBindingPublic(t *testing.T) {
	t.Parallel()

	f := newMTLSPublicFixture(t)
	cert := mtlsCert(t)
	want := mtlsThumbprint(cert)

	code, pkce := mtlsRunCodeFlow(t, f.tk, f.client)
	tokForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {f.client.RedirectURIs[0]},
		"code_verifier": {pkce.Verifier},
		"client_id":     {f.client.ID},
	}
	tokResp := mtlsServeWithCert(t, f.tk, http.MethodPost, mtlsTokenURL(f.tk), tokForm, cert, nil)
	defer tokResp.Body.Close()
	if tokResp.StatusCode != http.StatusOK {
		t.Fatalf("/token status=%d want 200", tokResp.StatusCode)
	}
	body := mtlsDecodeJSON(t, tokResp)
	rt, _ := body["refresh_token"].(string)
	if rt == "" {
		t.Fatal("refresh_token missing")
	}

	// Refresh with the SAME cert: success, rotated RT remains bound.
	refForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rt},
		"client_id":     {f.client.ID},
	}
	refResp := mtlsServeWithCert(t, f.tk, http.MethodPost, mtlsTokenURL(f.tk), refForm, cert, nil)
	defer refResp.Body.Close()
	if refResp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(refResp.Body)
		t.Fatalf("refresh status=%d body=%s", refResp.StatusCode, dump)
	}
	refBody := mtlsDecodeJSON(t, refResp)
	rotated, _ := refBody["refresh_token"].(string)
	if rotated == "" || rotated == rt {
		t.Fatalf("RT did not rotate; rotated=%q (was %q)", rotated, rt)
	}
	newAT, _ := refBody["access_token"].(string)
	if newAT == "" {
		t.Fatal("rotated access_token missing")
	}
	cnf := mtlsAccessTokenCnf(t, newAT)
	if got := cnf["x5t#S256"]; got != want {
		t.Errorf("rotated AT cnf.x5t#S256=%q want %q", got, want)
	}
	rec, err := f.tk.Store.RefreshTokens().Find(context.Background(), rotated)
	if err != nil {
		t.Fatalf("rotated RefreshTokens.Find: %v", err)
	}
	if rec.MTLSCertThumbprint != want {
		t.Errorf("rotated RT MTLSCertThumbprint=%q want %q", rec.MTLSCertThumbprint, want)
	}
}

// TestScenario_MTLS_021_RefreshTokenRequiresMTLSPublic pins the
// no-cert refresh rejection for public clients: the bound RT MUST
// fail invalid_grant when no cert is presented.
func TestScenario_MTLS_021_RefreshTokenRequiresMTLSPublic(t *testing.T) {
	t.Parallel()

	f := newMTLSPublicFixture(t)
	cert := mtlsCert(t)

	code, pkce := mtlsRunCodeFlow(t, f.tk, f.client)
	tokForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {f.client.RedirectURIs[0]},
		"code_verifier": {pkce.Verifier},
		"client_id":     {f.client.ID},
	}
	tokResp := mtlsServeWithCert(t, f.tk, http.MethodPost, mtlsTokenURL(f.tk), tokForm, cert, nil)
	defer tokResp.Body.Close()
	body := mtlsDecodeJSON(t, tokResp)
	rt, _ := body["refresh_token"].(string)
	if rt == "" {
		t.Fatal("refresh_token missing")
	}

	// Refresh WITHOUT cert: 400 invalid_grant.
	refForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rt},
		"client_id":     {f.client.ID},
	}
	refResp := mtlsServeWithCert(t, f.tk, http.MethodPost, mtlsTokenURL(f.tk), refForm, nil, nil)
	defer refResp.Body.Close()
	if refResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("refresh no-cert status=%d want 400", refResp.StatusCode)
	}
	refBody := mtlsDecodeJSON(t, refResp)
	if got, _ := refBody["error"].(string); got != "invalid_grant" {
		t.Errorf("error=%q want invalid_grant", got)
	}
}

// TestScenario_MTLS_022_RefreshTokenCertMismatchPublic drives the
// thumbprint-mismatch rejection: presenting a different cert on the
// refresh path yields 400 invalid_grant. The mismatch is detected by
// comparing the bound thumbprint on the RT record against the
// re-computed thumbprint of the presented cert.
func TestScenario_MTLS_022_RefreshTokenCertMismatchPublic(t *testing.T) {
	t.Parallel()

	f := newMTLSPublicFixture(t)
	cert := mtlsCert(t)
	other := mtlsCert(t)

	code, pkce := mtlsRunCodeFlow(t, f.tk, f.client)
	tokForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {f.client.RedirectURIs[0]},
		"code_verifier": {pkce.Verifier},
		"client_id":     {f.client.ID},
	}
	tokResp := mtlsServeWithCert(t, f.tk, http.MethodPost, mtlsTokenURL(f.tk), tokForm, cert, nil)
	defer tokResp.Body.Close()
	body := mtlsDecodeJSON(t, tokResp)
	rt, _ := body["refresh_token"].(string)
	if rt == "" {
		t.Fatal("refresh_token missing")
	}

	// Refresh with a DIFFERENT cert: 400 invalid_grant.
	refForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rt},
		"client_id":     {f.client.ID},
	}
	refResp := mtlsServeWithCert(t, f.tk, http.MethodPost, mtlsTokenURL(f.tk), refForm, other, nil)
	defer refResp.Body.Close()
	if refResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("refresh wrong-cert status=%d want 400", refResp.StatusCode)
	}
	refBody := mtlsDecodeJSON(t, refResp)
	if got, _ := refBody["error"].(string); got != "invalid_grant" {
		t.Errorf("error=%q want invalid_grant", got)
	}
}

// TestScenario_MTLS_023_ClientCredentialsBinding pins the
// client_credentials grant: presenting a client cert binds the
// issued AT by x5t#S256 (RFC 8705 §3 / RFC 6749 §4.4). The grant
// uses the confidential fixture because client_credentials requires
// client authentication.
func TestScenario_MTLS_023_ClientCredentialsBinding(t *testing.T) {
	t.Parallel()

	f := newMTLSConfidentialFixture(t)
	cert := mtlsCert(t)
	want := mtlsThumbprint(cert)

	form := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"profile"},
	}
	resp := mtlsServeWithCert(t, f.tk, http.MethodPost, mtlsTokenURL(f.tk), form, cert, func(r *http.Request) {
		r.SetBasicAuth(f.client.ID, f.secret)
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("/token client_credentials status=%d body=%s", resp.StatusCode, dump)
	}
	body := mtlsDecodeJSON(t, resp)
	at, _ := body["access_token"].(string)
	if at == "" {
		t.Fatal("access_token missing")
	}
	cnf := mtlsAccessTokenCnf(t, at)
	if got := cnf["x5t#S256"]; got != want {
		t.Errorf("cnf.x5t#S256=%q want %q", got, want)
	}
	// client_credentials never issues a refresh token (RFC 6749 §4.4.3).
	if rt, _ := body["refresh_token"].(string); rt != "" {
		t.Errorf("refresh_token=%q want empty for client_credentials", rt)
	}
}

// TestScenario_MTLS_024_ClientCredentialsRequiresMTLS is OOS for the
// same reason as MTLS-015 / MTLS-019: v1.0 has no per-client
// cert-binding-required policy. client_credentials without a cert
// returns a (bearer) AT, which matches RFC 8705 §3's
// opportunistic-binding posture.
func TestScenario_MTLS_024_ClientCredentialsRequiresMTLS(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: MTLS-024 (see catalog out_of_scope_reason)")
}

// TestScenario_MTLS_025_GrantErrorResponseShape is OOS — see catalog out_of_scope_reason.
func TestScenario_MTLS_025_GrantErrorResponseShape(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: MTLS-025 (see catalog out_of_scope_reason)")
}

// mtlsAsyncAuthTime is the wall clock the asynchronous fixtures stamp
// onto an approved device-code / CIBA record. A literal keeps the
// issued id_token's auth_time claim independent of the machine clock;
// no row asserts on the value, it only has to be deterministic.
var mtlsAsyncAuthTime = time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

// mtlsAsyncFixture is the harness the device-code and CIBA binding
// scenarios share. Both families commit the sender-constraint binding
// at an initiation endpoint (/device_authorization, /bc-authorize) and
// verify it again when the client polls /token, so one fixture drives
// both: it registers a confidential or public client for the grant
// under test and retains the single certificate that has to bind
// initiation and redemption.
type mtlsAsyncFixture struct {
	tk     *testkit.Provider
	client *store.Client
	secret string
	cert   *x509.Certificate
	thumb  string
}

// newMTLSAsyncFixture constructs an MTLS-enabled provider for one
// asynchronous grant family. enable installs either the device-code or
// the CIBA endpoint; grantType is registered alongside refresh_token so
// every successful redemption also exercises the refresh-token binding
// policy.
func newMTLSAsyncFixture(
	t *testing.T,
	public bool,
	enable op.Option,
	grantType, clientID string,
) *mtlsAsyncFixture {
	t.Helper()
	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithFeature(feature.MTLS),
		enable,
	))
	secret := ""
	secretHash := ""
	authMethod := "none"
	if !public {
		secret = "rp-mtls-async-secret" //nolint:gosec // not a credential — opaque test fixture secret.
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
	cert := mtlsCert(t)
	return &mtlsAsyncFixture{
		tk:     tk,
		client: client,
		secret: secret,
		cert:   cert,
		thumb:  mtlsThumbprint(cert),
	}
}

// post sends one form request to path with the supplied client
// certificate (nil for a certificate-less request). Public clients
// authenticate with client_id in the body; confidential clients use
// HTTP Basic.
func (f *mtlsAsyncFixture) post(
	t *testing.T,
	path string,
	form url.Values,
	cert *x509.Certificate,
) (int, map[string]any) {
	t.Helper()
	if f.secret == "" {
		form.Set("client_id", f.client.ID)
	}
	resp := mtlsServeWithCert(t, f.tk, http.MethodPost, f.tk.Issuer+path, form, cert, func(r *http.Request) {
		if f.secret != "" {
			r.SetBasicAuth(f.client.ID, f.secret)
		}
	})
	defer resp.Body.Close()
	return resp.StatusCode, mtlsDecodeJSON(t, resp)
}

// redeemDeviceCodeStatus drives /device_authorization with the
// fixture's certificate, approves the record through the substore (the
// verification page is the embedder's surface), and polls /token with
// pollCert. It returns the poll's status and body so a row can assert
// either outcome.
func (f *mtlsAsyncFixture) redeemDeviceCodeStatus(
	t *testing.T,
	pollCert *x509.Certificate,
) (int, map[string]any) {
	t.Helper()
	status, initiated := f.post(t, "/oidc/device_authorization",
		url.Values{"scope": {"openid"}}, f.cert)
	if status != http.StatusOK {
		t.Fatalf("/device_authorization status=%d body=%v", status, initiated)
	}
	deviceCode, _ := initiated["device_code"].(string)
	if deviceCode == "" {
		t.Fatalf("device_code missing: %v", initiated)
	}
	if err := f.tk.Store.DeviceCodes().Approve(
		context.Background(), deviceCode, devDefaultSubject, mtlsAsyncAuthTime,
	); err != nil {
		t.Fatalf("DeviceCodes.Approve: %v", err)
	}
	return f.post(t, "/oidc/token", url.Values{
		"grant_type":  {devURNDeviceCode},
		"device_code": {deviceCode},
	}, pollCert)
}

// redeemDeviceCode is the success-path wrapper around
// [mtlsAsyncFixture.redeemDeviceCodeStatus].
func (f *mtlsAsyncFixture) redeemDeviceCode(t *testing.T, pollCert *x509.Certificate) map[string]any {
	t.Helper()
	status, body := f.redeemDeviceCodeStatus(t, pollCert)
	if status != http.StatusOK {
		t.Fatalf("device_code /token status=%d body=%v", status, body)
	}
	return body
}

// redeemCIBAStatus mirrors [mtlsAsyncFixture.redeemDeviceCodeStatus]
// for the CIBA family: /bc-authorize with the fixture's certificate,
// approval through the substore (the authentication device is the
// embedder's surface), then a /token poll with pollCert.
func (f *mtlsAsyncFixture) redeemCIBAStatus(
	t *testing.T,
	pollCert *x509.Certificate,
) (int, map[string]any) {
	t.Helper()
	status, initiated := f.post(t, "/oidc/bc-authorize", url.Values{
		"scope":      {"openid"},
		"login_hint": {cibaKnownLoginHint},
	}, f.cert)
	if status != http.StatusOK {
		t.Fatalf("/bc-authorize status=%d body=%v", status, initiated)
	}
	authReqID, _ := initiated["auth_req_id"].(string)
	if authReqID == "" {
		t.Fatalf("auth_req_id missing: %v", initiated)
	}
	if err := f.tk.Store.CIBARequests().Approve(
		context.Background(), authReqID, cibaDefaultSubject, "", mtlsAsyncAuthTime,
	); err != nil {
		t.Fatalf("CIBARequests.Approve: %v", err)
	}
	return f.post(t, "/oidc/token", url.Values{
		"grant_type":  {cibaURNGrant},
		"auth_req_id": {authReqID},
	}, pollCert)
}

// redeemCIBA is the success-path wrapper around
// [mtlsAsyncFixture.redeemCIBAStatus].
func (f *mtlsAsyncFixture) redeemCIBA(t *testing.T, pollCert *x509.Certificate) map[string]any {
	t.Helper()
	status, body := f.redeemCIBAStatus(t, pollCert)
	if status != http.StatusOK {
		t.Fatalf("ciba /token status=%d body=%v", status, body)
	}
	return body
}

// assertBoundTokens checks both halves of the binding contract on a
// successful asynchronous redemption: the access token's cnf carries
// the certificate thumbprint (and no jkt, because no DPoP proof was
// presented), and the persisted refresh-token record carries the same
// thumbprint. The refresh half holds for confidential and public
// clients alike — v1.0 binds once and enforces always rather than
// leaving a confidential client's chain to downgrade to bearer on the
// first rotation.
func (f *mtlsAsyncFixture) assertBoundTokens(t *testing.T, body map[string]any) {
	t.Helper()
	if f.thumb == "" {
		t.Fatal("fixture certificate produced an empty thumbprint")
	}
	accessToken, _ := body["access_token"].(string)
	if accessToken == "" {
		t.Fatalf("access_token missing: %v", body)
	}
	cnf := mtlsAccessTokenCnf(t, accessToken)
	if got := cnf["x5t#S256"]; got != f.thumb {
		t.Errorf("access_token cnf.x5t#S256=%q want %q", got, f.thumb)
	}
	if _, hasJKT := cnf["jkt"]; hasJKT {
		t.Errorf("cnf must not carry jkt for an mTLS-only bound token (cnf=%v)", cnf)
	}
	refreshToken, _ := body["refresh_token"].(string)
	if refreshToken == "" {
		t.Fatalf("refresh_token missing: %v", body)
	}
	rec, err := f.tk.Store.RefreshTokens().Find(context.Background(), refreshToken)
	if err != nil {
		t.Fatalf("RefreshTokens.Find: %v", err)
	}
	if rec.MTLSCertThumbprint != f.thumb {
		t.Errorf("refresh token MTLSCertThumbprint=%q want %q", rec.MTLSCertThumbprint, f.thumb)
	}
}

// assertMTLSGrantRejected pins the refusal shape shared by the
// certificate-less polls: 400 invalid_grant with no credential in the
// body.
func assertMTLSGrantRejected(t *testing.T, status int, body map[string]any) {
	t.Helper()
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 (body=%v)", status, body)
	}
	if got, _ := body["error"].(string); got != "invalid_grant" {
		t.Errorf("error=%q want invalid_grant (body=%v)", got, body)
	}
	if _, present := body["access_token"]; present {
		t.Errorf("rejection must not mint an access token: %v", body)
	}
}

// mtlsIssueAuthCodeAccessToken is the shared "issue an mTLS-bound
// access token" helper used by the userinfo-side scenarios. It runs
// /authorize → /token with the supplied cert and returns the AT;
// callers that want the RT or the rotated chain replicate the
// /token step inline.
func mtlsIssueAuthCodeAccessToken(t *testing.T, f *mtlsConfidentialFixture, cert *x509.Certificate) string {
	t.Helper()
	code, pkce := mtlsRunCodeFlow(t, f.tk, f.client)
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {f.client.RedirectURIs[0]},
		"code_verifier": {pkce.Verifier},
	}
	resp := mtlsServeWithCert(t, f.tk, http.MethodPost, mtlsTokenURL(f.tk), form, cert, func(r *http.Request) {
		r.SetBasicAuth(f.client.ID, f.secret)
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("/token status=%d body=%s", resp.StatusCode, dump)
	}
	body := mtlsDecodeJSON(t, resp)
	at, _ := body["access_token"].(string)
	if at == "" {
		t.Fatal("access_token missing")
	}
	return at
}
