package scenarios_test

// Catalog: test/scenarios/catalog/jwt_bearer_grant.yaml (JBG-NNN)
// Spec:
//   - RFC 7523 — JWT Profile for OAuth 2.0 Client Authentication and
//     Authorization Grants (§2.1, §3, §3.1)
//   - RFC 6749 §5.2 — error response
//   - RFC 9449 (DPoP) and RFC 8705 (mTLS) for the binding rows
//
// Each test stands up a testkit provider that trusts a locally held ES256
// key as an assertion issuer (static JWKS, no network), signs assertions
// with that key, and POSTs to the token endpoint in-process so a client
// certificate can be presented. Every rejection row also pins the
// jwt_bearer.rejected audit reason, which names the verification stage.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

const (
	jbgGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer" //nolint:gosec // G101: grant type URN, not a credential.
	jbgPlainIss  = "https://idp-plain.example.com"
	jbgJAGIss    = "https://idp-jag.example.com"
	jbgKID       = "jbg-issuer-key"
	jbgSecret    = "jbg-client-secret" //nolint:gosec // G101: a test-only client secret.
	jbgAPI       = "https://api.example.com/mcp"
	jbgOther     = "https://other.example.com/mcp"
	jbgUser      = "user-alice"

	jbgBasic    = "jbg-basic"
	jbgPKJWT    = "jbg-pkjwt"
	jbgPublic   = "jbg-public"
	jbgNoGrant  = "jbg-no-grant"
	jbgOutsider = "jbg-outsider"
)

// jbgNow is the instant every jwt-bearer scenario runs at.
var jbgNow = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

// jbgAuditSink collects the JSON audit records the provider writes.
type jbgAuditSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *jbgAuditSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

// records returns the audit records named event, in emission order.
func (s *jbgAuditSink) records(event string) []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []map[string]any
	for _, line := range bytes.Split(s.buf.Bytes(), []byte("\n")) {
		var rec map[string]any
		if len(line) == 0 || json.Unmarshal(line, &rec) != nil || rec["event"] != event {
			continue
		}
		out = append(out, rec)
	}
	return out
}

// rejectedReasons lists the reason of every jwt_bearer.rejected record.
func (s *jbgAuditSink) rejectedReasons() []string {
	var out []string
	for _, rec := range s.records("jwt_bearer.rejected") {
		extras, _ := rec["extras"].(map[string]any)
		reason, _ := extras["reason"].(string)
		out = append(out, reason)
	}
	return out
}

// jbgAuditLogger returns a JSON audit logger writing to sink.
func jbgAuditLogger(sink *jbgAuditSink) *slog.Logger {
	return slog.New(slog.NewJSONHandler(sink, nil))
}

// jbgConfig varies the provider a fixture builds.
type jbgConfig struct {
	disabled  bool // omit WithJWTBearerGrant
	plainOnly bool // trust only the plain-profile issuer
}

// jbgFixture is a provider that trusts one local signing key as an
// assertion issuer under both profiles.
type jbgFixture struct {
	tk       *testkit.Provider
	audit    *jbgAuditSink
	issuer   *pkjwtKeypair
	clientKP *pkjwtKeypair
	clock    dpopFixedClock
	seq      atomic.Int64

	mu       sync.Mutex
	resolved []op.AssertionSubject
}

func newJBGFixture(t *testing.T, cfg jbgConfig) *jbgFixture {
	t.Helper()
	f := &jbgFixture{
		audit:    &jbgAuditSink{},
		issuer:   newPKJWTKeypair(t, jbgKID),
		clientKP: newPKJWTKeypair(t, "jbg-client-key"),
		clock:    dpopFixedClock{t: jbgNow},
	}
	opts := []op.Option{
		op.WithFeature(feature.DPoP),
		op.WithFeature(feature.MTLS),
		op.WithAuditLogger(jbgAuditLogger(f.audit)),
	}
	if !cfg.disabled {
		plain := op.AssertionIssuer{
			Issuer:         jbgPlainIss,
			JWKS:           f.issuer.PublicJWKSet(t),
			AllowedClients: []string{jbgBasic, jbgPKJWT, jbgPublic, jbgNoGrant},
			Profile:        op.AssertionProfileJWT,
		}
		issuers := []op.AssertionIssuer{plain}
		if !cfg.plainOnly {
			jag := plain
			jag.Issuer, jag.Profile = jbgJAGIss, op.AssertionProfileIDJAG
			jag.JWKS, jag.JWKSURI = f.issuer.PublicJWKSet(t), ""
			issuers = append(issuers, jag)
		}
		opts = append(opts, op.WithJWTBearerGrant(op.JWTBearerGrant{
			Issuers:        issuers,
			ResolveSubject: f.resolveSubject,
		}))
	}
	f.tk = testkit.NewProvider(t, testkit.WithClock(f.clock), testkit.WithOptions(opts...))

	hash, err := op.HashClientSecret(jbgSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	scopes := []string{"openid", "read", "write"}
	resources := []string{jbgAPI, jbgOther}
	f.tk.RegisterClient(t, testkit.ClientFixture{
		ID: jbgBasic, SecretHash: hash, TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes: []string{jbgGrantType}, Scopes: scopes, Resources: resources,
	})
	//nolint:gosec // G101: "private_key_jwt" is the auth-method name, not a credential.
	f.tk.RegisterClient(t, testkit.ClientFixture{
		ID: jbgPKJWT, TokenEndpointAuthMethod: "private_key_jwt", JWKs: f.clientKP.PublicJWKSet(t),
		GrantTypes: []string{jbgGrantType}, Scopes: scopes, Resources: resources,
	})
	f.tk.RegisterClient(t, testkit.ClientFixture{
		ID: jbgPublic, PublicClient: true, TokenEndpointAuthMethod: "none",
		GrantTypes: []string{jbgGrantType}, Scopes: []string{"read"},
	})
	f.tk.RegisterClient(t, testkit.ClientFixture{
		ID: jbgNoGrant, SecretHash: hash, TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes: []string{"authorization_code"}, Scopes: []string{"read"},
	})
	f.tk.RegisterClient(t, testkit.ClientFixture{
		ID: jbgOutsider, SecretHash: hash, TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes: []string{jbgGrantType}, Scopes: []string{"read"},
	})
	f.tk.Store.PutUser(context.Background(), &store.User{Subject: jbgUser})
	return f
}

// resolveSubject is the embedder callback: it maps a few assertion
// subjects onto local accounts and fails in the ways the rows need.
func (f *jbgFixture) resolveSubject(_ context.Context, a op.AssertionSubject) (string, error) {
	f.mu.Lock()
	f.resolved = append(f.resolved, a)
	f.mu.Unlock()
	switch a.Subject {
	case "alice", "山田太郎":
		return jbgUser, nil
	case "gone":
		return "user-gone", nil // mapped, but absent from the user store
	case "blank":
		return "", nil
	case "broken":
		return "", errors.New("directory unavailable")
	default:
		return "", op.ErrUnknownAssertionSubject
	}
}

func (f *jbgFixture) lastResolved(t *testing.T) op.AssertionSubject {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.resolved) == 0 {
		t.Fatal("ResolveSubject was never called")
	}
	return f.resolved[len(f.resolved)-1]
}

func (f *jbgFixture) resolveCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.resolved)
}

func (f *jbgFixture) tokenURL() string { return f.tk.Issuer + "/oidc/token" }

// claims returns a valid claim set for the issuer iss: addressed to the OP,
// two minutes of life, fresh jti.
func (f *jbgFixture) claims(iss, sub string) map[string]any {
	return map[string]any{
		"iss": iss,
		"sub": sub,
		"aud": f.tk.Issuer,
		"exp": jbgNow.Add(2 * time.Minute).Unix(),
		"iat": jbgNow.Unix(),
		"jti": "jbg-jti-" + strconv.FormatInt(f.seq.Add(1), 10),
	}
}

func (f *jbgFixture) plainClaims(sub string) map[string]any { return f.claims(jbgPlainIss, sub) }

// idjagClaims is a valid ID-JAG claim set for clientID.
func (f *jbgFixture) idjagClaims(sub, clientID string) map[string]any {
	c := f.claims(jbgJAGIss, sub)
	c["client_id"] = clientID
	return c
}

// sign signs claims with the issuer key; typ "" leaves the header untyped.
func (f *jbgFixture) sign(t *testing.T, claims map[string]any, typ string) string {
	t.Helper()
	return jbgSign(t, f.issuer, claims, typ, jbgKID)
}

func jbgSign(t *testing.T, kp *pkjwtKeypair, claims map[string]any, typ, kid string) string {
	t.Helper()
	opts := &josev4.SignerOptions{}
	if typ != "" {
		opts = opts.WithType(josev4.ContentType(typ))
	}
	signer, err := josev4.NewSigner(josev4.SigningKey{
		Algorithm: josev4.ES256,
		Key:       josev4.JSONWebKey{Key: kp.priv, KeyID: kid, Algorithm: "ES256", Use: "sig"},
	}, opts)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	out, err := obj.CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize: %v", err)
	}
	return out
}

// jbgReq describes one token request.
type jbgReq struct {
	client    string // client_id; empty means jbgBasic
	assertion string
	extra     url.Values // appended to the form
	dpop      *dpopKey   // present a DPoP proof signed by this key
	cert      *x509.Certificate
	skipGrant bool   // omit the assertion parameter entirely
	pkJTI     string // jti for the private_key_jwt client assertion; empty means unique
}

// jbgResp is a decoded token endpoint response.
type jbgResp struct {
	status int
	body   map[string]any
}

func (r jbgResp) errCode() string {
	s, _ := r.body["error"].(string)
	return s
}

func (f *jbgFixture) post(t *testing.T, r jbgReq) jbgResp {
	t.Helper()
	if r.client == "" {
		r.client = jbgBasic
	}
	form := url.Values{"grant_type": {jbgGrantType}}
	if r.assertion != "" && !r.skipGrant {
		form.Set("assertion", r.assertion)
	}
	for k, vs := range r.extra {
		form[k] = append(form[k], vs...)
	}
	switch r.client {
	case jbgPKJWT:
		jti := r.pkJTI
		if jti == "" {
			jti = "jbg-pk-" + strconv.FormatInt(f.seq.Add(1), 10)
		}
		form.Set("client_id", r.client)
		form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		form.Set("client_assertion", signedClientAssertion(t, f.clientKP, map[string]any{
			"iss": r.client, "sub": r.client, "aud": f.tokenURL(), "jti": jti,
			"iat": jbgNow.Unix(), "exp": jbgNow.Add(2 * time.Minute).Unix(),
		}))
	case jbgPublic:
		form.Set("client_id", r.client)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, f.tokenURL(), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if r.client != jbgPKJWT && r.client != jbgPublic {
		req.SetBasicAuth(r.client, jbgSecret)
	}
	if r.dpop != nil {
		req.Header.Set("DPoP", makeDPoPProof(t, *r.dpop, dpopProofOpts{
			htu: f.tokenURL(), iat: jbgNow, jti: "jbg-dpop-" + strconv.FormatInt(f.seq.Add(1), 10),
		}))
	}
	if r.cert != nil {
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{r.cert}}
	}
	rec := httptest.NewRecorder()
	f.tk.OP.ServeHTTP(rec, req)
	raw, err := io.ReadAll(rec.Result().Body)
	if err != nil {
		t.Fatalf("read token response: %v", err)
	}
	out := jbgResp{status: rec.Code, body: map[string]any{}}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out.body); err != nil {
			t.Fatalf("decode token response %q: %v", raw, err)
		}
	}
	return out
}

// expectError asserts status, error code and the single audit reason.
func (f *jbgFixture) expectError(t *testing.T, resp jbgResp, status int, code, reason string) {
	t.Helper()
	if resp.status != status || resp.errCode() != code {
		t.Fatalf("status=%d error=%q body=%v, want %d %s", resp.status, resp.errCode(), resp.body, status, code)
	}
	if got := f.audit.rejectedReasons(); !slices.Equal(got, []string{reason}) {
		t.Fatalf("jwt_bearer.rejected reasons = %v, want [%s]", got, reason)
	}
}

// expectOK asserts a 200 carrying neither refresh_token nor id_token and
// returns the access token claims.
func (f *jbgFixture) expectOK(t *testing.T, resp jbgResp) map[string]any {
	t.Helper()
	if resp.status != http.StatusOK {
		t.Fatalf("status=%d body=%v, want 200", resp.status, resp.body)
	}
	for _, absent := range []string{"refresh_token", "id_token"} {
		if _, has := resp.body[absent]; has {
			t.Errorf("%s must not be issued on the jwt-bearer grant", absent)
		}
	}
	at, _ := resp.body["access_token"].(string)
	return decodeJWTPayload(t, at)
}

// jbgAudience normalises an aud claim to a slice.
func jbgAudience(v any) []string {
	switch aud := v.(type) {
	case string:
		return []string{aud}
	case []any:
		var out []string
		for _, a := range aud {
			s, _ := a.(string)
			out = append(out, s)
		}
		return out
	}
	return nil
}

// jbgDiscovery fetches the discovery document.
func jbgDiscovery(t *testing.T, tk *testkit.Provider) map[string]any {
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
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	return doc
}

func jbgListed(doc map[string]any, field, want string) bool {
	values, _ := doc[field].([]any)
	return slices.Contains(values, any(want))
}

func TestScenario_JBG_001_DiscoveryAndEnablement(t *testing.T) {
	t.Parallel()

	t.Run("configured: grant listed, profile advertisement follows the issuers", func(t *testing.T) {
		t.Parallel()
		plainOnly := newJBGFixture(t, jbgConfig{plainOnly: true})
		doc := jbgDiscovery(t, plainOnly.tk)
		if !jbgListed(doc, "grant_types_supported", jbgGrantType) {
			t.Errorf("grant_types_supported = %v, want it to list %s", doc["grant_types_supported"], jbgGrantType)
		}
		if _, has := doc["authorization_grant_profiles_supported"]; has {
			t.Errorf("authorization_grant_profiles_supported = %v, want absent with only plain issuers", doc["authorization_grant_profiles_supported"])
		}
		raw, _ := json.Marshal(doc)
		if strings.Contains(string(raw), jbgPlainIss) {
			t.Error("discovery names a trusted assertion issuer")
		}

		both := newJBGFixture(t, jbgConfig{})
		doc = jbgDiscovery(t, both.tk)
		if !jbgListed(doc, "authorization_grant_profiles_supported", "urn:ietf:params:oauth:grant-profile:id-jag") {
			t.Errorf("authorization_grant_profiles_supported = %v, want the id-jag profile", doc["authorization_grant_profiles_supported"])
		}
		raw, _ = json.Marshal(doc)
		if strings.Contains(string(raw), jbgJAGIss) {
			t.Error("discovery names a trusted assertion issuer")
		}
	})

	t.Run("not configured: unsupported_grant_type and no listing", func(t *testing.T) {
		t.Parallel()
		f := newJBGFixture(t, jbgConfig{disabled: true})
		resp := f.post(t, jbgReq{assertion: f.sign(t, f.plainClaims("alice"), "")})
		if resp.status != http.StatusBadRequest || resp.errCode() != "unsupported_grant_type" {
			t.Errorf("status=%d body=%v, want 400 unsupported_grant_type", resp.status, resp.body)
		}
		if jbgListed(jbgDiscovery(t, f.tk), "grant_types_supported", jbgGrantType) {
			t.Error("grant_types_supported lists jwt-bearer on a provider without it")
		}
	})
}

func TestScenario_JBG_002_ReservedGrantURNAndExplicitEnablement(t *testing.T) {
	t.Parallel()

	good := jbgValidGrant(t)
	handler := func(name string) op.Option {
		return op.WithCustomGrant(&recordingCustomGrant{name: name})
	}

	// A custom grant under another URN is accepted, so the refusals below
	// are about the jwt-bearer name and not about the surrounding options.
	if _, err := op.New(testkit.MinimalOptions(t, op.WithJWTBearerGrant(good), handler("urn:example:grant:other"))...); err != nil {
		t.Fatalf("control: jwt-bearer plus an unrelated custom grant: %v", err)
	}

	cases := []struct {
		name string
		opts []op.Option
	}{
		{"custom grant after WithJWTBearerGrant", []op.Option{op.WithJWTBearerGrant(good), handler(jbgGrantType)}},
		{"custom grant before WithJWTBearerGrant", []op.Option{handler(jbgGrantType), op.WithJWTBearerGrant(good)}},
		{"custom grant without WithJWTBearerGrant", []op.Option{handler(jbgGrantType)}},
		{"WithGrants alone", []op.Option{op.WithGrants(grant.AuthorizationCode, grant.JWTBearer)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := op.New(testkit.MinimalOptions(t, tc.opts...)...); err == nil {
				t.Error("op.New accepted the configuration")
			}
		})
	}
}

// jbgValidGrant is a configuration op.New accepts.
func jbgValidGrant(t *testing.T) op.JWTBearerGrant {
	t.Helper()
	return op.JWTBearerGrant{
		Issuers: []op.AssertionIssuer{{
			Issuer:         jbgPlainIss,
			JWKS:           newPKJWTKeypair(t, jbgKID).PublicJWKSet(t),
			AllowedClients: []string{jbgBasic},
			Profile:        op.AssertionProfileJWT,
		}},
		ResolveSubject: func(context.Context, op.AssertionSubject) (string, error) { return jbgUser, nil },
	}
}

func TestScenario_JBG_003_ConfigurationRejectedAtConstruction(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		mutate func(*op.JWTBearerGrant)
	}{
		{"no issuers", func(g *op.JWTBearerGrant) { g.Issuers = nil }},
		{"nil ResolveSubject", func(g *op.JWTBearerGrant) { g.ResolveSubject = nil }},
		{"neither JWKS nor JWKSURI", func(g *op.JWTBearerGrant) { g.Issuers[0].JWKS = nil }},
		{"both JWKS and JWKSURI", func(g *op.JWTBearerGrant) { g.Issuers[0].JWKSURI = "https://idp.example.com/jwks" }},
		{"empty issuer", func(g *op.JWTBearerGrant) { g.Issuers[0].Issuer = "" }},
		{"duplicate issuer", func(g *op.JWTBearerGrant) { g.Issuers = append(g.Issuers, g.Issuers[0]) }},
		{"issuer equals the OP issuer", func(g *op.JWTBearerGrant) { g.Issuers[0].Issuer = testkit.DefaultIssuer }},
		{"plain-http JWKSURI", func(g *op.JWTBearerGrant) {
			g.Issuers[0].JWKS, g.Issuers[0].JWKSURI = nil, "http://idp.example.com/jwks"
		}},
		{"empty AllowedClients", func(g *op.JWTBearerGrant) { g.Issuers[0].AllowedClients = nil }},
	}

	if _, err := op.New(testkit.MinimalOptions(t, op.WithJWTBearerGrant(jbgValidGrant(t)))...); err != nil {
		t.Fatalf("control: the unmodified configuration was refused: %v", err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			g := jbgValidGrant(t)
			tc.mutate(&g)
			if _, err := op.New(testkit.MinimalOptions(t, op.WithJWTBearerGrant(g))...); err == nil {
				t.Error("op.New accepted the configuration")
			}
		})
	}
}

func TestScenario_JBG_004_PlainProfileIssuesAccessTokenOnly(t *testing.T) {
	t.Parallel()
	f := newJBGFixture(t, jbgConfig{})

	resp := f.post(t, jbgReq{assertion: f.sign(t, f.plainClaims("alice"), "")})
	at := f.expectOK(t, resp)

	if resp.body["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want Bearer", resp.body["token_type"])
	}
	if resp.body["scope"] != "read write" {
		t.Errorf("scope = %v, want the registered set without openid", resp.body["scope"])
	}
	if at["sub"] != jbgUser {
		t.Errorf("sub = %v, want %s (the ResolveSubject mapping)", at["sub"], jbgUser)
	}
	if at["iss"] != f.tk.Issuer || at["client_id"] != jbgBasic {
		t.Errorf("iss=%v client_id=%v, want %s / %s", at["iss"], at["client_id"], f.tk.Issuer, jbgBasic)
	}
	if aud := jbgAudience(at["aud"]); !slices.Equal(aud, []string{f.tk.Issuer}) {
		t.Errorf("aud = %v, want [%s]", aud, f.tk.Issuer)
	}
	if _, has := at["cnf"]; has {
		t.Errorf("cnf = %v, want none on an unbound request", at["cnf"])
	}
	granted := f.audit.records("jwt_bearer.granted")
	if len(granted) != 1 {
		t.Fatalf("jwt_bearer.granted records = %d, want 1", len(granted))
	}
	extras, _ := granted[0]["extras"].(map[string]any)
	if extras["issuer"] != jbgPlainIss || extras["profile"] != "jwt" {
		t.Errorf("jwt_bearer.granted extras = %v, want issuer %s profile jwt", extras, jbgPlainIss)
	}
}

func TestScenario_JBG_005_PublicClientUnauthorized(t *testing.T) {
	t.Parallel()
	f := newJBGFixture(t, jbgConfig{})

	resp := f.post(t, jbgReq{client: jbgPublic, assertion: f.sign(t, f.plainClaims("alice"), "")})
	f.expectError(t, resp, http.StatusBadRequest, "unauthorized_client", "public_client")
	if n := f.resolveCalls(); n != 0 {
		t.Errorf("ResolveSubject ran %d times for a refused client", n)
	}
}

func TestScenario_JBG_006_ClientNotPermittedUnauthorized(t *testing.T) {
	t.Parallel()

	t.Run("client outside the issuer's AllowedClients", func(t *testing.T) {
		t.Parallel()
		f := newJBGFixture(t, jbgConfig{})
		assertion := f.sign(t, f.plainClaims("alice"), "")
		f.expectError(t, f.post(t, jbgReq{client: jbgOutsider, assertion: assertion}),
			http.StatusBadRequest, "unauthorized_client", "client_not_allowed")
		// The refusal precedes verification, so the jti is still unspent.
		f.expectOK(t, f.post(t, jbgReq{assertion: assertion}))
	})

	t.Run("client not registered for the grant", func(t *testing.T) {
		t.Parallel()
		f := newJBGFixture(t, jbgConfig{})
		resp := f.post(t, jbgReq{client: jbgNoGrant, assertion: f.sign(t, f.plainClaims("alice"), "")})
		if resp.status != http.StatusBadRequest || resp.errCode() != "unauthorized_client" {
			t.Errorf("status=%d body=%v, want 400 unauthorized_client", resp.status, resp.body)
		}
	})
}

// jbgRejection is one assertion the plain profile must refuse.
type jbgRejection struct {
	name   string
	reason string
	build  func(t *testing.T, f *jbgFixture) string
}

func jbgClaimsMut(mut func(c map[string]any)) func(*testing.T, *jbgFixture) string {
	return func(t *testing.T, f *jbgFixture) string {
		c := f.plainClaims("alice")
		mut(c)
		return f.sign(t, c, "")
	}
}

func TestScenario_JBG_007_InvalidAssertionRefusedPerStage(t *testing.T) {
	t.Parallel()

	hs256 := func(t *testing.T, f *jbgFixture) string {
		signer, err := josev4.NewSigner(josev4.SigningKey{Algorithm: josev4.HS256, Key: []byte("0123456789abcdef0123456789abcdef")}, nil)
		if err != nil {
			t.Fatalf("NewSigner(HS256): %v", err)
		}
		payload, _ := json.Marshal(f.plainClaims("alice"))
		obj, err := signer.Sign(payload)
		if err != nil {
			t.Fatalf("Sign(HS256): %v", err)
		}
		out, _ := obj.CompactSerialize()
		return out
	}
	algNone := func(t *testing.T, f *jbgFixture) string {
		payload, _ := json.Marshal(f.plainClaims("alice"))
		enc := base64.RawURLEncoding
		return enc.EncodeToString([]byte(`{"alg":"none"}`)) + "." + enc.EncodeToString(payload) + "."
	}
	cases := []jbgRejection{
		{"not a JWS", "parse", func(*testing.T, *jbgFixture) string { return "not-a-jws" }},
		{"alg none", "parse", algNone},
		{"alg HS256", "parse", hs256},
		{"unknown issuer", "issuer", jbgClaimsMut(func(c map[string]any) { c["iss"] = "https://idp-unknown.example.com" })},
		{"issuer differing in case", "issuer", jbgClaimsMut(func(c map[string]any) { c["iss"] = strings.ToUpper(jbgPlainIss) })},
		{"issuer missing", "issuer", jbgClaimsMut(func(c map[string]any) { delete(c, "iss") })},
		{"typ oauth-id-jag+jwt on the plain profile", "typ", func(t *testing.T, f *jbgFixture) string {
			return f.sign(t, f.plainClaims("alice"), "oauth-id-jag+jwt")
		}},
		{"typ at+jwt on the plain profile", "typ", func(t *testing.T, f *jbgFixture) string {
			return f.sign(t, f.plainClaims("alice"), "at+jwt")
		}},
		{"signature by another key", "signature", func(t *testing.T, f *jbgFixture) string {
			return jbgSign(t, newPKJWTKeypair(t, jbgKID), f.plainClaims("alice"), "", jbgKID)
		}},
		{"kid absent from the issuer's keys", "signature", func(t *testing.T, f *jbgFixture) string {
			return jbgSign(t, f.issuer, f.plainClaims("alice"), "", "no-such-kid")
		}},
		{"aud names another authorization server", "claims", jbgClaimsMut(func(c map[string]any) { c["aud"] = "https://other-as.example.com" })},
		{"aud missing", "claims", jbgClaimsMut(func(c map[string]any) { delete(c, "aud") })},
		{"sub empty", "claims", jbgClaimsMut(func(c map[string]any) { c["sub"] = "" })},
		{"exp missing", "claims", jbgClaimsMut(func(c map[string]any) { delete(c, "exp") })},
		{"exp a string", "claims", jbgClaimsMut(func(c map[string]any) { c["exp"] = "soon" })},
		{"exp negative", "claims", jbgClaimsMut(func(c map[string]any) { c["exp"] = -1 })},
		{"exp long past", "claims", jbgClaimsMut(func(c map[string]any) { c["exp"] = jbgNow.Add(-5 * time.Minute).Unix() })},
		{"exp beyond five minutes plus leeway", "claims", jbgClaimsMut(func(c map[string]any) { c["exp"] = jbgNow.Add(6*time.Minute + time.Second).Unix() })},
		{"nbf in the future", "claims", jbgClaimsMut(func(c map[string]any) { c["nbf"] = jbgNow.Add(10 * time.Minute).Unix() })},
		{"jti missing", "replay", jbgClaimsMut(func(c map[string]any) { delete(c, "jti") })},
		{"jti empty", "replay", jbgClaimsMut(func(c map[string]any) { c["jti"] = "" })},
		{"jti over 256 characters", "replay", jbgClaimsMut(func(c map[string]any) { c["jti"] = strings.Repeat("j", 257) })},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newJBGFixture(t, jbgConfig{})
			resp := f.post(t, jbgReq{assertion: tc.build(t, f)})
			f.expectError(t, resp, http.StatusBadRequest, "invalid_grant", tc.reason)
			if n := f.resolveCalls(); n != 0 {
				t.Errorf("ResolveSubject ran %d times for a refused assertion", n)
			}
		})
	}
}

func TestScenario_JBG_008_AudienceAndLifetimeAcceptance(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		mut  func(f *jbgFixture, c map[string]any)
		want bool
	}{
		{"aud is the issuer", func(*jbgFixture, map[string]any) {}, true},
		{"aud is the token endpoint URL", func(f *jbgFixture, c map[string]any) { c["aud"] = f.tokenURL() }, true},
		{"aud array containing the issuer", func(f *jbgFixture, c map[string]any) {
			c["aud"] = []string{"https://elsewhere.example.com", f.tk.Issuer}
		}, true},
		{"aud array naming only others", func(_ *jbgFixture, c map[string]any) {
			c["aud"] = []string{"https://elsewhere.example.com", "https://other-as.example.com"}
		}, false},
		{"exp exactly five minutes plus leeway", func(_ *jbgFixture, c map[string]any) { c["exp"] = jbgNow.Add(6 * time.Minute).Unix() }, true},
		{"exp one second beyond", func(_ *jbgFixture, c map[string]any) { c["exp"] = jbgNow.Add(6*time.Minute + time.Second).Unix() }, false},
		{"nbf inside the leeway", func(_ *jbgFixture, c map[string]any) { c["nbf"] = jbgNow.Add(30 * time.Second).Unix() }, true},
		{"jti of exactly 256 characters", func(_ *jbgFixture, c map[string]any) { c["jti"] = strings.Repeat("j", 256) }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newJBGFixture(t, jbgConfig{})
			c := f.plainClaims("alice")
			tc.mut(f, c)
			resp := f.post(t, jbgReq{assertion: f.sign(t, c, "")})
			if tc.want {
				f.expectOK(t, resp)
				return
			}
			f.expectError(t, resp, http.StatusBadRequest, "invalid_grant", "claims")
		})
	}
}

func TestScenario_JBG_009_JTISingleUse(t *testing.T) {
	t.Parallel()

	t.Run("a second redemption of the same assertion is refused", func(t *testing.T) {
		t.Parallel()
		f := newJBGFixture(t, jbgConfig{})
		assertion := f.sign(t, f.plainClaims("alice"), "")

		f.expectOK(t, f.post(t, jbgReq{assertion: assertion}))
		f.expectError(t, f.post(t, jbgReq{assertion: assertion}), http.StatusBadRequest, "invalid_grant", "replay")
	})

	t.Run("a jti spent as a client_assertion does not collide", func(t *testing.T) {
		t.Parallel()
		f := newJBGFixture(t, jbgConfig{})
		c := f.plainClaims("alice")
		c["jti"] = "shared-jti"

		f.expectOK(t, f.post(t, jbgReq{client: jbgPKJWT, pkJTI: "shared-jti", assertion: f.sign(t, c, "")}))
	})
}

func TestScenario_JBG_010_SubjectResolutionOutcomes(t *testing.T) {
	t.Parallel()

	cases := []struct {
		sub    string
		status int
		code   string
		reason string
	}{
		{"stranger", http.StatusBadRequest, "access_denied", "unknown_subject"},
		{"gone", http.StatusBadRequest, "access_denied", "subject_not_live"},
		{"blank", http.StatusInternalServerError, "server_error", "resolver_fault"},
		{"broken", http.StatusInternalServerError, "server_error", "resolver_fault"},
	}
	for _, tc := range cases {
		t.Run(tc.sub, func(t *testing.T) {
			t.Parallel()
			f := newJBGFixture(t, jbgConfig{})
			f.expectError(t, f.post(t, jbgReq{assertion: f.sign(t, f.plainClaims(tc.sub), "")}), tc.status, tc.code, tc.reason)
		})
	}
}

func TestScenario_JBG_011_ResolverReceivesVerifiedClaims(t *testing.T) {
	t.Parallel()
	f := newJBGFixture(t, jbgConfig{})
	c := f.plainClaims("山田太郎")
	c["email"] = "taro@example.com"

	at := f.expectOK(t, f.post(t, jbgReq{assertion: f.sign(t, c, "")}))

	got := f.lastResolved(t)
	if got.Issuer != jbgPlainIss || got.Subject != "山田太郎" || got.ClientID != jbgBasic {
		t.Errorf("AssertionSubject = {%s %s %s}, want {%s 山田太郎 %s}", got.Issuer, got.Subject, got.ClientID, jbgPlainIss, jbgBasic)
	}
	if got.Claims["email"] != "taro@example.com" || got.Claims["jti"] != c["jti"] {
		t.Errorf("Claims = %v, want the full verified claim set", got.Claims)
	}
	if at["sub"] != jbgUser {
		t.Errorf("sub = %v, want %s", at["sub"], jbgUser)
	}
}

func TestScenario_JBG_012_ScopeAndResourceNarrowing(t *testing.T) {
	t.Parallel()

	scopes := []struct {
		name, requested, want string
	}{
		{"unregistered scope dropped", "read admin", "read"},
		{"openid dropped", "openid write", "write"},
		{"absent falls back to the registration", "", "read write"},
	}
	for _, tc := range scopes {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newJBGFixture(t, jbgConfig{})
			req := jbgReq{assertion: f.sign(t, f.plainClaims("alice"), "")}
			if tc.requested != "" {
				req.extra = url.Values{"scope": {tc.requested}}
			}
			resp := f.post(t, req)
			at := f.expectOK(t, resp)
			if resp.body["scope"] != tc.want {
				t.Errorf("response scope = %v, want %q", resp.body["scope"], tc.want)
			}
			if at["scope"] != tc.want {
				t.Errorf("access token scope = %v, want %q", at["scope"], tc.want)
			}
		})
	}

	t.Run("only unregistered scopes", func(t *testing.T) {
		t.Parallel()
		f := newJBGFixture(t, jbgConfig{})
		assertion := f.sign(t, f.plainClaims("alice"), "")
		f.expectError(t, f.post(t, jbgReq{assertion: assertion, extra: url.Values{"scope": {"admin"}}}),
			http.StatusBadRequest, "invalid_scope", "scope")
		// A request the client can correct does not spend the assertion.
		f.expectOK(t, f.post(t, jbgReq{assertion: assertion}))
	})

	t.Run("registered resource becomes the audience", func(t *testing.T) {
		t.Parallel()
		f := newJBGFixture(t, jbgConfig{})
		at := f.expectOK(t, f.post(t, jbgReq{
			assertion: f.sign(t, f.plainClaims("alice"), ""), extra: url.Values{"resource": {jbgOther}},
		}))
		if aud := jbgAudience(at["aud"]); !slices.Equal(aud, []string{jbgOther}) {
			t.Errorf("aud = %v, want [%s]", aud, jbgOther)
		}
	})

	t.Run("unregistered resource", func(t *testing.T) {
		t.Parallel()
		f := newJBGFixture(t, jbgConfig{})
		f.expectError(t, f.post(t, jbgReq{
			assertion: f.sign(t, f.plainClaims("alice"), ""), extra: url.Values{"resource": {"https://unregistered.example.com"}},
		}), http.StatusBadRequest, "invalid_target", "resource")
	})
}

func TestScenario_JBG_013_DPoPBindsAccessToken(t *testing.T) {
	t.Parallel()
	f := newJBGFixture(t, jbgConfig{})
	key := newDPoPKey(t)

	resp := f.post(t, jbgReq{assertion: f.sign(t, f.plainClaims("alice"), ""), dpop: &key})
	at := f.expectOK(t, resp)

	if resp.body["token_type"] != "DPoP" {
		t.Errorf("token_type = %v, want DPoP", resp.body["token_type"])
	}
	cnf, _ := at["cnf"].(map[string]any)
	if cnf["jkt"] != key.jkt {
		t.Errorf("cnf = %v, want jkt %s", cnf, key.jkt)
	}
}

func TestScenario_JBG_014_MTLSBindsAccessToken(t *testing.T) {
	t.Parallel()
	f := newJBGFixture(t, jbgConfig{})
	cert := mtlsCert(t)

	resp := f.post(t, jbgReq{assertion: f.sign(t, f.plainClaims("alice"), ""), cert: cert})
	at := f.expectOK(t, resp)

	if resp.body["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want Bearer (RFC 8705 keeps the bearer type)", resp.body["token_type"])
	}
	cnf, _ := at["cnf"].(map[string]any)
	if cnf["x5t#S256"] != mtlsThumbprint(cert) {
		t.Errorf("cnf = %v, want x5t#S256 %s", cnf, mtlsThumbprint(cert))
	}
}

func TestScenario_JBG_015_AssertionParameterShape(t *testing.T) {
	t.Parallel()
	f := newJBGFixture(t, jbgConfig{})
	assertion := f.sign(t, f.plainClaims("alice"), "")

	cases := []struct {
		name string
		req  jbgReq
	}{
		{"missing", jbgReq{skipGrant: true, assertion: assertion}},
		{"duplicated", jbgReq{assertion: assertion, extra: url.Values{"assertion": {assertion}}}},
	}
	for _, tc := range cases {
		resp := f.post(t, tc.req)
		if resp.status != http.StatusBadRequest || resp.errCode() != "invalid_request" {
			t.Errorf("%s: status=%d body=%v, want 400 invalid_request", tc.name, resp.status, resp.body)
		}
	}
	// Neither malformed request reached verification, so the assertion is unspent.
	f.expectOK(t, f.post(t, jbgReq{assertion: assertion}))
}

// TestScenario_JBG_018_AssertionForAnotherASRefused confirms an assertion
// whose aud names a different authorization server is refused even though
// its signature verifies.
//
// Tracks: GHSA-fch4-3c6x-j4gc (Authlib) — a JWT bearer grant that checked
// only that aud was present accepted an assertion minted for a sibling AS.
func TestScenario_JBG_018_AssertionForAnotherASRefused(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		aud  any
	}{
		{"sibling issuer", "https://sibling-as.example.com"},
		{"sibling token endpoint", "https://sibling-as.example.com/oidc/token"},
		{"array of other servers", []string{"https://sibling-as.example.com", "https://another-as.example.com"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newJBGFixture(t, jbgConfig{})
			c := f.plainClaims("alice")
			c["aud"] = tc.aud
			f.expectError(t, f.post(t, jbgReq{assertion: f.sign(t, c, "")}), http.StatusBadRequest, "invalid_grant", "claims")
			if n := f.resolveCalls(); n != 0 {
				t.Errorf("ResolveSubject ran %d times for an assertion minted for another AS", n)
			}
		})
	}

	// Control: the same key and claims addressed to this AS are accepted.
	f := newJBGFixture(t, jbgConfig{})
	f.expectOK(t, f.post(t, jbgReq{assertion: f.sign(t, f.plainClaims("alice"), "")}))
}

// jbgBinding names how a pairwise row binds the request.
type jbgBinding int

const (
	jbgBindNone jbgBinding = iota
	jbgBindDPoP
	jbgBindMTLS
)

// jbgCnf names what the assertion's cnf claim carries.
type jbgCnf int

const (
	jbgCnfNone     jbgCnf = iota
	jbgCnfMatch           // the thumbprint of the credential the request presents
	jbgCnfMismatch        // a thumbprint of some other credential
)

// jbgCombo is one row of the combination set: profile x client
// authentication x request binding x assertion cnf.
type jbgCombo struct {
	id      string
	idjag   bool
	client  string
	binding jbgBinding
	cnf     jbgCnf
	// wantStatus / wantCode / wantReason describe the expected outcome;
	// wantCode "" means success.
	wantStatus int
	wantCode   string
	wantReason string
}

func (c jbgCombo) profile() string {
	if c.idjag {
		return "IDJAG"
	}
	return "JWT"
}

func (c jbgCombo) auth() string {
	switch c.client {
	case jbgPKJWT:
		return "private_key_jwt"
	case jbgPublic:
		return "none"
	}
	return "client_secret_basic"
}

// jbgCombos is a hand-built all-pairs set over profile {JWT, IDJAG} x
// client authentication {private_key_jwt, client_secret_basic, none} x
// request binding {none, DPoP, mTLS} x assertion cnf {none, match,
// mismatch}: C1-C9 cover every pair of levels, and C10-C11 add the
// bound-and-mismatched IDJAG cases the all-pairs rows only reach through
// an unauthenticated client. The plain profile does not read cnf.
var jbgCombos = []jbgCombo{
	{id: "C1", client: jbgPKJWT, binding: jbgBindNone, cnf: jbgCnfNone, wantStatus: http.StatusOK},
	{id: "C2", idjag: true, client: jbgPKJWT, binding: jbgBindDPoP, cnf: jbgCnfMatch, wantStatus: http.StatusOK},
	{id: "C3", client: jbgPKJWT, binding: jbgBindMTLS, cnf: jbgCnfMismatch, wantStatus: http.StatusOK},
	{
		id: "C4", idjag: true, client: jbgBasic, binding: jbgBindNone, cnf: jbgCnfMatch,
		wantStatus: http.StatusBadRequest, wantCode: "invalid_grant", wantReason: "idjag",
	},
	{id: "C5", client: jbgBasic, binding: jbgBindDPoP, cnf: jbgCnfMismatch, wantStatus: http.StatusOK},
	{id: "C6", idjag: true, client: jbgBasic, binding: jbgBindMTLS, cnf: jbgCnfNone, wantStatus: http.StatusOK},
	{
		id: "C7", idjag: true, client: jbgPublic, binding: jbgBindNone, cnf: jbgCnfMismatch,
		wantStatus: http.StatusBadRequest, wantCode: "unauthorized_client", wantReason: "public_client",
	},
	{
		id: "C8", client: jbgPublic, binding: jbgBindDPoP, cnf: jbgCnfNone,
		wantStatus: http.StatusBadRequest, wantCode: "unauthorized_client", wantReason: "public_client",
	},
	{
		id: "C9", client: jbgPublic, binding: jbgBindMTLS, cnf: jbgCnfMatch,
		wantStatus: http.StatusBadRequest, wantCode: "unauthorized_client", wantReason: "public_client",
	},
	{
		id: "C10", idjag: true, client: jbgPKJWT, binding: jbgBindDPoP, cnf: jbgCnfMismatch,
		wantStatus: http.StatusBadRequest, wantCode: "invalid_grant", wantReason: "idjag",
	},
	{
		id: "C11", idjag: true, client: jbgBasic, binding: jbgBindMTLS, cnf: jbgCnfMismatch,
		wantStatus: http.StatusBadRequest, wantCode: "invalid_grant", wantReason: "idjag",
	},
}

// jbgAllPairsRows is how many leading rows of jbgCombos form the all-pairs set.
const jbgAllPairsRows = 9

// run drives one combination row against a fresh provider.
func (c jbgCombo) run(t *testing.T) {
	t.Helper()
	f := newJBGFixture(t, jbgConfig{})
	var claims map[string]any
	var typ string
	if c.idjag {
		claims, typ = f.idjagClaims("alice", c.client), "oauth-id-jag+jwt"
	} else {
		claims = f.plainClaims("alice")
	}

	req := jbgReq{client: c.client}
	var wantCnf map[string]any
	switch c.binding {
	case jbgBindDPoP:
		key := newDPoPKey(t)
		req.dpop = &key
		wantCnf = map[string]any{"jkt": key.jkt}
	case jbgBindMTLS:
		req.cert = mtlsCert(t)
		wantCnf = map[string]any{"x5t#S256": mtlsThumbprint(req.cert)}
	}
	switch c.cnf {
	case jbgCnfMatch:
		// With no credential presented there is nothing to match: the
		// claim carries a thumbprint no request can satisfy.
		claims["cnf"] = map[string]any{"jkt": "thumbprint-of-an-absent-key"}
		if wantCnf != nil {
			claims["cnf"] = wantCnf
		}
	case jbgCnfMismatch:
		claims["cnf"] = map[string]any{"jkt": "thumbprint-of-another-key"}
		if c.binding == jbgBindMTLS {
			claims["cnf"] = map[string]any{"x5t#S256": "thumbprint-of-another-certificate"}
		}
	}
	req.assertion = f.sign(t, claims, typ)

	resp := f.post(t, req)
	if c.wantCode != "" {
		f.expectError(t, resp, c.wantStatus, c.wantCode, c.wantReason)
		return
	}
	at := f.expectOK(t, resp)
	if at["sub"] != jbgUser {
		t.Errorf("sub = %v, want %s", at["sub"], jbgUser)
	}
	gotCnf, _ := at["cnf"].(map[string]any)
	if len(gotCnf) != len(wantCnf) {
		t.Fatalf("cnf = %v, want %v", gotCnf, wantCnf)
	}
	for k, v := range wantCnf {
		if gotCnf[k] != v {
			t.Errorf("cnf.%s = %v, want %v", k, gotCnf[k], v)
		}
	}
}

// TestScenario_JBG_017_CombinationCoverage proves the set covers every pair
// and runs the plain-profile rows.
func TestScenario_JBG_017_CombinationCoverage(t *testing.T) {
	t.Parallel()
	assertJBGCombosCoverAllPairs(t)

	for _, c := range jbgCombos {
		if c.idjag {
			continue
		}
		t.Run(c.id+"/"+c.profile()+"/"+c.auth(), func(t *testing.T) {
			t.Parallel()
			c.run(t)
		})
	}
}

// assertJBGCombosCoverAllPairs fails unless every pair of levels from two
// different factors occurs in at least one of the C1-C9 rows.
func assertJBGCombosCoverAllPairs(t *testing.T) {
	t.Helper()
	factors := [][]string{
		{"JWT", "IDJAG"},
		{jbgPKJWT, jbgBasic, jbgPublic},
		{"bind-none", "bind-dpop", "bind-mtls"},
		{"cnf-none", "cnf-match", "cnf-mismatch"},
	}
	levels := func(c jbgCombo) []string {
		prof := 0
		if c.idjag {
			prof = 1
		}
		auth := slices.Index(factors[1], c.client)
		return []string{factors[0][prof], factors[1][auth], factors[2][c.binding], factors[3][c.cnf]}
	}
	seen := map[[4]string]bool{} // factor-pair key: i, j, level a, level b
	for _, c := range jbgCombos[:jbgAllPairsRows] {
		l := levels(c)
		for i := range l {
			for j := i + 1; j < len(l); j++ {
				seen[[4]string{strconv.Itoa(i), strconv.Itoa(j), l[i], l[j]}] = true
			}
		}
	}
	for i := range factors {
		for j := i + 1; j < len(factors); j++ {
			for _, a := range factors[i] {
				for _, b := range factors[j] {
					if !seen[[4]string{strconv.Itoa(i), strconv.Itoa(j), a, b}] {
						t.Errorf("pair (%s, %s) is not covered by the combination set", a, b)
					}
				}
			}
		}
	}
}
