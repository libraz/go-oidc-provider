package scenarios_test

// Catalog: test/scenarios/catalog/id_jag.yaml (IDJAG-NNN)
// Spec:
//   - draft-ietf-oauth-identity-assertion-authz-grant-06 (ID-JAG) §3.1, §4.3,
//     §4.4, §5.1
//   - RFC 8693 — OAuth 2.0 Token Exchange
//   - RFC 7523 §3
//
// Two halves share this file. The resource-AS half reuses the jwt-bearer
// fixture: a locally held ES256 key plays the IdP and signs ID-JAGs for an
// OP that trusts it under the ID-JAG profile. The IdP half stands up a
// provider configured with op.WithIDJAGIssuance, obtains a real ID token
// through the code flow and exchanges it for an ID-JAG; the round-trip row
// then redeems that ID-JAG at a second provider.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
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
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

const (
	ijgIDJAGType  = "urn:ietf:params:oauth:token-type:id-jag"
	ijgIDTokType  = "urn:ietf:params:oauth:token-type:id_token"
	ijgATTokType  = "urn:ietf:params:oauth:token-type:access_token"
	ijgProfile    = "urn:ietf:params:oauth:grant-profile:id-jag"
	ijgIDPIssuer  = "https://idp.testkit.invalid"
	ijgRASIssuer  = "https://ras.testkit.invalid"
	ijgRASPlain   = "https://ras-plain.testkit.invalid"
	ijgRASClient  = "ras-client"
	ijgRASSecret  = "ras-client-secret" //nolint:gosec // G101: a test-only client secret.
	ijgIDPClient  = "idp-rp"
	ijgIDPOther   = "idp-other-rp"
	ijgIDPPublic  = "idp-public-rp"
	ijgIDPPair    = "idp-pairwise-rp"
	ijgIDPSecret  = "idp-rp-secret" //nolint:gosec // G101: a test-only client secret.
	ijgRASAPI     = "https://ras.example.com/api"
	ijgRASAPITwo  = "https://ras.example.com/api2"
	ijgRASSubject = "ras-user-1"
	ijgEmail      = "taro@example.com"
	ijgRedirect   = "https://rp.testkit.invalid/callback"
)

// ijgProofSeq makes every DPoP proof jti unique.
var ijgProofSeq atomic.Int64

// ijgPolicy is the embedder's ID-JAG issuance policy. By default it admits
// the RAS issuer and echoes the requested scope and resource.
type ijgPolicy struct {
	mu   sync.Mutex
	fn   func(op.IDJAGRequest) (*op.IDJAGDecision, error)
	seen []op.IDJAGRequest
}

func (p *ijgPolicy) Allow(_ context.Context, req op.IDJAGRequest) (*op.IDJAGDecision, error) {
	p.mu.Lock()
	p.seen = append(p.seen, req)
	fn := p.fn
	p.mu.Unlock()
	if fn != nil {
		return fn(req)
	}
	if req.Audience != ijgRASIssuer {
		return nil, op.ErrIDJAGUnknownAudience
	}
	return &op.IDJAGDecision{ClientID: ijgRASClient, Scope: req.Scope, Resource: req.Resource, Email: ijgEmail}, nil
}

func (p *ijgPolicy) calls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.seen)
}

func (p *ijgPolicy) set(fn func(op.IDJAGRequest) (*op.IDJAGDecision, error)) {
	p.mu.Lock()
	p.fn = fn
	p.mu.Unlock()
}

// ijgIDPConfig varies the IdP a fixture builds.
type ijgIDPConfig struct {
	// accessTokenExchangeOnly configures the stable token-exchange policy
	// instead of ID-JAG issuance.
	accessTokenExchangeOnly bool
	pairwise                bool
}

// ijgIDP is a provider that issues ID-JAGs, plus an ID token its client
// obtained through the code flow.
type ijgIDP struct {
	tk       *testkit.Provider
	audit    *jbgAuditSink
	policy   *ijgPolicy
	idToken  string
	idClaims map[string]any
}

func newIJGIdP(t *testing.T, cfg ijgIDPConfig, tk ...testkit.Option) *ijgIDP {
	t.Helper()
	idp := &ijgIDP{audit: &jbgAuditSink{}, policy: &ijgPolicy{}}
	opts := []op.Option{
		op.WithFeature(feature.DPoP),
		op.WithFeature(feature.MTLS),
		op.WithAuditLogger(jbgAuditLogger(idp.audit)),
	}
	if cfg.accessTokenExchangeOnly {
		opts = append(opts, op.WithTokenExchange(txAllowAllPolicy{}))
	} else {
		opts = append(opts, op.WithIDJAGIssuance(idp.policy))
	}
	if cfg.pairwise {
		opts = append(opts, op.WithPairwiseSubject([]byte("idjag-pairwise-salt-32-bytes-long")))
	}
	idp.tk = testkit.NewProvider(t, append([]testkit.Option{
		testkit.WithIssuer(ijgIDPIssuer),
		testkit.WithClock(dpopFixedClock{t: jbgNow}),
		testkit.WithOptions(opts...),
	}, tk...)...)
	hash, err := op.HashClientSecret(ijgIDPSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	for _, id := range []string{ijgIDPClient, ijgIDPOther} {
		idp.tk.RegisterClient(t, testkit.ClientFixture{
			ID: id, SecretHash: hash, TokenEndpointAuthMethod: "client_secret_basic",
			GrantTypes: []string{"authorization_code", op.TokenExchangeGrantType},
			Scopes:     []string{"openid", "profile"},
		})
	}
	idp.tk.RegisterClient(t, testkit.ClientFixture{
		ID: ijgIDPPublic, PublicClient: true, TokenEndpointAuthMethod: "none",
		GrantTypes: []string{"authorization_code", op.TokenExchangeGrantType},
		Scopes:     []string{"openid", "profile"},
	})
	if cfg.pairwise {
		idp.tk.RegisterClient(t, testkit.ClientFixture{
			ID: ijgIDPPair, SecretHash: hash, TokenEndpointAuthMethod: "client_secret_basic",
			SubjectType: "pairwise",
			GrantTypes:  []string{"authorization_code", op.TokenExchangeGrantType},
			Scopes:      []string{"openid", "profile"},
		})
	}
	idp.idToken = idp.idTokenFor(t, ijgIDPClient)
	idp.idClaims = scenariokit.DecodeJWSClaims(t, idp.idToken)
	return idp
}

// idTokenFor runs the code flow for clientID and returns its ID token.
func (i *ijgIDP) idTokenFor(t *testing.T, clientID string) string {
	t.Helper()
	pkce := scenariokit.NewPKCEPair("")
	res := scenariokit.RunCodeFlow(t, i.tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID: clientID, RedirectURI: ijgRedirect, Scope: "openid profile", PKCE: pkce,
	})
	if res.Error != "" || res.Code == "" {
		t.Fatalf("authorize for %s failed: %+v", clientID, res)
	}
	tok := scenariokit.ExchangeCode(t, i.tk, scenariokit.ExchangeCodeRequest{
		Code: res.Code, RedirectURI: ijgRedirect, Verifier: pkce.Verifier,
		ClientID: clientID, ClientSecret: ijgIDPSecret,
	})
	if tok.StatusCode != http.StatusOK || tok.IDToken == "" {
		t.Fatalf("code redemption for %s: status=%d body=%v", clientID, tok.StatusCode, tok.Raw)
	}
	return tok.IDToken
}

// ijgExchange describes one token-exchange request to the IdP.
type ijgExchange struct {
	client       string // empty means ijgIDPClient
	subjectToken string // empty means the fixture's ID token
	subjectType  string // empty means id_token
	requested    []string
	audience     []string
	scope        string
	resource     []string
	extra        url.Values
	dpop         *dpopKey
	cert         *x509.Certificate
}

// ijgDefaultExchange asks for an ID-JAG addressed to the RAS.
func ijgDefaultExchange() ijgExchange {
	return ijgExchange{requested: []string{ijgIDJAGType}, audience: []string{ijgRASIssuer}, scope: "profile"}
}

func (x ijgExchange) form(idToken string) url.Values {
	form := url.Values{"grant_type": {op.TokenExchangeGrantType}}
	subject := x.subjectToken
	if subject == "" {
		subject = idToken
	}
	form.Set("subject_token", subject)
	form.Set("subject_token_type", ijgIDTokType)
	if x.subjectType != "" {
		form.Set("subject_token_type", x.subjectType)
	}
	if x.requested != nil {
		form["requested_token_type"] = x.requested
	}
	if x.audience != nil {
		form["audience"] = x.audience
	}
	if x.scope != "" {
		form.Set("scope", x.scope)
	}
	if x.resource != nil {
		form["resource"] = x.resource
	}
	for k, vs := range x.extra {
		form[k] = append(form[k], vs...)
	}
	return form
}

func (i *ijgIDP) exchange(t *testing.T, x ijgExchange) jbgResp {
	t.Helper()
	client := x.client
	if client == "" {
		client = ijgIDPClient
	}
	return ijgPost(t, i.tk, x.form(i.idToken), client, ijgIDPSecret, x.dpop, x.cert)
}

// issue exchanges and requires a 200, returning the response.
func (i *ijgIDP) issue(t *testing.T, x ijgExchange) jbgResp {
	t.Helper()
	resp := i.exchange(t, x)
	if resp.status != http.StatusOK {
		t.Fatalf("token exchange status=%d body=%v, want 200", resp.status, resp.body)
	}
	return resp
}

// ijgPost sends a token request to tk in-process, authenticating clientID
// by HTTP Basic (or by client_id alone for the public client).
func ijgPost(t *testing.T, tk *testkit.Provider, form url.Values, clientID, secret string, key *dpopKey, cert *x509.Certificate) jbgResp {
	t.Helper()
	tokenURL := tk.Issuer + "/oidc/token"
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, tokenURL, strings.NewReader(ijgFormWithClient(form, clientID)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if clientID != ijgIDPPublic {
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(secret))
	}
	if key != nil {
		req.Header.Set("DPoP", makeDPoPProof(t, *key, dpopProofOpts{htu: tokenURL, iat: jbgNow, jti: "ijg-dpop-" + strconv.FormatInt(ijgProofSeq.Add(1), 10)}))
	}
	if cert != nil {
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	}
	rec := httptest.NewRecorder()
	tk.OP.ServeHTTP(rec, req)
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

// ijgFormWithClient adds client_id for the public client, which has no
// other way to identify itself.
func ijgFormWithClient(form url.Values, clientID string) string {
	if clientID == ijgIDPPublic {
		form = cloneURLValues(form)
		form.Set("client_id", clientID)
	}
	return form.Encode()
}

func cloneURLValues(v url.Values) url.Values {
	out := make(url.Values, len(v))
	for k, vs := range v {
		out[k] = slices.Clone(vs)
	}
	return out
}

// ijgHeader decodes a compact JWS's protected header.
func ijgHeader(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var h map[string]any
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	return h
}

// ijgVerifyAgainstJWKS verifies token's ES256 signature with the key the
// provider publishes at its JWKS endpoint.
func ijgVerifyAgainstJWKS(t *testing.T, tk *testkit.Provider, token string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, tk.Server.URL+"/oidc/jwks", http.NoBody)
	if err != nil {
		t.Fatalf("build jwks request: %v", err)
	}
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("GET jwks: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var set josev4.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	jws, err := josev4.ParseSignedCompact(token, []josev4.SignatureAlgorithm{josev4.ES256})
	if err != nil {
		t.Fatalf("ParseSigned: %v", err)
	}
	keys := set.Key(jws.Signatures[0].Header.KeyID)
	if len(keys) != 1 {
		t.Fatalf("kid %q matches %d published keys, want 1", jws.Signatures[0].Header.KeyID, len(keys))
	}
	if _, err := jws.Verify(keys[0].Public()); err != nil {
		t.Errorf("ID-JAG does not verify under the published key: %v", err)
	}
}

// ijgRAS is a second provider that trusts the IdP's published keys and
// redeems ID-JAGs through the jwt-bearer grant.
type ijgRAS struct {
	tk       *testkit.Provider
	audit    *jbgAuditSink
	mu       sync.Mutex
	resolved []op.AssertionSubject
}

func newIJGRAS(t *testing.T, idp *ijgIDP, issuer string, profile op.AssertionProfile, tk ...testkit.Option) *ijgRAS {
	t.Helper()
	ras := &ijgRAS{audit: &jbgAuditSink{}}
	jwks := jbgFetchBody(t, idp.tk, "/oidc/jwks")
	ras.tk = testkit.NewProvider(t, append([]testkit.Option{
		testkit.WithIssuer(issuer),
		testkit.WithClock(dpopFixedClock{t: jbgNow}),
		testkit.WithOptions(
			op.WithAuditLogger(jbgAuditLogger(ras.audit)),
			op.WithJWTBearerGrant(op.JWTBearerGrant{
				Issuers: []op.AssertionIssuer{{
					Issuer: ijgIDPIssuer, JWKS: jwks, AllowedClients: []string{ijgRASClient}, Profile: profile,
				}},
				ResolveSubject: func(_ context.Context, a op.AssertionSubject) (string, error) {
					ras.mu.Lock()
					ras.resolved = append(ras.resolved, a)
					ras.mu.Unlock()
					if a.Issuer != ijgIDPIssuer || a.Subject != idp.idClaims["sub"] || a.ClientID != ijgRASClient {
						return "", op.ErrUnknownAssertionSubject
					}
					return ijgRASSubject, nil
				},
			}),
		),
	}, tk...)...)
	hash, err := op.HashClientSecret(ijgRASSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	ras.tk.RegisterClient(t, testkit.ClientFixture{
		ID: ijgRASClient, SecretHash: hash, GrantTypes: []string{jbgGrantType},
		Scopes: []string{"profile", "chat.read"}, Resources: []string{ijgRASAPI},
	})
	ras.tk.Store.PutUser(context.Background(), &store.User{Subject: ijgRASSubject})
	return ras
}

func (r *ijgRAS) redeem(t *testing.T, assertion string, extra url.Values) jbgResp {
	t.Helper()
	form := url.Values{"grant_type": {jbgGrantType}, "assertion": {assertion}}
	for k, vs := range extra {
		form[k] = vs
	}
	return ijgPost(t, r.tk, form, ijgRASClient, ijgRASSecret, nil, nil)
}

// jbgFetchBody GETs path from tk and returns the 200 body.
func jbgFetchBody(t *testing.T, tk *testkit.Provider, path string) []byte {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, tk.Server.URL+path, http.NoBody)
	if err != nil {
		t.Fatalf("build GET %s: %v", path, err)
	}
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status=%d err=%v", path, resp.StatusCode, err)
	}
	return raw
}

// ---------------------------------------------------------------------
// Resource-AS half: redemption of ID-JAGs signed by a local key.
// ---------------------------------------------------------------------

// idjagFor returns a signed, valid ID-JAG for sub addressed to jbgBasic.
func (f *jbgFixture) idjagFor(t *testing.T, mut func(c map[string]any)) string {
	t.Helper()
	c := f.idjagClaims("alice", jbgBasic)
	if mut != nil {
		mut(c)
	}
	return f.sign(t, c, "oauth-id-jag+jwt")
}

func TestScenario_IDJAG_001_TypeHeaderRequired(t *testing.T) {
	t.Parallel()

	for _, typ := range []string{"", "JWT", "at+jwt", "id_token+jwt"} {
		t.Run("typ="+typ, func(t *testing.T) {
			t.Parallel()
			f := newJBGFixture(t, jbgConfig{})
			assertion := f.sign(t, f.idjagClaims("alice", jbgBasic), typ)
			f.expectError(t, f.post(t, jbgReq{assertion: assertion}), http.StatusBadRequest, "invalid_grant", "typ")
		})
	}

	t.Run("oauth-id-jag+jwt is accepted", func(t *testing.T) {
		t.Parallel()
		f := newJBGFixture(t, jbgConfig{})
		f.expectOK(t, f.post(t, jbgReq{assertion: f.idjagFor(t, nil)}))
	})
}

func TestScenario_IDJAG_002_AudienceIsTheIssuerOnly(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		aud  func(f *jbgFixture) any
		ok   bool
	}{
		{"issuer as a string", func(f *jbgFixture) any { return f.tk.Issuer }, true},
		{"issuer as a one-element array", func(f *jbgFixture) any { return []string{f.tk.Issuer} }, true},
		{"token endpoint URL", func(f *jbgFixture) any { return f.tokenURL() }, false},
		{"array with two members", func(f *jbgFixture) any { return []string{f.tk.Issuer, "https://elsewhere.example.com"} }, false},
		{"another authorization server", func(*jbgFixture) any { return "https://other-as.example.com" }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newJBGFixture(t, jbgConfig{})
			resp := f.post(t, jbgReq{assertion: f.idjagFor(t, func(c map[string]any) { c["aud"] = tc.aud(f) })})
			if tc.ok {
				f.expectOK(t, resp)
				return
			}
			f.expectError(t, resp, http.StatusBadRequest, "invalid_grant", "claims")
		})
	}
}

func TestScenario_IDJAG_003_ClientIDAndIssuedAtRequired(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		mut    func(c map[string]any)
		reason string
	}{
		{"client_id names another client", func(c map[string]any) { c["client_id"] = jbgPKJWT }, "idjag"},
		{"client_id missing", func(c map[string]any) { delete(c, "client_id") }, "idjag"},
		{"client_id empty", func(c map[string]any) { c["client_id"] = "" }, "idjag"},
		{"iat missing", func(c map[string]any) { delete(c, "iat") }, "claims"},
		{"iat in the future", func(c map[string]any) { c["iat"] = jbgNow.Add(10 * time.Minute).Unix() }, "claims"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newJBGFixture(t, jbgConfig{})
			f.expectError(t, f.post(t, jbgReq{assertion: f.idjagFor(t, tc.mut)}), http.StatusBadRequest, "invalid_grant", tc.reason)
		})
	}
}

func TestScenario_IDJAG_004_TenantClaimRefused(t *testing.T) {
	t.Parallel()

	for _, claim := range []string{"tenant", "aud_tenant"} {
		t.Run(claim, func(t *testing.T) {
			t.Parallel()
			f := newJBGFixture(t, jbgConfig{})
			assertion := f.idjagFor(t, func(c map[string]any) { c[claim] = "acme" })
			f.expectError(t, f.post(t, jbgReq{assertion: assertion}), http.StatusBadRequest, "invalid_grant", "idjag")
			if n := f.resolveCalls(); n != 0 {
				t.Errorf("ResolveSubject ran %d times for a tenant-scoped ID-JAG", n)
			}
		})
	}
}

func TestScenario_IDJAG_005_RequestedScopeCoveredByClaim(t *testing.T) {
	t.Parallel()

	t.Run("request beyond the claim", func(t *testing.T) {
		t.Parallel()
		f := newJBGFixture(t, jbgConfig{})
		assertion := f.idjagFor(t, func(c map[string]any) { c["scope"] = "read" })
		f.expectError(t, f.post(t, jbgReq{assertion: assertion, extra: url.Values{"scope": {"read write"}}}),
			http.StatusBadRequest, "invalid_grant", "idjag")
	})

	t.Run("request within the claim", func(t *testing.T) {
		t.Parallel()
		f := newJBGFixture(t, jbgConfig{})
		assertion := f.idjagFor(t, func(c map[string]any) { c["scope"] = "read write" })
		resp := f.post(t, jbgReq{assertion: assertion, extra: url.Values{"scope": {"read"}}})
		at := f.expectOK(t, resp)
		if resp.body["scope"] != "read" || at["scope"] != "read" {
			t.Errorf("scope = %v / %v, want read", resp.body["scope"], at["scope"])
		}
	})

	t.Run("no request: the claim narrows the registered default", func(t *testing.T) {
		t.Parallel()
		f := newJBGFixture(t, jbgConfig{})
		assertion := f.idjagFor(t, func(c map[string]any) { c["scope"] = "read" })
		resp := f.post(t, jbgReq{assertion: assertion})
		f.expectOK(t, resp)
		if resp.body["scope"] != "read" {
			t.Errorf("scope = %v, want read", resp.body["scope"])
		}
	})
}

func TestScenario_IDJAG_006_ResourceRules(t *testing.T) {
	t.Parallel()

	const unregistered = "https://unregistered.example.com"
	cases := []struct {
		name      string
		claim     any // nil: no resource claim
		requested string
		wantAud   string
		wantCode  string
		wantWhy   string
	}{
		{name: "claim outside the client's resources", claim: unregistered, wantCode: "invalid_grant", wantWhy: "idjag"},
		{name: "request within the claim", claim: jbgAPI, requested: jbgAPI, wantAud: jbgAPI},
		{name: "request outside the claim", claim: jbgAPI, requested: jbgOther, wantCode: "invalid_target", wantWhy: "resource"},
		{name: "claim becomes the audience", claim: jbgAPI, wantAud: jbgAPI},
		{name: "several claimed, request selects one", claim: []string{jbgAPI, jbgOther}, requested: jbgOther, wantAud: jbgOther},
		{name: "several claimed, none selected", claim: []string{jbgAPI, jbgOther}, wantCode: "invalid_target", wantWhy: "resource"},
		{name: "no claim, registered request", requested: jbgOther, wantAud: jbgOther},
		{name: "no claim, unregistered request", requested: unregistered, wantCode: "invalid_target", wantWhy: "resource"},
		{name: "neither: the OP issuer is the audience", wantAud: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newJBGFixture(t, jbgConfig{})
			assertion := f.idjagFor(t, func(c map[string]any) {
				if tc.claim != nil {
					c["resource"] = tc.claim
				}
			})
			req := jbgReq{assertion: assertion}
			if tc.requested != "" {
				req.extra = url.Values{"resource": {tc.requested}}
			}
			resp := f.post(t, req)
			if tc.wantCode != "" {
				f.expectError(t, resp, http.StatusBadRequest, tc.wantCode, tc.wantWhy)
				return
			}
			at := f.expectOK(t, resp)
			want := tc.wantAud
			if want == "" {
				want = f.tk.Issuer
			}
			if aud := jbgAudience(at["aud"]); !slices.Equal(aud, []string{want}) {
				t.Errorf("aud = %v, want [%s]", aud, want)
			}
		})
	}
}

func TestScenario_IDJAG_007_ConfirmationMustMatchTheBinding(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		cnf     func(key *dpopKey, cert *x509.Certificate) any
		dpop    bool
		mtls    bool
		wantCnf string // "" means the redemption is refused
		wantVal func(key *dpopKey, cert *x509.Certificate) string
	}{
		{
			name: "jkt matching the DPoP key", dpop: true, wantCnf: "jkt",
			cnf:     func(k *dpopKey, _ *x509.Certificate) any { return map[string]any{"jkt": k.jkt} },
			wantVal: func(k *dpopKey, _ *x509.Certificate) string { return k.jkt },
		},
		{
			name: "x5t#S256 matching the client certificate", mtls: true, wantCnf: "x5t#S256",
			cnf:     func(_ *dpopKey, c *x509.Certificate) any { return map[string]any{"x5t#S256": mtlsThumbprint(c)} },
			wantVal: func(_ *dpopKey, c *x509.Certificate) string { return mtlsThumbprint(c) },
		},
		{name: "jkt of another key", dpop: true, cnf: func(*dpopKey, *x509.Certificate) any { return map[string]any{"jkt": "another-key"} }},
		{name: "x5t#S256 of another certificate", mtls: true, cnf: func(*dpopKey, *x509.Certificate) any { return map[string]any{"x5t#S256": "another-cert"} }},
		{name: "jkt while a certificate is presented", mtls: true, cnf: func(k *dpopKey, _ *x509.Certificate) any { return map[string]any{"jkt": k.jkt} }},
		{name: "cnf with nothing presented", cnf: func(k *dpopKey, _ *x509.Certificate) any { return map[string]any{"jkt": k.jkt} }},
		{name: "both methods", dpop: true, cnf: func(k *dpopKey, c *x509.Certificate) any {
			return map[string]any{"jkt": k.jkt, "x5t#S256": mtlsThumbprint(c)}
		}},
		{name: "unsupported jwk method", dpop: true, cnf: func(*dpopKey, *x509.Certificate) any { return map[string]any{"jwk": map[string]any{"kty": "EC"}} }},
		{name: "cnf not an object", dpop: true, cnf: func(*dpopKey, *x509.Certificate) any { return "jkt" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newJBGFixture(t, jbgConfig{})
			key := newDPoPKey(t)
			cert := mtlsCert(t)
			req := jbgReq{}
			if tc.dpop {
				req.dpop = &key
			}
			if tc.mtls {
				req.cert = cert
			}
			req.assertion = f.idjagFor(t, func(c map[string]any) { c["cnf"] = tc.cnf(&key, cert) })

			resp := f.post(t, req)
			if tc.wantCnf == "" {
				f.expectError(t, resp, http.StatusBadRequest, "invalid_grant", "idjag")
				return
			}
			at := f.expectOK(t, resp)
			cnf, _ := at["cnf"].(map[string]any)
			if len(cnf) != 1 || cnf[tc.wantCnf] != tc.wantVal(&key, cert) {
				t.Errorf("cnf = %v, want only %s=%s", cnf, tc.wantCnf, tc.wantVal(&key, cert))
			}
		})
	}
}

func TestScenario_IDJAG_008_RedemptionMapsTheSubject(t *testing.T) {
	t.Parallel()

	t.Run("resolver sees the verified claims and the access token names the local account", func(t *testing.T) {
		t.Parallel()
		f := newJBGFixture(t, jbgConfig{})
		assertion := f.idjagFor(t, func(c map[string]any) {
			c["email"] = ijgEmail
			c["scope"] = "read"
		})

		at := f.expectOK(t, f.post(t, jbgReq{assertion: assertion}))

		got := f.lastResolved(t)
		if got.Issuer != jbgJAGIss || got.Subject != "alice" || got.ClientID != jbgBasic {
			t.Errorf("AssertionSubject = {%s %s %s}, want {%s alice %s}", got.Issuer, got.Subject, got.ClientID, jbgJAGIss, jbgBasic)
		}
		if got.Claims["email"] != ijgEmail || got.Claims["client_id"] != jbgBasic {
			t.Errorf("Claims = %v, want email and client_id from the ID-JAG", got.Claims)
		}
		if at["sub"] != jbgUser {
			t.Errorf("sub = %v, want %s", at["sub"], jbgUser)
		}
		granted := f.audit.records("jwt_bearer.granted")
		if len(granted) != 1 {
			t.Fatalf("jwt_bearer.granted records = %d, want 1", len(granted))
		}
		extras, _ := granted[0]["extras"].(map[string]any)
		if extras["profile"] != "id-jag" || extras["issuer"] != jbgJAGIss {
			t.Errorf("jwt_bearer.granted extras = %v, want profile id-jag from %s", extras, jbgJAGIss)
		}
	})

	t.Run("an unprovisioned subject is access_denied", func(t *testing.T) {
		t.Parallel()
		f := newJBGFixture(t, jbgConfig{})
		assertion := f.sign(t, f.idjagClaims("stranger", jbgBasic), "oauth-id-jag+jwt")
		f.expectError(t, f.post(t, jbgReq{assertion: assertion}), http.StatusBadRequest, "access_denied", "unknown_subject")
	})
}

func TestScenario_IDJAG_009_UnauthenticatedClientRefused(t *testing.T) {
	t.Parallel()
	f := newJBGFixture(t, jbgConfig{})
	key := newDPoPKey(t)

	// The ID-JAG is bound to the key the request proves, but a public client
	// still gets no token: the binding is not a substitute for authentication.
	assertion := f.sign(t, func() map[string]any {
		c := f.idjagClaims("alice", jbgPublic)
		c["cnf"] = map[string]any{"jkt": key.jkt}
		return c
	}(), "oauth-id-jag+jwt")
	resp := f.post(t, jbgReq{client: jbgPublic, assertion: assertion, dpop: &key})
	f.expectError(t, resp, http.StatusBadRequest, "unauthorized_client", "public_client")
}

// ---------------------------------------------------------------------
// IdP half: issuance through token exchange.
// ---------------------------------------------------------------------

func TestScenario_IDJAG_010_IssuedAssertionClaims(t *testing.T) {
	t.Parallel()
	idp := newIJGIdP(t, ijgIDPConfig{})

	x := ijgDefaultExchange()
	x.scope = "chat.read chat.history"
	x.resource = []string{ijgRASAPI}
	resp := idp.issue(t, x)
	token, _ := resp.body["access_token"].(string)

	header := ijgHeader(t, token)
	if header["typ"] != "oauth-id-jag+jwt" || header["alg"] != "ES256" {
		t.Errorf("header = %v, want typ oauth-id-jag+jwt, alg ES256", header)
	}
	ijgVerifyAgainstJWKS(t, idp.tk, token)

	c := scenariokit.DecodeJWSClaims(t, token)
	want := map[string]any{
		"iss":       ijgIDPIssuer,
		"sub":       idp.idClaims["sub"],
		"aud":       ijgRASIssuer,
		"client_id": ijgRASClient,
		"scope":     "chat.read chat.history",
		"resource":  ijgRASAPI,
		"email":     ijgEmail,
		"iat":       float64(jbgNow.Unix()),
		"exp":       float64(jbgNow.Add(5 * time.Minute).Unix()),
	}
	for k, v := range want {
		if c[k] != v {
			t.Errorf("claim %s = %v, want %v", k, c[k], v)
		}
	}
	if jti, _ := c["jti"].(string); jti == "" {
		t.Error("jti missing")
	}
	for _, name := range []string{"auth_time", "acr"} {
		if idp.idClaims[name] == nil {
			t.Fatalf("control: the ID token carries no %s to carry over", name)
		}
	}
	for _, name := range []string{"auth_time", "acr", "amr"} {
		if fmtJSON(c[name]) != fmtJSON(idp.idClaims[name]) {
			t.Errorf("claim %s = %v, want the ID token's %v", name, c[name], idp.idClaims[name])
		}
	}
	for _, absent := range []string{"cnf", "act", "azp", "nonce"} {
		if _, has := c[absent]; has {
			t.Errorf("claim %s = %v on an unbound ID-JAG", absent, c[absent])
		}
	}
}

func fmtJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestScenario_IDJAG_011_ResponseShapeAndBinding(t *testing.T) {
	t.Parallel()
	idp := newIJGIdP(t, ijgIDPConfig{})
	key := newDPoPKey(t)
	cert := mtlsCert(t)

	cases := []struct {
		name string
		dpop *dpopKey
		cert *x509.Certificate
		cnf  map[string]any
	}{
		{"unbound", nil, nil, nil},
		{"DPoP", &key, nil, map[string]any{"jkt": key.jkt}},
		{"mTLS", nil, cert, map[string]any{"x5t#S256": mtlsThumbprint(cert)}},
		{"both presented: one method", &key, cert, map[string]any{"jkt": key.jkt}},
	}
	for _, tc := range cases {
		x := ijgDefaultExchange()
		x.dpop, x.cert = tc.dpop, tc.cert
		resp := idp.issue(t, x)

		if resp.body["issued_token_type"] != ijgIDJAGType {
			t.Errorf("%s: issued_token_type = %v, want %s", tc.name, resp.body["issued_token_type"], ijgIDJAGType)
		}
		if resp.body["token_type"] != "N_A" {
			t.Errorf("%s: token_type = %v, want N_A", tc.name, resp.body["token_type"])
		}
		if resp.body["expires_in"] != float64(300) {
			t.Errorf("%s: expires_in = %v, want 300", tc.name, resp.body["expires_in"])
		}
		for _, absent := range []string{"refresh_token", "id_token"} {
			if _, has := resp.body[absent]; has {
				t.Errorf("%s: response carries %s", tc.name, absent)
			}
		}
		token, _ := resp.body["access_token"].(string)
		c := scenariokit.DecodeJWSClaims(t, token)
		cnf, _ := c["cnf"].(map[string]any)
		if fmtJSON(cnf) != fmtJSON(tc.cnf) && (tc.cnf != nil || len(cnf) != 0) {
			t.Errorf("%s: cnf = %v, want %v", tc.name, cnf, tc.cnf)
		}
	}
}

func TestScenario_IDJAG_012_LifetimeCappedAtFiveMinutes(t *testing.T) {
	t.Parallel()
	idp := newIJGIdP(t, ijgIDPConfig{})

	cases := []struct {
		stated time.Duration
		want   time.Duration
	}{
		{0, 5 * time.Minute},
		{2 * time.Minute, 2 * time.Minute},
		{10 * time.Minute, 5 * time.Minute},
	}
	for _, tc := range cases {
		idp.policy.set(func(req op.IDJAGRequest) (*op.IDJAGDecision, error) {
			return &op.IDJAGDecision{ClientID: ijgRASClient, Scope: req.Scope, TTL: tc.stated}, nil
		})
		resp := idp.issue(t, ijgDefaultExchange())
		token, _ := resp.body["access_token"].(string)
		c := scenariokit.DecodeJWSClaims(t, token)
		iat, _ := c["iat"].(float64)
		exp, _ := c["exp"].(float64)
		if got := time.Duration(exp-iat) * time.Second; got != tc.want {
			t.Errorf("stated %v: exp-iat = %v, want %v", tc.stated, got, tc.want)
		}
		if resp.body["expires_in"] != float64(tc.want/time.Second) {
			t.Errorf("stated %v: expires_in = %v, want %v", tc.stated, resp.body["expires_in"], float64(tc.want/time.Second))
		}
	}
}

func TestScenario_IDJAG_013_IssuanceRequestRefused(t *testing.T) {
	t.Parallel()
	idp := newIJGIdP(t, ijgIDPConfig{})
	other := idp.idTokenFor(t, ijgIDPOther)

	cases := []struct {
		name   string
		mutate func(x *ijgExchange)
		status int
		code   string
	}{
		{"requested_token_type absent", func(x *ijgExchange) { x.requested = nil }, http.StatusBadRequest, "invalid_request"},
		{"requested_token_type access_token", func(x *ijgExchange) { x.requested = []string{ijgATTokType} }, http.StatusBadRequest, "invalid_request"},
		{"audience absent", func(x *ijgExchange) { x.audience = nil }, http.StatusBadRequest, "invalid_request"},
		{"audience repeated", func(x *ijgExchange) { x.audience = []string{ijgRASIssuer, "https://other.testkit.invalid"} }, http.StatusBadRequest, "invalid_request"},
		{"actor_token present", func(x *ijgExchange) {
			x.extra = url.Values{"actor_token": {"x"}, "actor_token_type": {ijgATTokType}}
		}, http.StatusBadRequest, "invalid_request"},
		{"subject_token_type access_token", func(x *ijgExchange) { x.subjectType = ijgATTokType }, http.StatusBadRequest, "invalid_request"},
		{"id_token issued to another client", func(x *ijgExchange) { x.subjectToken = other }, http.StatusBadRequest, "invalid_grant"},
		{"public client", func(x *ijgExchange) { x.client = ijgIDPPublic }, http.StatusUnauthorized, "invalid_client"},
	}
	for _, tc := range cases {
		before := idp.policy.calls()
		x := ijgDefaultExchange()
		tc.mutate(&x)
		resp := idp.exchange(t, x)
		if resp.status != tc.status || resp.errCode() != tc.code {
			t.Errorf("%s: status=%d body=%v, want %d %s", tc.name, resp.status, resp.body, tc.status, tc.code)
		}
		if got := idp.policy.calls(); got != before {
			t.Errorf("%s: the issuance policy ran for a refused request", tc.name)
		}
	}

	t.Run("an ID-JAG is not accepted back as an id_token", func(t *testing.T) {
		t.Parallel()
		resp := idp.issue(t, ijgDefaultExchange())
		idjag, _ := resp.body["access_token"].(string)
		x := ijgDefaultExchange()
		x.subjectToken = idjag
		got := idp.exchange(t, x)
		if got.status != http.StatusBadRequest || got.errCode() != "invalid_grant" {
			t.Errorf("status=%d body=%v, want 400 invalid_grant", got.status, got.body)
		}
	})
}

func TestScenario_IDJAG_014_PolicyOutcomesMapToErrors(t *testing.T) {
	t.Parallel()
	idp := newIJGIdP(t, ijgIDPConfig{})

	cases := []struct {
		name     string
		resource []string
		decide   func(op.IDJAGRequest) (*op.IDJAGDecision, error)
		status   int
		code     string
	}{
		{
			"unknown audience", nil, func(op.IDJAGRequest) (*op.IDJAGDecision, error) { return nil, op.ErrIDJAGUnknownAudience },
			http.StatusBadRequest, "invalid_target",
		},
		{
			"denied", nil, func(op.IDJAGRequest) (*op.IDJAGDecision, error) { return nil, op.ErrIDJAGDenied },
			http.StatusBadRequest, "access_denied",
		},
		{"nil decision", nil, func(op.IDJAGRequest) (*op.IDJAGDecision, error) { return nil, nil }, //nolint:nilnil // the case under test.
			http.StatusBadRequest, "access_denied"},
		{
			"other error", nil, func(op.IDJAGRequest) (*op.IDJAGDecision, error) { return nil, errors.New("directory down") },
			http.StatusInternalServerError, "server_error",
		},
		{
			"decision without client_id", nil, func(op.IDJAGRequest) (*op.IDJAGDecision, error) { return &op.IDJAGDecision{}, nil },
			http.StatusInternalServerError, "server_error",
		},
		{"resource granted that was not requested", nil, func(op.IDJAGRequest) (*op.IDJAGDecision, error) {
			return &op.IDJAGDecision{ClientID: ijgRASClient, Resource: []string{ijgRASAPI}}, nil
		}, http.StatusInternalServerError, "server_error"},
		{"resource requested, none granted", []string{ijgRASAPI}, func(op.IDJAGRequest) (*op.IDJAGDecision, error) {
			return &op.IDJAGDecision{ClientID: ijgRASClient}, nil
		}, http.StatusBadRequest, "invalid_target"},
	}
	for _, tc := range cases {
		idp.policy.set(tc.decide)
		x := ijgDefaultExchange()
		x.resource = tc.resource
		resp := idp.exchange(t, x)
		if resp.status != tc.status || resp.errCode() != tc.code {
			t.Errorf("%s: status=%d body=%v, want %d %s", tc.name, resp.status, resp.body, tc.status, tc.code)
		}
	}
}

func TestScenario_IDJAG_015_RASNamespaceNeedsNoIdPRegistration(t *testing.T) {
	t.Parallel()
	idp := newIJGIdP(t, ijgIDPConfig{})

	// idp-rp is registered for openid and profile only; the scope and the
	// resources below exist solely at the resource AS.
	x := ijgDefaultExchange()
	x.scope = "chat.read chat.history"
	x.resource = []string{ijgRASAPI, ijgRASAPITwo}
	resp := idp.issue(t, x)
	token, _ := resp.body["access_token"].(string)
	c := scenariokit.DecodeJWSClaims(t, token)

	if c["scope"] != "chat.read chat.history" {
		t.Errorf("scope = %v, want the requested RAS scope uncut", c["scope"])
	}
	if fmtJSON(c["resource"]) != fmtJSON([]string{ijgRASAPI, ijgRASAPITwo}) {
		t.Errorf("resource = %v, want both requested values verbatim", c["resource"])
	}
	idp.policy.mu.Lock()
	seen := idp.policy.seen[len(idp.policy.seen)-1]
	idp.policy.mu.Unlock()
	if !slices.Equal(seen.Scope, []string{"chat.read", "chat.history"}) || !slices.Equal(seen.Resource, []string{ijgRASAPI, ijgRASAPITwo}) {
		t.Errorf("policy saw scope=%v resource=%v, want the request uncut", seen.Scope, seen.Resource)
	}
	if seen.Audience != ijgRASIssuer || seen.Client == nil || seen.Client.ID != ijgIDPClient {
		t.Errorf("policy saw audience=%q client=%v, want %s / %s", seen.Audience, seen.Client, ijgRASIssuer, ijgIDPClient)
	}
}

func TestScenario_IDJAG_016_IdPToResourceASRoundTrip(t *testing.T) {
	t.Parallel()
	idp := newIJGIdP(t, ijgIDPConfig{})
	ras := newIJGRAS(t, idp, ijgRASIssuer, op.AssertionProfileIDJAG)

	x := ijgDefaultExchange()
	x.scope = "chat.read"
	x.resource = []string{ijgRASAPI}
	resp := idp.issue(t, x)
	idjag, _ := resp.body["access_token"].(string)

	redeemed := ras.redeem(t, idjag, url.Values{"scope": {"chat.read"}})
	if redeemed.status != http.StatusOK {
		t.Fatalf("redemption status=%d body=%v, want 200", redeemed.status, redeemed.body)
	}
	for _, absent := range []string{"refresh_token", "id_token"} {
		if _, has := redeemed.body[absent]; has {
			t.Errorf("redemption carries %s", absent)
		}
	}
	at := scenariokit.DecodeJWSClaims(t, redeemed.body["access_token"].(string))
	if at["sub"] != ijgRASSubject || at["iss"] != ijgRASIssuer || at["client_id"] != ijgRASClient || at["scope"] != "chat.read" {
		t.Errorf("access token sub=%v iss=%v client_id=%v scope=%v, want %s / %s / %s / chat.read",
			at["sub"], at["iss"], at["client_id"], at["scope"], ijgRASSubject, ijgRASIssuer, ijgRASClient)
	}
	if aud := jbgAudience(at["aud"]); !slices.Equal(aud, []string{ijgRASAPI}) {
		t.Errorf("aud = %v, want the ID-JAG's resource [%s]", aud, ijgRASAPI)
	}
	ras.mu.Lock()
	got := ras.resolved[len(ras.resolved)-1]
	ras.mu.Unlock()
	if got.Issuer != ijgIDPIssuer || got.Subject != idp.idClaims["sub"] || got.Claims["email"] != ijgEmail {
		t.Errorf("AssertionSubject = {%s %s} email=%v, want the IdP's issuer, the ID token sub and %s", got.Issuer, got.Subject, got.Claims["email"], ijgEmail)
	}

	replay := ras.redeem(t, idjag, nil)
	if replay.status != http.StatusBadRequest || replay.errCode() != "invalid_grant" {
		t.Errorf("replayed ID-JAG status=%d body=%v, want 400 invalid_grant", replay.status, replay.body)
	}

	t.Run("a plain-profile AS refuses it on type", func(t *testing.T) {
		t.Parallel()
		plain := newIJGRAS(t, idp, ijgRASPlain, op.AssertionProfileJWT)
		fresh, _ := idp.issue(t, ijgDefaultExchange()).body["access_token"].(string)
		// The plain AS's issuer differs from the ID-JAG's audience, so the
		// type check, which runs first, is what refuses it.
		got := plain.redeem(t, fresh, nil)
		if got.status != http.StatusBadRequest || got.errCode() != "invalid_grant" {
			t.Errorf("status=%d body=%v, want 400 invalid_grant", got.status, got.body)
		}
		if reasons := plain.audit.rejectedReasons(); !slices.Equal(reasons, []string{"typ"}) {
			t.Errorf("jwt_bearer.rejected reasons = %v, want [typ]", reasons)
		}
	})

	t.Run("an ID token is not a grant at the ID-JAG AS", func(t *testing.T) {
		t.Parallel()
		other := newIJGRAS(t, idp, "https://ras-third.testkit.invalid", op.AssertionProfileIDJAG)
		got := other.redeem(t, idp.idToken, nil)
		if got.status != http.StatusBadRequest || got.errCode() != "invalid_grant" {
			t.Errorf("status=%d body=%v, want 400 invalid_grant", got.status, got.body)
		}
		if reasons := other.audit.rejectedReasons(); !slices.Equal(reasons, []string{"typ"}) {
			t.Errorf("jwt_bearer.rejected reasons = %v, want [typ]", reasons)
		}
	})
}

func TestScenario_IDJAG_017_PairwiseSubjectIsNotVouchedFor(t *testing.T) {
	t.Parallel()
	idp := newIJGIdP(t, ijgIDPConfig{pairwise: true})
	pairwiseToken := idp.idTokenFor(t, ijgIDPPair)

	// The pairwise id_token names a sub the IdP's grant records do not hold,
	// so the exchange fails instead of handing the RAS an ID-JAG sub.
	x := ijgDefaultExchange()
	x.client, x.subjectToken = ijgIDPPair, pairwiseToken
	resp := idp.exchange(t, x)
	if resp.status != http.StatusBadRequest || resp.errCode() != "invalid_grant" {
		t.Fatalf("status=%d body=%v, want 400 invalid_grant", resp.status, resp.body)
	}
	if _, has := resp.body["access_token"]; has {
		t.Error("an ID-JAG was issued for a pairwise client")
	}

	// A public-subject client of the same IdP still gets one.
	idp.issue(t, ijgDefaultExchange())
}

func TestScenario_IDJAG_018_DiscoveryAdvertisement(t *testing.T) {
	t.Parallel()

	t.Run("issuance configured", func(t *testing.T) {
		t.Parallel()
		idp := newIJGIdP(t, ijgIDPConfig{})
		doc := jbgDiscovery(t, idp.tk)
		if !jbgListed(doc, "identity_chaining_requested_token_types_supported", ijgIDJAGType) {
			t.Errorf("identity_chaining_requested_token_types_supported = %v, want %s", doc["identity_chaining_requested_token_types_supported"], ijgIDJAGType)
		}
		if !jbgListed(doc, "grant_types_supported", op.TokenExchangeGrantType) {
			t.Errorf("grant_types_supported = %v, want token-exchange with only ID-JAG issuance configured", doc["grant_types_supported"])
		}
		if _, has := doc["id_jag_signing_alg_values_supported"]; has {
			t.Errorf("id_jag_signing_alg_values_supported = %v, want absent", doc["id_jag_signing_alg_values_supported"])
		}
	})

	t.Run("issuance not configured", func(t *testing.T) {
		t.Parallel()
		idp := newIJGIdP(t, ijgIDPConfig{accessTokenExchangeOnly: true})
		doc := jbgDiscovery(t, idp.tk)
		if _, has := doc["identity_chaining_requested_token_types_supported"]; has {
			t.Errorf("identity_chaining_requested_token_types_supported = %v, want absent", doc["identity_chaining_requested_token_types_supported"])
		}
	})

	t.Run("resource AS: profile advertised only with an ID-JAG issuer", func(t *testing.T) {
		t.Parallel()
		idp := newIJGIdP(t, ijgIDPConfig{})
		withJAG := newIJGRAS(t, idp, ijgRASIssuer, op.AssertionProfileIDJAG)
		if !jbgListed(jbgDiscovery(t, withJAG.tk), "authorization_grant_profiles_supported", ijgProfile) {
			t.Error("authorization_grant_profiles_supported lacks the id-jag profile")
		}
		plain := newIJGRAS(t, idp, ijgRASPlain, op.AssertionProfileJWT)
		if v, has := jbgDiscovery(t, plain.tk)["authorization_grant_profiles_supported"]; has {
			t.Errorf("authorization_grant_profiles_supported = %v, want absent", v)
		}
	})
}

func TestScenario_IDJAG_019_RequestWithoutIssuanceKeepsRFC8693Behaviour(t *testing.T) {
	t.Parallel()
	idp := newIJGIdP(t, ijgIDPConfig{accessTokenExchangeOnly: true})

	resp := idp.exchange(t, ijgDefaultExchange())
	if resp.status != http.StatusBadRequest || resp.errCode() != "invalid_request" {
		t.Errorf("status=%d body=%v, want 400 invalid_request without WithIDJAGIssuance", resp.status, resp.body)
	}
	if got := idp.audit.records("token_exchange.idjag_issued"); len(got) != 0 {
		t.Errorf("token_exchange.idjag_issued records = %d, want 0", len(got))
	}
}

func TestScenario_IDJAG_020_IssuanceAudit(t *testing.T) {
	t.Parallel()
	idp := newIJGIdP(t, ijgIDPConfig{})

	x := ijgDefaultExchange()
	x.audience = []string{"https://unknown-ras.testkit.invalid"}
	if resp := idp.exchange(t, x); resp.errCode() != "invalid_target" {
		t.Fatalf("control: unknown audience body=%v, want invalid_target", resp.body)
	}
	if got := idp.audit.records("token_exchange.idjag_issued"); len(got) != 0 {
		t.Fatalf("token_exchange.idjag_issued records after a refusal = %d, want 0", len(got))
	}

	idp.issue(t, ijgDefaultExchange())
	got := idp.audit.records("token_exchange.idjag_issued")
	if len(got) != 1 {
		t.Fatalf("token_exchange.idjag_issued records = %d, want 1", len(got))
	}
	if got[0]["client_id"] != ijgIDPClient {
		t.Errorf("client_id = %v, want %s", got[0]["client_id"], ijgIDPClient)
	}
}

// TestScenario_IDJAG_021_CombinationCoverage runs the ID-JAG-profile rows of
// the combination set defined with the jwt-bearer scenarios.
func TestScenario_IDJAG_021_CombinationCoverage(t *testing.T) {
	t.Parallel()
	assertJBGCombosCoverAllPairs(t)

	for _, c := range jbgCombos {
		if !c.idjag {
			continue
		}
		t.Run(c.id+"/"+c.profile()+"/"+c.auth(), func(t *testing.T) {
			t.Parallel()
			c.run(t)
		})
	}
}

// TestScenario_IDJAG_022_RS256SignedIDJAG checks that an OP configured for
// RS256 issues an RS256 ID-JAG whose kid resolves to an RS256 JWKS entry,
// and that a resource AS trusting those keys redeems it. The ES256 OP is
// run alongside as the control.
//
// Spec: draft-ietf-oauth-identity-assertion-authz-grant-06 §3.
func TestScenario_IDJAG_022_RS256SignedIDJAG(t *testing.T) {
	t.Parallel()
	for _, alg := range sigAlgBoth {
		t.Run(string(alg), func(t *testing.T) {
			t.Parallel()
			sigAlgAssertIDJAGRedeemed(t, alg)
		})
	}
}
