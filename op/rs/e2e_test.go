package rs_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/rs"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

const (
	opaqueAudience = "https://rs.example.com/opaque"

	appClientID = "rs-e2e-app"
	//nolint:gosec // test fixture secret, not a credential.
	appSecret = "rs-e2e-app-secret"

	introspectorID = "rs-e2e-introspector"
	//nolint:gosec // test fixture secret, not a credential.
	introspectorSecret = "rs-e2e-introspector-secret"
)

// opServer is a real OP built with op.New and served over TLS by
// httptest. Its issuer is the server's own URL, so discovery, the JWK Set
// and introspection are all reached the way a deployed resource server
// reaches them.
type opServer struct {
	issuer string
	srv    *httptest.Server
	clock  *testClock
}

// startOP boots the OP. The issuance options under test:
//
//   - op.WithFeature(feature.DPoP): a token request carrying a DPoP proof
//     gets a token bound to the proof key (cnf.jkt).
//   - op.WithFeature(feature.MTLS): a token request over a TLS connection
//     presenting a client certificate gets a token bound to that
//     certificate (cnf.x5t#S256). The server requests, without verifying,
//     a client certificate so the token endpoint sees it.
//   - op.WithFeature(feature.Introspect),
//     op.WithAccessTokenFormatPerAudience and op.WithProtectedResources:
//     tokens for opaqueAudience are opaque, and introspectorID may
//     introspect them.
func startOP(t *testing.T) *opServer {
	t.Helper()
	clock := newTestClock()
	var provider atomic.Pointer[op.Provider]
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := provider.Load()
		if p == nil {
			http.Error(w, "provider not ready", http.StatusServiceUnavailable)
			return
		}
		p.ServeHTTP(w, r)
	}))
	srv.TLS = &tls.Config{ClientAuth: tls.RequestClientCert, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	st := inmem.New(inmem.WithClock(clock))
	p, err := op.New(
		op.WithIssuer(srv.URL),
		op.WithStore(st),
		op.WithKeyset(op.Keyset{testkit.NewSigningKey(t, "rs-e2e")}),
		op.WithCookieKeys(testkit.NewCookieKey(t)),
		op.WithClock(clock),
		op.WithGrants(grant.ClientCredentials),
		op.WithFeature(feature.DPoP),
		op.WithFeature(feature.MTLS),
		op.WithFeature(feature.Introspect),
		op.WithAccessTokenFormatPerAudience(map[string]store.AccessTokenFormat{opaqueAudience: op.AccessTokenFormatOpaque}),
		op.WithProtectedResources(op.ProtectedResource{Resource: opaqueAudience, IntrospectionClients: []string{introspectorID}}),
	)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	provider.Store(p)

	registerClient(t, st, appClientID, appSecret, []string{testAudience, opaqueAudience})
	registerClient(t, st, introspectorID, introspectorSecret, nil)
	return &opServer{issuer: srv.URL, srv: srv, clock: clock}
}

func registerClient(t *testing.T, st *inmem.Store, id, secret string, resources []string) {
	t.Helper()
	hash, err := op.HashClientSecret(secret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	err = st.RegisterClient(context.Background(), &store.Client{
		ID:                      id,
		SecretHash:              hash,
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"client_credentials"},
		Scopes:                  []string{"read", "write"},
		Resources:               resources,
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	if err != nil {
		t.Fatalf("RegisterClient(%s): %v", id, err)
	}
}

// issue runs client_credentials for resource and returns the access
// token and token_type. A non-nil proofKey adds a DPoP proof; a non-nil
// cert is presented on the TLS connection.
func (o *opServer) issue(t *testing.T, resource string, key *proofKey, cert *clientCert) (token, tokenType string) {
	t.Helper()
	client := o.srv.Client()
	if cert != nil {
		base, ok := client.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("httptest client transport is %T", client.Transport)
		}
		tr := base.Clone()
		tr.TLSClientConfig.Certificates = []tls.Certificate{{
			Certificate: [][]byte{cert.cert.Raw},
			PrivateKey:  cert.key,
			Leaf:        cert.cert,
		}}
		t.Cleanup(tr.CloseIdleConnections)
		client = &http.Client{Transport: tr}
	}
	endpoint := o.issuer + "/oidc/token"
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"read write"}, "resource": {resource}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(appClientID, appSecret)
	if key != nil {
		req.Header.Set("DPoP", key.proof(t, http.MethodPost, endpoint, o.clock.Now(), ""))
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read token response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token endpoint status %d: %s", resp.StatusCode, body)
	}
	var out struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	return out.AccessToken, out.TokenType
}

// verifier builds a resource-server verifier that discovers everything
// from the OP's issuer.
func (o *opServer) verifier(t *testing.T, audience string, mutate ...func(*rs.Config)) *rs.Verifier {
	t.Helper()
	cfg := rs.Config{
		Issuer:              o.issuer,
		Audience:            audience,
		HTTPClient:          o.srv.Client(),
		AllowPrivateNetwork: true,
		Clock:               o.clock,
	}
	for _, m := range mutate {
		m(&cfg)
	}
	v, err := rs.New(cfg)
	if err != nil {
		t.Fatalf("rs.New: %v", err)
	}
	return v
}

func withIntrospection(c *rs.Config) {
	c.Introspection = &rs.IntrospectionConfig{ClientID: introspectorID, ClientSecret: introspectorSecret}
}

// TestEndToEnd_RS_JWT: a JWT access token the OP issued verifies through
// discovery and the OP's JWK Set, and the middleware enforces scope.
func TestEndToEnd_RS_JWT(t *testing.T) {
	t.Parallel()

	o := startOP(t)
	raw, tokenType := o.issue(t, testAudience, nil, nil)
	if tokenType != "Bearer" {
		t.Fatalf("token_type = %q, want Bearer", tokenType)
	}
	v := o.verifier(t, testAudience)

	h := v.Middleware(rs.RequireScope("read"))(okHandler())
	rec := serve(t, h, newRequest(t, "Bearer", raw))
	if rec.Code != http.StatusOK || rec.Body.String() != appClientID {
		t.Fatalf("status=%d body=%q, want 200 %s", rec.Code, rec.Body.String(), appClientID)
	}

	tok := mustVerify(t, v, newRequest(t, "Bearer", raw))
	if tok.ClientID != appClientID || !slices.Equal(tok.Scopes, []string{"read", "write"}) {
		t.Errorf("client_id=%q scopes=%v", tok.ClientID, tok.Scopes)
	}

	h = v.Middleware(rs.RequireScope("admin"))(okHandler())
	wantRejected(t, serve(t, h, newRequest(t, "Bearer", raw)), http.StatusForbidden)

	// The same token is not accepted by a resource it was not issued for.
	_, err := o.verifier(t, "https://rs.example.com/elsewhere").Verify(newRequest(t, "Bearer", raw))
	wantError(t, err, http.StatusUnauthorized, "invalid_token")
}

// TestEndToEnd_RS_DPoP: a DPoP-bound JWT verifies with a proof from the
// bound key, and is refused under the Bearer scheme or with a replayed
// proof.
func TestEndToEnd_RS_DPoP(t *testing.T) {
	t.Parallel()

	o := startOP(t)
	key := newProofKey(t, "ES256")
	raw, tokenType := o.issue(t, testAudience, &key, nil)
	if tokenType != "DPoP" {
		t.Fatalf("token_type = %q, want DPoP", tokenType)
	}
	v := o.verifier(t, testAudience, func(c *rs.Config) { c.DPoP = rs.DPoPRequired })
	h := v.Middleware()(okHandler())

	proof := key.proof(t, http.MethodGet, resourceURL, o.clock.Now(), raw)
	req := newRequest(t, "DPoP", raw)
	req.Header.Set("DPoP", proof)
	tok := mustVerify(t, v, req)
	if tok.Binding.JKT != key.jkt {
		t.Errorf("Binding.JKT = %q, want %q", tok.Binding.JKT, key.jkt)
	}

	replay := newRequest(t, "DPoP", raw)
	replay.Header.Set("DPoP", proof)
	got := wantRejected(t, serve(t, h, replay), http.StatusUnauthorized)
	if !strings.Contains(got, `error="invalid_dpop_proof"`) {
		t.Errorf("replay challenge = %q, want invalid_dpop_proof", got)
	}

	asBearer := newRequest(t, "Bearer", raw)
	asBearer.Header.Set("DPoP", key.proof(t, http.MethodGet, resourceURL, o.clock.Now(), raw))
	got = wantRejected(t, serve(t, h, asBearer), http.StatusUnauthorized)
	if !strings.Contains(got, `error="invalid_token"`) {
		t.Errorf("bearer-downgrade challenge = %q, want invalid_token", got)
	}
}

// TestEndToEnd_RS_MTLS: a token issued over a connection presenting a
// client certificate is accepted only when the same certificate is
// presented to the resource server.
func TestEndToEnd_RS_MTLS(t *testing.T) {
	t.Parallel()

	o := startOP(t)
	ca := newTestCA(t)
	bound := ca.issue(t, "rs-e2e-app")
	raw, _ := o.issue(t, testAudience, nil, &bound)
	v := o.verifier(t, testAudience)

	present := func(cert *x509.Certificate) *http.Request {
		req := newRequest(t, "Bearer", raw)
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
		return req
	}
	tok := mustVerify(t, v, present(bound.cert))
	if tok.Binding.CertThumbprint != thumbprint(bound.cert) {
		t.Fatalf("Binding.CertThumbprint = %q, want the presented certificate's", tok.Binding.CertThumbprint)
	}

	_, err := v.Verify(present(ca.issue(t, "intruder").cert))
	wantError(t, err, http.StatusUnauthorized, "invalid_token")

	_, err = v.Verify(newRequest(t, "Bearer", raw))
	wantError(t, err, http.StatusUnauthorized, "invalid_token")
}

// TestEndToEnd_RS_OpaqueIntrospection: an opaque token verifies through
// the OP's introspection endpoint, which answers because the resource
// server's client is listed in the ProtectedResource's
// IntrospectionClients.
func TestEndToEnd_RS_OpaqueIntrospection(t *testing.T) {
	t.Parallel()

	o := startOP(t)
	raw, _ := o.issue(t, opaqueAudience, nil, nil)
	if strings.Count(raw, ".") == 2 {
		t.Fatalf("token for %s looks like a JWT; the OP should issue it opaque", opaqueAudience)
	}
	v := o.verifier(t, opaqueAudience, withIntrospection)

	tok := mustVerify(t, v, newRequest(t, "Bearer", raw))
	if tok.Subject != appClientID || tok.ClientID != appClientID {
		t.Errorf("sub=%q client_id=%q, want %s", tok.Subject, tok.ClientID, appClientID)
	}
	if !slices.Equal(tok.Scopes, []string{"read", "write"}) {
		t.Errorf("Scopes = %v", tok.Scopes)
	}
	if active, _ := tok.Claims["active"].(bool); !active {
		t.Errorf("Claims[active] = %v", tok.Claims["active"])
	}

	_, err := v.Verify(newRequest(t, "Bearer", "unknown-opaque-token"))
	wantError(t, err, http.StatusUnauthorized, "invalid_token")

	// Without introspection the verifier cannot judge an opaque token.
	_, err = o.verifier(t, opaqueAudience).Verify(newRequest(t, "Bearer", raw))
	wantError(t, err, http.StatusUnauthorized, "invalid_token")
}

// TestVerifier_IntrospectedDPoPBoundTokenAsBearer: the cnf of an
// introspection response is enforced like a JWT's, so a DPoP-bound opaque
// token presented as Bearer is refused rather than downgraded.
func TestVerifier_IntrospectedDPoPBoundTokenAsBearer(t *testing.T) {
	t.Parallel()

	o := startOP(t)
	key := newProofKey(t, "ES256")
	raw, tokenType := o.issue(t, opaqueAudience, &key, nil)
	if tokenType != "DPoP" {
		t.Fatalf("token_type = %q, want DPoP", tokenType)
	}
	v := o.verifier(t, opaqueAudience, withIntrospection)

	_, err := v.Verify(newRequest(t, "Bearer", raw))
	wantError(t, err, http.StatusUnauthorized, "invalid_token")

	req := newRequest(t, "DPoP", raw)
	req.Header.Set("DPoP", key.proof(t, http.MethodGet, resourceURL, o.clock.Now(), raw))
	if tok := mustVerify(t, v, req); tok.Binding.JKT != key.jkt {
		t.Errorf("Binding.JKT = %q, want %q", tok.Binding.JKT, key.jkt)
	}
}
