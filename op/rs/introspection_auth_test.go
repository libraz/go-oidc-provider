package rs_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/profile"
	"github.com/libraz/go-oidc-provider/op/rs"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

const clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

func TestVerifier_NewRejectsIntrospectionAuthConfig(t *testing.T) {
	t.Parallel()

	ecKey := newECKey(t, elliptic.P256())
	cert := newTestCA(t).issue(t, "rs")
	tlsCert := &tls.Certificate{Certificate: [][]byte{cert.cert.Raw}, PrivateKey: cert.key}
	base := func(in rs.IntrospectionConfig) rs.Config {
		in.Endpoint = "https://issuer.example.com/introspect"
		in.ClientID = "rs"
		return rs.Config{Issuer: testIssuer, Audience: testAudience, JWKSURI: "https://issuer.example.com/jwks", Introspection: &in}
	}
	cases := []struct {
		name string
		in   rs.IntrospectionConfig
		ok   bool
	}{
		{"no method", rs.IntrospectionConfig{}, false},
		{"secret and private key", rs.IntrospectionConfig{ClientSecret: "s", PrivateKey: ecKey, KeyID: "k"}, false},
		{"secret and certificate", rs.IntrospectionConfig{ClientSecret: "s", TLSCertificate: tlsCert}, false},
		{"private key and certificate", rs.IntrospectionConfig{PrivateKey: ecKey, KeyID: "k", TLSCertificate: tlsCert}, false},
		{"private key without key id", rs.IntrospectionConfig{PrivateKey: ecKey}, false},
		{"P-384 private key", rs.IntrospectionConfig{PrivateKey: newECKey(t, elliptic.P384()), KeyID: "k"}, false},
		{"typed nil private key", rs.IntrospectionConfig{PrivateKey: (*ecdsa.PrivateKey)(nil), KeyID: "k"}, false},
		{"certificate without key", rs.IntrospectionConfig{TLSCertificate: &tls.Certificate{Certificate: [][]byte{cert.cert.Raw}}}, false},
		{"secret", rs.IntrospectionConfig{ClientSecret: "s"}, true},
		{"private key", rs.IntrospectionConfig{PrivateKey: ecKey, KeyID: "k"}, true},
		{"certificate", rs.IntrospectionConfig{TLSCertificate: tlsCert}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := rs.New(base(tc.in))
			if (err == nil) != tc.ok {
				t.Fatalf("rs.New: err=%v, want ok=%v", err, tc.ok)
			}
		})
	}
}

// introspectionServer is an issuer whose introspection answer the test
// builds per request, recording what each request carried.
type introspectionServer struct {
	srv    *httptest.Server
	answer func(r *http.Request) (contentType, body string)

	mu   sync.Mutex
	last *http.Request
	form url.Values
}

func newIntrospectionServer(t *testing.T, keys *keyServer) *introspectionServer {
	t.Helper()
	s := &introspectionServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q,"introspection_endpoint":%q}`, s.srv.URL, s.srv.URL+"/jwks", s.srv.URL+"/introspect")
	})
	mux.HandleFunc("/jwks", keys.srv.Config.Handler.ServeHTTP)
	mux.HandleFunc("/introspect", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		s.last, s.form = r, r.PostForm
		s.mu.Unlock()
		ct, body := s.answer(r)
		w.Header().Set("Content-Type", ct)
		_, _ = io.WriteString(w, body)
	})
	s.srv = httptest.NewTLSServer(mux)
	t.Cleanup(s.srv.Close)
	return s
}

func (s *introspectionServer) verifier(t *testing.T, clock *testClock, in rs.IntrospectionConfig) *rs.Verifier {
	t.Helper()
	in.ClientID = "rs"
	v, err := rs.New(rs.Config{
		Issuer:              s.srv.URL,
		Audience:            testAudience,
		HTTPClient:          s.srv.Client(),
		AllowPrivateNetwork: true,
		Clock:               clock,
		Introspection:       &in,
	})
	if err != nil {
		t.Fatalf("rs.New: %v", err)
	}
	return v
}

func (s *introspectionServer) request() (*http.Request, url.Values) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last, s.form
}

// activeResponse is an RFC 7662 answer for an active token issued by issuer.
func activeResponse(issuer string) map[string]any {
	return map[string]any{
		"active":    true,
		"iss":       issuer,
		"sub":       "user-1",
		"aud":       []string{testAudience},
		"client_id": "client-1",
		"scope":     "read",
		"iat":       testNow.Unix(),
		"exp":       testNow.Add(5 * time.Minute).Unix(),
	}
}

// introspectionJWT is an RFC 9701 envelope around activeResponse.
func introspectionJWT(issuer string, aud any) map[string]any {
	return map[string]any{
		"iss":                 issuer,
		"aud":                 aud,
		"iat":                 testNow.Unix(),
		"token_introspection": activeResponse(issuer),
	}
}

// TestVerifier_IntrospectionJWTResponse: an RFC 9701 response is accepted
// only with the introspection typ, a signature from the issuer's keys,
// this issuer and the introspecting client in aud; anything else is the
// server's fault, not the token's.
func TestVerifier_IntrospectionJWTResponse(t *testing.T) {
	t.Parallel()

	const jwtType = "application/token-introspection+jwt"
	stranger := newECKey(t, elliptic.P256())
	cases := []struct {
		name string
		sign func(f *fixture, issuer string) string
		ok   bool
	}{
		{"valid, aud string", func(f *fixture, iss string) string {
			return signJWS(t, josev4.ES256, f.key, primaryKID, "token-introspection+jwt", introspectionJWT(iss, "rs"))
		}, true},
		{"valid, aud array", func(f *fixture, iss string) string {
			return signJWS(t, josev4.ES256, f.key, primaryKID, "token-introspection+jwt", introspectionJWT(iss, []string{"other", "rs"}))
		}, true},
		{"wrong typ", func(f *fixture, iss string) string {
			return signJWS(t, josev4.ES256, f.key, primaryKID, "JWT", introspectionJWT(iss, "rs"))
		}, false},
		{"access token typ", func(f *fixture, iss string) string {
			return signJWS(t, josev4.ES256, f.key, primaryKID, "at+jwt", introspectionJWT(iss, "rs"))
		}, false},
		{"wrong aud", func(f *fixture, iss string) string {
			return signJWS(t, josev4.ES256, f.key, primaryKID, "token-introspection+jwt", introspectionJWT(iss, "someone-else"))
		}, false},
		{"wrong iss", func(f *fixture, _ string) string {
			return signJWS(t, josev4.ES256, f.key, primaryKID, "token-introspection+jwt", introspectionJWT("https://attacker.example.com", "rs"))
		}, false},
		{"bad signature", func(_ *fixture, iss string) string {
			return signJWS(t, josev4.ES256, stranger, primaryKID, "token-introspection+jwt", introspectionJWT(iss, "rs"))
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			s := newIntrospectionServer(t, f.ks)
			s.answer = func(*http.Request) (string, string) { return jwtType, tc.sign(f, s.srv.URL) }
			v := s.verifier(t, f.clock, rs.IntrospectionConfig{ClientSecret: "rs-secret"})

			tok, err := v.Verify(newRequest(t, "Bearer", "opaque-token"))
			if !tc.ok {
				wantError(t, err, http.StatusServiceUnavailable, "")
				return
			}
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if tok.Subject != "user-1" || tok.ClientID != "client-1" {
				t.Errorf("sub=%q client_id=%q", tok.Subject, tok.ClientID)
			}
			req, _ := s.request()
			if got := req.Header.Get("Accept"); !strings.HasPrefix(got, jwtType) {
				t.Errorf("Accept = %q, want the JWT media type first", got)
			}
		})
	}
}

// TestVerifier_IntrospectionJWTInactive: an inactive answer inside a JWT
// is invalid_token, exactly as in JSON.
func TestVerifier_IntrospectionJWTInactive(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	s := newIntrospectionServer(t, f.ks)
	s.answer = func(*http.Request) (string, string) {
		claims := map[string]any{"iss": s.srv.URL, "aud": "rs", "iat": testNow.Unix(), "token_introspection": map[string]any{"active": false}}
		return "application/token-introspection+jwt", signJWS(t, josev4.ES256, f.key, primaryKID, "token-introspection+jwt", claims)
	}
	_, err := s.verifier(t, f.clock, rs.IntrospectionConfig{ClientSecret: "rs-secret"}).Verify(newRequest(t, "Bearer", "opaque-token"))
	wantError(t, err, http.StatusUnauthorized, "invalid_token")
}

// TestVerifier_IntrospectionPrivateKeyJWT: each request carries a fresh
// RFC 7523 assertion signed with the configured key, with the alg the key
// type implies and the issuer alone as audience.
func TestVerifier_IntrospectionPrivateKeyJWT(t *testing.T) {
	t.Parallel()

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	cases := []struct {
		alg string
		key crypto.Signer
	}{
		{"ES256", newECKey(t, elliptic.P256())},
		{"PS256", newRSAKey(t)},
		{"EdDSA", edKey},
	}
	for _, tc := range cases {
		t.Run(tc.alg, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			s := newIntrospectionServer(t, f.ks)
			s.answer = func(*http.Request) (string, string) {
				body, _ := json.Marshal(activeResponse(s.srv.URL))
				return "application/json", string(body)
			}
			v := s.verifier(t, f.clock, rs.IntrospectionConfig{PrivateKey: tc.key, KeyID: "rs-key"})
			mustVerify(t, v, newRequest(t, "Bearer", "opaque-token"))

			req, form := s.request()
			if req.Header.Get("Authorization") != "" {
				t.Error("private_key_jwt request also carried an Authorization header")
			}
			if form.Get("client_id") != "rs" || form.Get("client_assertion_type") != clientAssertionType {
				t.Fatalf("form = %v", form)
			}
			first := form.Get("client_assertion")
			jws, err := josev4.ParseSignedCompact(first, []josev4.SignatureAlgorithm{josev4.SignatureAlgorithm(tc.alg)})
			if err != nil {
				t.Fatalf("ParseSigned(%s): %v", tc.alg, err)
			}
			if kid := jws.Signatures[0].Header.KeyID; kid != "rs-key" {
				t.Errorf("kid = %q", kid)
			}
			payload, err := jws.Verify(tc.key.Public())
			if err != nil {
				t.Fatalf("assertion signature: %v", err)
			}
			var claims struct {
				Iss string `json:"iss"`
				Sub string `json:"sub"`
				Aud any    `json:"aud"`
				JTI string `json:"jti"`
				Iat int64  `json:"iat"`
				Exp int64  `json:"exp"`
			}
			if err := json.Unmarshal(payload, &claims); err != nil {
				t.Fatalf("assertion claims: %v", err)
			}
			if claims.Iss != "rs" || claims.Sub != "rs" || claims.Aud != s.srv.URL || claims.JTI == "" ||
				claims.Iat != testNow.Unix() || claims.Exp != testNow.Add(time.Minute).Unix() {
				t.Errorf("assertion claims = %+v", claims)
			}

			mustVerify(t, v, newRequest(t, "Bearer", "opaque-token"))
			if _, form = s.request(); form.Get("client_assertion") == first {
				t.Error("the second request reused the first client assertion")
			}
		})
	}
}

// TestVerifier_IntrospectionMTLS: the certificate is presented on the
// connection, client_id rides in the form, and the discovered mTLS alias
// is preferred over the plain introspection endpoint.
func TestVerifier_IntrospectionMTLS(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	answer := func(w http.ResponseWriter, issuer string) {
		body, _ := json.Marshal(activeResponse(issuer))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}

	var (
		issuer     *httptest.Server
		plainHits  atomic.Int32
		mu         sync.Mutex
		peer       *x509.Certificate
		form       url.Values
		authHeader string
	)
	aliasMux := http.NewServeMux()
	aliasMux.HandleFunc("/introspect", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		peer, form, authHeader = r.TLS.PeerCertificates[0], r.PostForm, r.Header.Get("Authorization")
		mu.Unlock()
		answer(w, issuer.URL)
	})
	alias := httptest.NewUnstartedServer(aliasMux)
	alias.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS12}
	alias.StartTLS()
	t.Cleanup(alias.Close)

	issuerMux := http.NewServeMux()
	issuerMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q,"introspection_endpoint":%q,"mtls_endpoint_aliases":{"introspection_endpoint":%q}}`,
			issuer.URL, issuer.URL+"/jwks", issuer.URL+"/introspect", alias.URL+"/introspect")
	})
	issuerMux.HandleFunc("/jwks", f.ks.srv.Config.Handler.ServeHTTP)
	issuerMux.HandleFunc("/introspect", func(w http.ResponseWriter, _ *http.Request) {
		plainHits.Add(1)
		answer(w, issuer.URL)
	})
	issuer = httptest.NewTLSServer(issuerMux)
	t.Cleanup(issuer.Close)

	cert := newTestCA(t).issue(t, "rs")
	v, err := rs.New(rs.Config{
		Issuer:              issuer.URL,
		Audience:            testAudience,
		HTTPClient:          issuer.Client(),
		AllowPrivateNetwork: true,
		Clock:               f.clock,
		Introspection: &rs.IntrospectionConfig{
			ClientID:       "rs",
			TLSCertificate: &tls.Certificate{Certificate: [][]byte{cert.cert.Raw}, PrivateKey: cert.key},
		},
	})
	if err != nil {
		t.Fatalf("rs.New: %v", err)
	}
	mustVerify(t, v, newRequest(t, "Bearer", "opaque-token"))

	mu.Lock()
	defer mu.Unlock()
	if peer == nil || !peer.Equal(cert.cert) {
		t.Fatal("the mTLS alias did not see the configured client certificate")
	}
	if form.Get("client_id") != "rs" || form.Get("client_assertion") != "" || authHeader != "" {
		t.Errorf("form=%v Authorization=%q, want client_id alone", form, authHeader)
	}
	if got := plainHits.Load(); got != 0 {
		t.Errorf("plain introspection_endpoint hit %d times, want 0", got)
	}
}

// fapiOP is a real OP under a FAPI 2.0 profile that issues opaque access
// tokens to fapiAppID and answers introspection for fapiIntrospectorID,
// both authenticating with private_key_jwt.
type fapiOP struct {
	*opServer
	appKey        *ecdsa.PrivateKey
	introspectKey *ecdsa.PrivateKey
	// introspectionType is the Content-Type of the last successful
	// introspection answer.
	introspectionType atomic.Value
}

// typeRecorder captures the Content-Type a handler answers with.
type typeRecorder struct {
	http.ResponseWriter
	status int
	ct     string
}

func (w *typeRecorder) WriteHeader(status int) {
	w.status, w.ct = status, w.Header().Get("Content-Type")
	w.ResponseWriter.WriteHeader(status)
}

const (
	fapiAppID          = "rs-fapi-app"
	fapiIntrospectorID = "rs-fapi-introspector"
	fapiKID            = "client-key"
	fapiDPoPNonce      = "rs-fapi-nonce"
)

// fixedNonce is a DPoP nonce source that issues and accepts one value, so
// a token request can carry the nonce without the use_dpop_nonce retry.
type fixedNonce struct{}

func (fixedNonce) IssueNonce() string         { return fapiDPoPNonce }
func (fixedNonce) Validate(nonce string) bool { return nonce == fapiDPoPNonce }

func startFAPIOP(t *testing.T, p profile.Profile) *fapiOP {
	t.Helper()
	clock := newTestClock()
	var provider atomic.Pointer[op.Provider]
	o := &fapiOP{appKey: newECKey(t, elliptic.P256()), introspectKey: newECKey(t, elliptic.P256())}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pr := provider.Load()
		if pr == nil {
			http.Error(w, "provider not ready", http.StatusServiceUnavailable)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/introspect") {
			pr.ServeHTTP(w, r)
			return
		}
		rec := &typeRecorder{ResponseWriter: w}
		pr.ServeHTTP(rec, r)
		if rec.status == http.StatusOK {
			o.introspectionType.Store(rec.ct)
		}
	}))
	t.Cleanup(srv.Close)

	st := inmem.New(inmem.WithClock(clock))
	pr, err := op.New(
		op.WithIssuer(srv.URL),
		op.WithStore(st),
		op.WithKeyset(op.Keyset{testkit.NewSigningKey(t, "rs-fapi")}),
		op.WithCookieKeys(testkit.NewCookieKey(t)),
		op.WithClock(clock),
		op.WithProfile(p),
		op.WithGrants(grant.ClientCredentials),
		op.WithFeature(feature.DPoP),
		op.WithDPoPNonceSource(fixedNonce{}),
		op.WithFeature(feature.Introspect),
		op.WithAccessTokenFormat(op.AccessTokenFormatOpaque),
		op.WithProtectedResources(op.ProtectedResource{Resource: opaqueAudience, IntrospectionClients: []string{fapiIntrospectorID}}),
	)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	provider.Store(pr)

	o.opServer = &opServer{issuer: srv.URL, srv: srv, clock: clock}
	registerKeyClient(t, st, fapiAppID, o.appKey, []string{opaqueAudience})
	registerKeyClient(t, st, fapiIntrospectorID, o.introspectKey, nil)
	return o
}

func registerKeyClient(t *testing.T, st *inmem.Store, id string, key *ecdsa.PrivateKey, resources []string) {
	t.Helper()
	jwks, err := json.Marshal(josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{publicJWK(t, key, fapiKID, "ES256")}})
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}
	err = st.RegisterClient(context.Background(), &store.Client{ //nolint:gosec // test fixture naming an auth method, not a credential.
		ID:                      id,
		JWKs:                    jwks,
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"client_credentials"},
		Scopes:                  []string{"read", "write"},
		Resources:               resources,
		TokenEndpointAuthMethod: "private_key_jwt",
	})
	if err != nil {
		t.Fatalf("RegisterClient(%s): %v", id, err)
	}
}

// issueOpaque runs client_credentials for opaqueAudience with a DPoP proof
// from key and returns the DPoP-bound opaque access token.
func (o *fapiOP) issueOpaque(t *testing.T, key proofKey) string {
	t.Helper()
	endpoint := o.issuer + "/oidc/token"
	now := o.clock.Now()
	assertion := signJWS(t, josev4.ES256, o.appKey, fapiKID, "", map[string]any{
		"iss": fapiAppID, "sub": fapiAppID, "aud": o.issuer, "jti": randomID(t),
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
	})
	form := url.Values{
		"grant_type":            {"client_credentials"},
		"scope":                 {"read write"},
		"resource":              {opaqueAudience},
		"client_id":             {fapiAppID},
		"client_assertion_type": {clientAssertionType},
		"client_assertion":      {assertion},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", key.proofWithNonce(t, http.MethodPost, endpoint, now, "", fapiDPoPNonce))
	resp, err := o.srv.Client().Do(req)
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
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if strings.Count(out.AccessToken, ".") == 2 {
		t.Fatal("the OP issued a JWT; the test needs an opaque token")
	}
	return out.AccessToken
}

// TestEndToEnd_RS_FAPI2Introspection: against an OP under each FAPI 2.0
// profile, a resource server authenticating with private_key_jwt verifies
// an opaque DPoP-bound token. Under Message Signing the OP always answers
// with an RFC 9701 JWT. A client_secret_basic request is refused by the
// OP, which the verifier reports as its own fault.
func TestEndToEnd_RS_FAPI2Introspection(t *testing.T) {
	t.Parallel()

	for _, p := range []profile.Profile{profile.FAPI2Baseline, profile.FAPI2MessageSigning} {
		t.Run(p.String(), func(t *testing.T) {
			t.Parallel()
			o := startFAPIOP(t, p)
			key := newProofKey(t, "ES256")
			raw := o.issueOpaque(t, key)

			v := o.verifier(t, opaqueAudience, func(c *rs.Config) {
				c.Introspection = &rs.IntrospectionConfig{ClientID: fapiIntrospectorID, PrivateKey: o.introspectKey, KeyID: fapiKID}
			})
			req := newRequest(t, "DPoP", raw)
			req.Header.Set("DPoP", key.proof(t, http.MethodGet, resourceURL, o.clock.Now(), raw))
			tok := mustVerify(t, v, req)
			if tok.ClientID != fapiAppID || tok.Binding.JKT != key.jkt {
				t.Errorf("client_id=%q jkt=%q", tok.ClientID, tok.Binding.JKT)
			}
			if p == profile.FAPI2MessageSigning {
				if ct, _ := o.introspectionType.Load().(string); ct != "application/token-introspection+jwt" {
					t.Errorf("introspection answered with %q, want the RFC 9701 JWT", ct)
				}
			}

			secret := o.verifier(t, opaqueAudience, func(c *rs.Config) {
				c.Introspection = &rs.IntrospectionConfig{ClientID: fapiIntrospectorID, ClientSecret: "not-accepted"}
			})
			req = newRequest(t, "DPoP", raw)
			req.Header.Set("DPoP", key.proof(t, http.MethodGet, resourceURL, o.clock.Now(), raw))
			_, err := secret.Verify(req)
			wantError(t, err, http.StatusServiceUnavailable, "")
		})
	}
}
