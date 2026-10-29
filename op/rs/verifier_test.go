package rs_test

import (
	"context"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/remotecache"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/rs"
)

func TestVerifier_NewRejectsInvalidConfig(t *testing.T) {
	t.Parallel()

	valid := func() rs.Config {
		return rs.Config{Issuer: testIssuer, Audience: testAudience, JWKSURI: "https://issuer.example.com/jwks"}
	}
	cases := []struct {
		name   string
		mutate func(*rs.Config)
	}{
		{"empty issuer", func(c *rs.Config) { c.Issuer = "" }},
		{"empty audience", func(c *rs.Config) { c.Audience = "" }},
		{"unknown dpop mode", func(c *rs.Config) { c.DPoP = rs.DPoPMode(7) }},
		{"introspection without secret", func(c *rs.Config) {
			c.Introspection = &rs.IntrospectionConfig{Endpoint: "https://issuer.example.com/introspect", ClientID: "rs"}
		}},
		{"introspection without client", func(c *rs.Config) {
			c.Introspection = &rs.IntrospectionConfig{Endpoint: "https://issuer.example.com/introspect", ClientSecret: "s"}
		}},
		{"mtls proxy header without trusted proxies", func(c *rs.Config) {
			c.MTLSProxy = &op.MTLSProxy{HeaderName: "X-Client-Cert"}
		}},
		{"plain http issuer used for discovery", func(c *rs.Config) {
			c.Issuer = "http://issuer.example.com"
			c.JWKSURI = ""
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := valid()
			tc.mutate(&cfg)
			if _, err := rs.New(cfg); err == nil {
				t.Fatal("rs.New accepted an invalid configuration")
			}
		})
	}
	if _, err := rs.New(valid()); err != nil {
		t.Fatalf("rs.New rejected the valid baseline: %v", err)
	}
}

// TestVerifier_NewJWKSURIScheme pins the outbound URL rule: https always,
// plain http only to a loopback IP literal with AllowPrivateNetwork.
func TestVerifier_NewJWKSURIScheme(t *testing.T) {
	t.Parallel()

	cases := []struct {
		uri          string
		allowPrivate bool
		ok           bool
	}{
		{"https://issuer.example.com/jwks", false, true},
		{"http://issuer.example.com/jwks", false, false},
		{"http://issuer.example.com/jwks", true, false},
		{"http://127.0.0.1:8080/jwks", false, false},
		{"http://127.0.0.1:8080/jwks", true, true},
		{"http://[::1]:8080/jwks", true, true},
		{"http://localhost:8080/jwks", true, false},
		{"ftp://issuer.example.com/jwks", true, false},
		{"/jwks", true, false},
	}
	for _, tc := range cases {
		_, err := rs.New(rs.Config{
			Issuer:              testIssuer,
			Audience:            testAudience,
			JWKSURI:             tc.uri,
			AllowPrivateNetwork: tc.allowPrivate,
		})
		if (err == nil) != tc.ok {
			t.Errorf("JWKSURI=%q allowPrivate=%v: err=%v, want ok=%v", tc.uri, tc.allowPrivate, err, tc.ok)
		}
	}
}

func TestVerifier_AcceptsValidJWT(t *testing.T) {
	t.Parallel()

	for _, typ := range []string{"at+jwt", "application/at+jwt"} {
		t.Run(typ, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			claims := baseClaims()
			claims["acr"] = "urn:example:acr"
			claims["amr"] = []string{"pwd", "otp"}
			claims["auth_time"] = testNow.Add(-time.Minute).Unix()
			raw := signJWS(t, josev4.ES256, f.key, primaryKID, typ, claims)

			tok := mustVerify(t, f.verifier(t), newRequest(t, "Bearer", raw))
			if tok.Subject != "user-1" || tok.ClientID != "client-1" {
				t.Errorf("sub/client_id = %q/%q", tok.Subject, tok.ClientID)
			}
			if !slices.Equal(tok.Scopes, []string{"read", "write"}) {
				t.Errorf("Scopes = %v", tok.Scopes)
			}
			if tok.ACR != "urn:example:acr" || !slices.Equal(tok.AMR, []string{"pwd", "otp"}) {
				t.Errorf("acr/amr = %q/%v", tok.ACR, tok.AMR)
			}
			if !tok.AuthTime.Equal(testNow.Add(-time.Minute)) || !tok.ExpiresAt.Equal(testNow.Add(5*time.Minute)) {
				t.Errorf("auth_time/exp = %v/%v", tok.AuthTime, tok.ExpiresAt)
			}
			if tok.Binding != (rs.Binding{}) {
				t.Errorf("Binding = %+v, want empty for a bearer token", tok.Binding)
			}
			if tok.Claims["jti"] != "token-1" {
				t.Errorf("Claims[jti] = %v", tok.Claims["jti"])
			}
		})
	}
}

// TestVerifier_NoAuthorizationHeader: 401 with no error attribute (RFC 6750 §3.1).
func TestVerifier_NoAuthorizationHeader(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	_, err := f.verifier(t).Verify(newRequest(t, "", ""))
	e := wantError(t, err, http.StatusUnauthorized, "")
	if strings.Contains(e.WWWAuthenticate(), "error=") {
		t.Errorf("challenge %q carries an error attribute for a request without credentials", e.WWWAuthenticate())
	}
}

// TestVerifier_MalformedAuthorization: an unknown scheme or an empty /
// malformed token is 400 invalid_request.
func TestVerifier_MalformedAuthorization(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	v := f.verifier(t)
	for _, header := range []string{"Bearer", "Bearer ", "DPoP ", "Bearer a b", "Bearer a\"b"} {
		req := newRequest(t, "", "")
		req.Header.Set("Authorization", header)
		_, err := v.Verify(req)
		wantError(t, err, http.StatusBadRequest, "invalid_request")
	}

	for _, header := range []string{"Basic dXNlcjpwYXNz", "Token abc", ""} {
		req := newRequest(t, "", "")
		req.Header.Set("Authorization", header)
		_, err := v.Verify(req)
		e := wantError(t, err, http.StatusUnauthorized, "")
		if strings.Contains(e.WWWAuthenticate(), "error=") {
			t.Errorf("challenge %q carries an error attribute for an unsupported scheme", e.WWWAuthenticate())
		}
	}

	req := newRequest(t, "Bearer", f.token(t, nil))
	req.Header.Add("Authorization", "Bearer "+f.token(t, nil))
	_, err := v.Verify(req)
	wantError(t, err, http.StatusBadRequest, "invalid_request")

	// The scheme name is case-insensitive.
	mustVerify(t, v, newRequest(t, "bEaReR", f.token(t, nil)))
}

// TestVerifier_AlgorithmRules covers the alg row of the boundary table:
// none, HS*, an alg outside the allow-list, and an alg that differs from
// the one the JWK declares are all invalid_token.
func TestVerifier_AlgorithmRules(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	rsaKey := newRSAKey(t)
	p384 := newECKey(t, elliptic.P384())
	f.ks.setKeys(
		publicJWK(t, f.key, primaryKID, "ES256"),
		publicJWK(t, rsaKey, "rsa-ps256", "PS256"),
		publicJWK(t, rsaKey, "rsa-rs256", "RS256"),
		publicJWK(t, p384, "p384", ""),
	)
	v := f.verifier(t)
	claims := baseClaims()

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"at+jwt","kid":"k1"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"` + testIssuer + `"}`))

	rejected := map[string]string{
		"none":                     header + "." + payload + ".",
		"none with signature":      header + "." + payload + ".AAAA",
		"HS256":                    signJWS(t, josev4.HS256, []byte("0123456789abcdef0123456789abcdef"), primaryKID, "at+jwt", claims),
		"ES384 outside allow-list": signJWS(t, josev4.ES384, p384, "p384", "at+jwt", claims),
		"RS256 under a PS256 JWK":  signJWS(t, josev4.RS256, rsaKey, "rsa-ps256", "at+jwt", claims),
	}
	for name, raw := range rejected {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := v.Verify(newRequest(t, "Bearer", raw))
			wantError(t, err, http.StatusUnauthorized, "invalid_token")
		})
	}
	t.Run("RS256 under an RS256 JWK", func(t *testing.T) {
		t.Parallel()
		mustVerify(t, v, newRequest(t, "Bearer", signJWS(t, josev4.RS256, rsaKey, "rsa-rs256", "at+jwt", claims)))
	})
}

func TestVerifier_RejectsWrongTyp(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	v := f.verifier(t)
	for _, typ := range []string{"", "JWT", "AT+JWT", "application/jwt"} {
		raw := signJWS(t, josev4.ES256, f.key, primaryKID, typ, baseClaims())
		_, err := v.Verify(newRequest(t, "Bearer", raw))
		wantError(t, err, http.StatusUnauthorized, "invalid_token")
	}
}

// TestVerifier_ExpiryIsExclusive: a token is expired at its exp second.
func TestVerifier_ExpiryIsExclusive(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	v := f.verifier(t)
	raw := f.token(t, nil)
	exp := testNow.Add(5 * time.Minute)

	f.clock.Set(exp.Add(-time.Second))
	mustVerify(t, v, newRequest(t, "Bearer", raw))

	f.clock.Set(exp)
	_, err := v.Verify(newRequest(t, "Bearer", raw))
	wantError(t, err, http.StatusUnauthorized, "invalid_token")
}

// TestVerifier_RejectsFutureIssuedAt: iat later than now is rejected with
// no leeway; iat equal to now is accepted.
func TestVerifier_RejectsFutureIssuedAt(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	v := f.verifier(t)
	mustVerify(t, v, newRequest(t, "Bearer", f.token(t, func(c map[string]any) { c["iat"] = testNow.Unix() })))

	future := f.token(t, func(c map[string]any) { c["iat"] = testNow.Add(time.Second).Unix() })
	_, err := v.Verify(newRequest(t, "Bearer", future))
	wantError(t, err, http.StatusUnauthorized, "invalid_token")
}

// TestVerifier_RejectsFutureNotBefore: nbf later than now is rejected with
// no leeway; nbf equal to now is accepted.
func TestVerifier_RejectsFutureNotBefore(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	v := f.verifier(t)
	mustVerify(t, v, newRequest(t, "Bearer", f.token(t, func(c map[string]any) { c["nbf"] = testNow.Unix() })))

	future := f.token(t, func(c map[string]any) { c["nbf"] = testNow.Add(time.Second).Unix() })
	_, err := v.Verify(newRequest(t, "Bearer", future))
	wantError(t, err, http.StatusUnauthorized, "invalid_token")
}

func TestVerifier_AudienceShapes(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	v := f.verifier(t)
	cases := []struct {
		name string
		aud  any
		ok   bool
	}{
		{"string", testAudience, true},
		{"array containing", []string{"https://other.example.com", testAudience}, true},
		{"array without", []string{"https://other.example.com"}, false},
		{"other string", "https://other.example.com", false},
		{"empty string", "", false},
		{"empty array", []string{}, false},
		{"absent", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			raw := f.token(t, func(c map[string]any) {
				if tc.aud == nil {
					delete(c, "aud")
					return
				}
				c["aud"] = tc.aud
			})
			_, err := v.Verify(newRequest(t, "Bearer", raw))
			if tc.ok {
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				return
			}
			wantError(t, err, http.StatusUnauthorized, "invalid_token")
		})
	}
}

func TestVerifier_RejectsIssuerMismatch(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	raw := f.token(t, func(c map[string]any) { c["iss"] = testIssuer + "/" })
	_, err := f.verifier(t).Verify(newRequest(t, "Bearer", raw))
	wantError(t, err, http.StatusUnauthorized, "invalid_token")
}

func TestVerifier_RejectsMissingRequiredClaim(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	v := f.verifier(t)
	for _, claim := range []string{"sub", "client_id", "iat", "exp", "iss"} {
		raw := f.token(t, func(c map[string]any) { delete(c, claim) })
		_, err := v.Verify(newRequest(t, "Bearer", raw))
		wantError(t, err, http.StatusUnauthorized, "invalid_token")
	}
}

func TestVerifier_RejectsForgedSignature(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	forger := newECKey(t, elliptic.P256())
	raw := signJWS(t, josev4.ES256, forger, primaryKID, "at+jwt", baseClaims())
	_, err := f.verifier(t).Verify(newRequest(t, "Bearer", raw))
	wantError(t, err, http.StatusUnauthorized, "invalid_token")
}

// TestVerifier_RefetchesKeysOnUnknownKid: a kid the cached set lacks
// triggers one refetch, which is how a key rotation reaches the verifier.
func TestVerifier_RefetchesKeysOnUnknownKid(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	v := f.verifier(t)
	mustVerify(t, v, newRequest(t, "Bearer", f.token(t, nil)))
	if got := f.ks.hits.Load(); got != 1 {
		t.Fatalf("JWK Set fetched %d times after the first token, want 1", got)
	}

	rotated := newECKey(t, elliptic.P256())
	f.ks.setKeys(publicJWK(t, f.key, primaryKID, "ES256"), publicJWK(t, rotated, "k2", "ES256"))
	raw := signJWS(t, josev4.ES256, rotated, "k2", "at+jwt", baseClaims())
	mustVerify(t, v, newRequest(t, "Bearer", raw))
	if got := f.ks.hits.Load(); got != 2 {
		t.Fatalf("JWK Set fetched %d times after the rotated kid, want 2", got)
	}
}

// TestVerifier_DPoPBoundTokenAsBearer: a token bound by cnf.jkt presented
// under the Bearer scheme is a downgrade and is invalid_token.
func TestVerifier_DPoPBoundTokenAsBearer(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	key := newProofKey(t, josev4.ES256)
	raw := f.token(t, func(c map[string]any) { c["cnf"] = map[string]string{"jkt": key.jkt} })
	req := newRequest(t, "Bearer", raw)
	req.Header.Set("DPoP", key.proof(t, http.MethodGet, resourceURL, testNow, raw))
	_, err := f.verifier(t).Verify(req)
	wantError(t, err, http.StatusUnauthorized, "invalid_token")
}

func TestVerifier_DPoPBoundTokenWithProof(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	key := newProofKey(t, josev4.ES256)
	raw := f.token(t, func(c map[string]any) { c["cnf"] = map[string]string{"jkt": key.jkt} })
	for _, mode := range []rs.DPoPMode{rs.DPoPAllowed, rs.DPoPRequired} {
		req := newRequest(t, "DPoP", raw)
		req.Header.Set("DPoP", key.proof(t, http.MethodGet, resourceURL, testNow, raw))
		tok := mustVerify(t, f.verifier(t, func(c *rs.Config) { c.DPoP = mode }), req)
		if tok.Binding.JKT != key.jkt {
			t.Errorf("mode %d: Binding.JKT = %q, want %q", mode, tok.Binding.JKT, key.jkt)
		}
	}
}

func TestVerifier_DPoPProofFailures(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	key := newProofKey(t, josev4.ES256)
	raw := f.token(t, func(c map[string]any) { c["cnf"] = map[string]string{"jkt": key.jkt} })
	other := f.token(t, func(c map[string]any) { c["jti"] = "token-2" })

	cases := []struct {
		name  string
		proof func(t *testing.T) string
		code  string
	}{
		{"missing proof", func(*testing.T) string { return "" }, "invalid_dpop_proof"},
		{"wrong htm", func(t *testing.T) string {
			t.Helper()
			return key.proof(t, http.MethodPost, resourceURL, testNow, raw)
		}, "invalid_dpop_proof"},
		{"wrong htu", func(t *testing.T) string {
			t.Helper()
			return key.proof(t, http.MethodGet, "https://rs.example.com/other", testNow, raw)
		}, "invalid_dpop_proof"},
		{"ath of another token", func(t *testing.T) string {
			t.Helper()
			return key.proof(t, http.MethodGet, resourceURL, testNow, other)
		}, "invalid_dpop_proof"},
		{"stale iat", func(t *testing.T) string {
			t.Helper()
			return key.proof(t, http.MethodGet, resourceURL, testNow.Add(-10*time.Minute), raw)
		}, "invalid_dpop_proof"},
		{"proof by another key", func(t *testing.T) string {
			t.Helper()
			return newProofKey(t, josev4.ES256).proof(t, http.MethodGet, resourceURL, testNow, raw)
		}, "invalid_token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := newRequest(t, "DPoP", raw)
			if p := tc.proof(t); p != "" {
				req.Header.Set("DPoP", p)
			}
			_, err := f.verifier(t).Verify(req)
			wantError(t, err, http.StatusUnauthorized, tc.code)
		})
	}
}

// TestVerifier_DPoPReplay: a proof is single-use within one verifier's
// replay store.
func TestVerifier_DPoPReplay(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	key := newProofKey(t, josev4.ES256)
	raw := f.token(t, func(c map[string]any) { c["cnf"] = map[string]string{"jkt": key.jkt} })
	proof := key.proof(t, http.MethodGet, resourceURL, testNow, raw)
	v := f.verifier(t)

	first := newRequest(t, "DPoP", raw)
	first.Header.Set("DPoP", proof)
	mustVerify(t, v, first)

	replay := newRequest(t, "DPoP", raw)
	replay.Header.Set("DPoP", proof)
	_, err := v.Verify(replay)
	wantError(t, err, http.StatusUnauthorized, "invalid_dpop_proof")
}

// TestVerifier_DPoPSchemeWithUnboundToken: the DPoP scheme asserts a
// binding the token does not carry.
func TestVerifier_DPoPSchemeWithUnboundToken(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	key := newProofKey(t, josev4.ES256)
	raw := f.token(t, nil)
	req := newRequest(t, "DPoP", raw)
	req.Header.Set("DPoP", key.proof(t, http.MethodGet, resourceURL, testNow, raw))
	_, err := f.verifier(t).Verify(req)
	wantError(t, err, http.StatusUnauthorized, "invalid_token")
}

// TestVerifier_DPoPRequiredRejectsUnboundToken: under DPoPRequired a plain
// bearer token is refused, and the only challenge is DPoP.
func TestVerifier_DPoPRequiredRejectsUnboundToken(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	v := f.verifier(t, func(c *rs.Config) { c.DPoP = rs.DPoPRequired })
	_, err := v.Verify(newRequest(t, "Bearer", f.token(t, nil)))
	e := wantError(t, err, http.StatusUnauthorized, "invalid_token")
	if got := e.WWWAuthenticate(); !strings.HasPrefix(got, `DPoP algs="`) || strings.Contains(got, "Bearer") {
		t.Errorf("WWWAuthenticate = %q, want a lone DPoP challenge", got)
	}
}

func TestVerifier_CertificateBoundToken(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t)
	bound := ca.issue(t, "bound-client")
	stranger := ca.issue(t, "other-client")
	f := newFixture(t)
	raw := f.token(t, func(c map[string]any) { c["cnf"] = map[string]string{"x5t#S256": thumbprint(bound.cert)} })
	headerValue := url.QueryEscape(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: bound.cert.Raw})))
	proxy := &op.MTLSProxy{HeaderName: "X-Client-Cert", TrustedProxies: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}

	withTLS := func(cert *x509.Certificate) func(*http.Request) {
		return func(r *http.Request) { r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}} }
	}
	viaProxy := func(remote string) func(*http.Request) {
		return func(r *http.Request) {
			r.TLS = nil
			r.RemoteAddr = remote
			r.Header.Set("X-Client-Cert", headerValue)
		}
	}
	cases := []struct {
		name  string
		proxy *op.MTLSProxy
		shape func(*http.Request)
		ok    bool
	}{
		{"bound certificate on the handshake", nil, withTLS(bound.cert), true},
		{"another certificate", nil, withTLS(stranger.cert), false},
		{"no certificate", nil, func(r *http.Request) { r.TLS = &tls.ConnectionState{} }, false},
		{"bound certificate from a trusted proxy", proxy, viaProxy("192.0.2.10:4431"), true},
		{"proxy header from an untrusted source", proxy, viaProxy("198.51.100.7:4431"), false},
		{"proxy header without MTLSProxy", nil, viaProxy("192.0.2.10:4431"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v := f.verifier(t, func(c *rs.Config) { c.MTLSProxy = tc.proxy })
			req := newRequest(t, "Bearer", raw)
			tc.shape(req)
			tok, err := v.Verify(req)
			if !tc.ok {
				wantError(t, err, http.StatusUnauthorized, "invalid_token")
				return
			}
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if tok.Binding.CertThumbprint != thumbprint(bound.cert) {
				t.Errorf("Binding.CertThumbprint = %q", tok.Binding.CertThumbprint)
			}
		})
	}
}

// TestVerifier_OpaqueTokenWithoutIntrospection: a non-JWT token cannot be
// verified without introspection and is invalid_token.
func TestVerifier_OpaqueTokenWithoutIntrospection(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	_, err := f.verifier(t).Verify(newRequest(t, "Bearer", "opaque-token-value"))
	wantError(t, err, http.StatusUnauthorized, "invalid_token")
}

// TestVerifier_UnreachableKeysAreServerFault: a JWK Set the verifier
// cannot fetch is the server's fault (503), not the client's token.
func TestVerifier_UnreachableKeysAreServerFault(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	v := f.verifier(t)
	f.ks.srv.Close()
	_, err := v.Verify(newRequest(t, "Bearer", f.token(t, nil)))
	e := wantError(t, err, http.StatusServiceUnavailable, "")
	if e.Description == "" {
		t.Error("server-fault error has no description")
	}
}

// TestVerifier_RequireScopeWithoutArguments: RequireScope() requires nothing.
func TestVerifier_RequireScopeWithoutArguments(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	h := f.verifier(t).Middleware(rs.RequireScope())(okHandler())
	raw := f.token(t, func(c map[string]any) { delete(c, "scope") })
	if rec := serve(t, h, newRequest(t, "Bearer", raw)); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestVerifier_RequireMaxAgeRejectsNonPositive(t *testing.T) {
	t.Parallel()

	for _, d := range []time.Duration{0, -time.Second} {
		if !panics(func() { rs.RequireMaxAge(d) }) {
			t.Errorf("RequireMaxAge(%v) did not panic", d)
		}
	}
	if panics(func() { rs.RequireMaxAge(time.Nanosecond) }) {
		t.Error("RequireMaxAge(1ns) panicked")
	}
}

func TestVerifier_RequireACRRejectsUndeclared(t *testing.T) {
	t.Parallel()

	levels := op.ACRLevels{"urn:example:mfa": op.AAL2}
	if !panics(func() { rs.RequireACR(levels, "urn:example:typo") }) {
		t.Error("RequireACR with an undeclared acr did not panic")
	}
	if !panics(func() { rs.RequireACR(levels, "") }) {
		t.Error("RequireACR with an empty acr did not panic")
	}
	for _, acr := range []string{"urn:example:mfa", op.AAL1.ACRURI()} {
		if panics(func() { rs.RequireACR(levels, acr) }) {
			t.Errorf("RequireACR(%q) panicked for a resolvable value", acr)
		}
	}
}

func panics(fn func()) (did bool) {
	defer func() {
		if recover() != nil {
			did = true
		}
	}()
	fn()
	return false
}

// TestVerifier_UnknownKidUnderLoadPressureIsInvalidToken: when the shared
// URL-load gate is saturated, a token naming an unknown kid is rejected as
// invalid_token against the held key set, and a cached kid still verifies.
// It is not parallel: it saturates the process-wide gate.
func TestVerifier_UnknownKidUnderLoadPressureIsInvalidToken(t *testing.T) { //nolint:paralleltest // saturates the process-wide URL-load gate.
	f := newFixture(t)
	v := f.verifier(t)
	mustVerify(t, v, newRequest(t, "Bearer", f.token(t, nil)))

	gate := remotecache.SharedLoadGate(remotecache.DefaultMaxInflight)
	var releases []func()
	defer func() {
		for _, r := range releases {
			r()
		}
	}()
	for {
		release, err := gate.Acquire(context.Background())
		if err != nil {
			break
		}
		releases = append(releases, release)
	}

	mustVerify(t, v, newRequest(t, "Bearer", f.token(t, nil)))
	other := newECKey(t, elliptic.P256())
	raw := signJWS(t, josev4.ES256, other, "unknown-kid", "at+jwt", baseClaims())
	_, err := v.Verify(newRequest(t, "Bearer", raw))
	wantError(t, err, http.StatusUnauthorized, "invalid_token")
}
