package userinfo_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/dpop"
	"github.com/libraz/go-oidc-provider/internal/mtls"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// mtlsUserInfoFixture builds a userinfo fixture with the mTLS feature
// enabled. Because httptest.Server is plain HTTP, mTLS-specific tests
// drive the [op.Provider] handler directly via ServeHTTP and fabricate
// [tls.ConnectionState] on the request.
func mtlsUserInfoFixture(tb testing.TB) *userInfoFixture {
	tb.Helper()
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	prov := testkit.NewProvider(tb,
		testkit.WithClock(clock),
		testkit.WithOptions(op.WithFeature(feature.MTLS)),
	)
	return &userInfoFixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/userinfo",
		signer:   tokens.SigningKey{KeyID: prov.SigningKey.KeyID, Signer: prov.SigningKey.Signer},
		clock:    clock,
	}
}

// dualFeatureUserInfoFixture builds a fixture with BOTH DPoP and
// mTLS enabled. The combination exercises the dual-cnf branch: a
// token that carries cnf.jkt AND cnf.x5t#S256 must present BOTH a
// matching proof and a matching cert.
func dualFeatureUserInfoFixture(tb testing.TB) *userInfoFixture {
	tb.Helper()
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	prov := testkit.NewProvider(tb,
		testkit.WithClock(clock),
		testkit.WithOptions(op.WithFeature(feature.DPoP), op.WithFeature(feature.MTLS)),
	)
	return &userInfoFixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/userinfo",
		signer:   tokens.SigningKey{KeyID: prov.SigningKey.KeyID, Signer: prov.SigningKey.Signer},
		clock:    clock,
	}
}

// generateMTLSLeafForUserInfo produces a self-signed leaf cert. The
// helper duplicates the tokenendpoint sibling so this _test package
// does not need to reach across packages for it.
func generateMTLSLeafForUserInfo(tb testing.TB) *x509.Certificate {
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

// getWithMTLS dispatches a /userinfo GET against the provider with a
// fabricated TLS handshake state, bypassing the testkit's plain-HTTP
// httptest.Server.
func getWithMTLS(tb testing.TB, prov *testkit.Provider, token string, cert *x509.Certificate) *http.Response {
	tb.Helper()
	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"https://op.testkit.invalid/oidc/userinfo",
		http.NoBody,
	)
	if err != nil {
		tb.Fatalf("NewRequest: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if cert != nil {
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	}
	rec := httptest.NewRecorder()
	prov.OP.ServeHTTP(rec, req)
	return rec.Result()
}

// TestUserInfo_MTLS_HappyPath proves that a cnf.x5t#S256-bound access
// token paired with the matching client cert releases userinfo
// claims.
func TestUserInfo_MTLS_HappyPath(t *testing.T) {
	t.Parallel()

	f := mtlsUserInfoFixture(t)
	f.putUser(t, "user-1", map[string]any{
		"email":          "alice@example.com",
		"email_verified": true,
	})
	cert := generateMTLSLeafForUserInfo(t)
	thumb := mtls.Thumbprint(cert)
	token := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.Scope = []string{"openid", "email"}
		c.Confirmation = map[string]string{"x5t#S256": thumb}
	})
	resp := getWithMTLS(t, f.prov, token, cert)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
}

// TestUserInfo_MTLS_MissingCert rejects a sender-constrained token
// presented without any client cert.
func TestUserInfo_MTLS_MissingCert(t *testing.T) {
	t.Parallel()

	f := mtlsUserInfoFixture(t)
	f.putUser(t, "user-1", map[string]any{"email": "alice@example.com"})
	cert := generateMTLSLeafForUserInfo(t)
	token := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.Confirmation = map[string]string{"x5t#S256": mtls.Thumbprint(cert)}
	})
	resp := getWithMTLS(t, f.prov, token, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); !strings.Contains(got, `error="invalid_token"`) {
		t.Errorf("WWW-Authenticate=%q must declare invalid_token", got)
	}
}

// TestUserInfo_MTLS_DifferentCert rejects when the presented cert is
// not the bound one.
func TestUserInfo_MTLS_DifferentCert(t *testing.T) {
	t.Parallel()

	f := mtlsUserInfoFixture(t)
	f.putUser(t, "user-1", map[string]any{"email": "alice@example.com"})
	bound := generateMTLSLeafForUserInfo(t)
	other := generateMTLSLeafForUserInfo(t)
	token := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.Confirmation = map[string]string{"x5t#S256": mtls.Thumbprint(bound)}
	})
	resp := getWithMTLS(t, f.prov, token, other)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", resp.StatusCode)
	}
}

// TestUserInfo_MTLS_BearerStillWorks confirms bearer access tokens
// still pass when the mTLS feature is enabled.
func TestUserInfo_MTLS_BearerStillWorks(t *testing.T) {
	t.Parallel()

	f := mtlsUserInfoFixture(t)
	f.putUser(t, "user-1", map[string]any{
		"email":          "alice@example.com",
		"email_verified": true,
	})
	token := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.Scope = []string{"openid", "email"}
	})
	resp := getWithMTLS(t, f.prov, token, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
}

// TestUserInfo_MTLS_FeatureDisabled rejects a cnf.x5t#S256 token
// when the OP has the mTLS feature off (fail-closed). The default
// userinfo fixture has neither DPoP nor mTLS enabled.
func TestUserInfo_MTLS_FeatureDisabled(t *testing.T) {
	t.Parallel()

	f := newUserInfoFixture(t)
	cert := generateMTLSLeafForUserInfo(t)
	token := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.Confirmation = map[string]string{"x5t#S256": mtls.Thumbprint(cert)}
	})
	resp := getWithMTLS(t, f.prov, token, cert)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 (mTLS feature disabled)", resp.StatusCode)
	}
}

// TestUserInfo_DualBinding requires BOTH a matching DPoP proof and a
// matching client cert when the access token carries jkt + x5t#S256.
// The path is unusual but theoretically reachable; this test pins
// the fail-on-either-half behaviour.
func TestUserInfo_DualBinding(t *testing.T) {
	t.Parallel()

	f := dualFeatureUserInfoFixture(t)
	f.putUser(t, "user-1", map[string]any{
		"email":          "alice@example.com",
		"email_verified": true,
	})
	cert := generateMTLSLeafForUserInfo(t)
	dpopKey := newDPoPProofKey(t)
	x5t := mtls.Thumbprint(cert)
	token := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.Scope = []string{"openid", "email"}
		c.Confirmation = map[string]string{
			"jkt":      dpopKey.jkt,
			"x5t#S256": x5t,
		}
	})

	// Both proofs present: success.
	dual := newRequestDualProof(t, f.prov, token, cert, dpopKey, "jti-dual-1", f.clock.now)
	rec := httptest.NewRecorder()
	f.prov.OP.ServeHTTP(rec, dual)
	if got := rec.Result().StatusCode; got != http.StatusOK {
		t.Fatalf("dual status=%d want 200", got)
	}

	// Cert missing: fail.
	missCert := newRequestDualProof(t, f.prov, token, nil, dpopKey, "jti-dual-2", f.clock.now)
	rec = httptest.NewRecorder()
	f.prov.OP.ServeHTTP(rec, missCert)
	if got := rec.Result().StatusCode; got != http.StatusUnauthorized {
		t.Fatalf("missCert status=%d want 401", got)
	}

	// Proof missing: fail.
	missProof, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"https://op.testkit.invalid/oidc/userinfo", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	// jkt-bound token → DPoP scheme; this case omits the proof header to
	// exercise the missing-proof rejection.
	missProof.Header.Set("Authorization", "DPoP "+token)
	missProof.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	rec = httptest.NewRecorder()
	f.prov.OP.ServeHTTP(rec, missProof)
	if got := rec.Result().StatusCode; got != http.StatusUnauthorized {
		t.Fatalf("missProof status=%d want 401", got)
	}
}

// newRequestDualProof assembles a /userinfo GET carrying both a DPoP
// proof header and a TLS handshake cert. Used exclusively by the
// dual-binding test.
func newRequestDualProof(
	tb testing.TB,
	_ *testkit.Provider,
	token string,
	cert *x509.Certificate,
	key dpopProofKey,
	jti string,
	now time.Time,
) *http.Request {
	tb.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"https://op.testkit.invalid/oidc/userinfo", http.NoBody)
	if err != nil {
		tb.Fatalf("NewRequest: %v", err)
	}
	// The dual-bound token carries cnf.jkt, so RFC 9449 §7.1 requires the
	// DPoP authentication scheme (not Bearer) even though a cert is also
	// presented.
	req.Header.Set("Authorization", "DPoP "+token)
	req.Header.Set("DPoP", proofFor(tb, key, "GET", "https://op.testkit.invalid/oidc/userinfo", now, jti, dpop.AccessTokenHash(token)))
	if cert != nil {
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	}
	return req
}
