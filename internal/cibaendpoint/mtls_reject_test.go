// Package cibaendpoint_test (this file): a /bc-authorize request that
// presents an unusable mTLS client certificate must fail closed the
// same way the token endpoint does, instead of silently falling back
// to the unbound (bearer) path.
package cibaendpoint_test

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
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/cibaendpoint"
	"github.com/libraz/go-oidc-provider/internal/mtls"
)

// generateCIBALeaf returns a self-signed, client-auth-capable leaf
// certificate. It is never added to a trust pool, so a [mtls.Verifier]
// configured with any [mtls.VerifierConfig.RootCAs] rejects it as
// untrusted.
func generateCIBALeaf(tb testing.TB) *x509.Certificate {
	tb.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("generate key: %v", err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rp.example"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		tb.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatalf("parse certificate: %v", err)
	}
	return cert
}

// TestServe_RejectsUntrustedMTLSCertificate pins the fail-closed
// behaviour: a certificate that fails chain validation must surface
// as invalid_client, not be silently dropped into the unbound path.
// On the old code, extractMTLSThumbprint mapped ErrCertUntrusted to
// an empty thumbprint and the request would have succeeded.
func TestServe_RejectsUntrustedMTLSCertificate(t *testing.T) {
	t.Parallel()
	clock := fixedClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}
	s := newTestStore(t, clock)
	deps := newDeps(s, clock)

	verifier, err := mtls.NewVerifier(mtls.VerifierConfig{RootCAs: x509.NewCertPool()})
	if err != nil {
		t.Fatalf("mtls.NewVerifier: %v", err)
	}
	deps.MTLS = verifier

	req := newRequest(nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{generateCIBALeaf(t)}}
	rec := httptest.NewRecorder()

	cibaendpoint.Handler(deps).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
	if got := decodeError(t, rec.Body.Bytes()); got != wireInvalidClient {
		t.Fatalf("error = %q, want %q", got, wireInvalidClient)
	}
}

// TestServe_RejectsMalformedMTLSCertificateHeader mirrors the
// [TestServe_RejectsUntrustedMTLSCertificate] guard for the
// present-but-unparseable case: a trusted proxy forwarded a header
// that does not decode to a certificate at all. The old code
// collapsed this into the unbound path too.
func TestServe_RejectsMalformedMTLSCertificateHeader(t *testing.T) {
	t.Parallel()
	clock := fixedClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}
	s := newTestStore(t, clock)
	deps := newDeps(s, clock)

	proxies, err := mtls.ParseTrustedProxies([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("ParseTrustedProxies: %v", err)
	}
	verifier, err := mtls.NewVerifier(mtls.VerifierConfig{
		Proxy: mtls.ProxyConfig{HeaderName: "X-Client-Cert", TrustedProxies: proxies},
	})
	if err != nil {
		t.Fatalf("mtls.NewVerifier: %v", err)
	}
	deps.MTLS = verifier

	form := url.Values{}
	form.Set("scope", "openid")
	form.Set("login_hint", "user@example")
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/bc-authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(testClientID, testClientSecret)
	req.Header.Set("X-Client-Cert", "not a certificate")
	req.RemoteAddr = "10.1.2.3:12345"

	rec := httptest.NewRecorder()
	cibaendpoint.Handler(deps).ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if got := decodeError(t, rec.Body.Bytes()); got != wireInvalidRequest {
		t.Fatalf("error = %q, want %q", got, wireInvalidRequest)
	}
}
